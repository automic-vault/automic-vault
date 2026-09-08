import Foundation
import Darwin
import Security

public let sshCredentialSecretName = "AV_SSH_CREDENTIAL"
public let sshAgentConfigurationService = "com.automicvault.ssh-agent-configuration"

public struct SSHAgentConfiguration: Codable, Equatable, Sendable {
    public var generation: UUID = UUID()
    public var enabled: Bool
    public var publicKey: String
    public init(enabled: Bool = false, publicKey: String = "") {
        self.enabled = enabled
        self.publicKey = publicKey
    }
}

public func loadSSHAgentConfiguration() -> SSHAgentConfiguration {
    guard case .success(let data) = loadKeychainDataResult(
        service: sshAgentConfigurationService, account: "configuration"
    ), let config = try? JSONDecoder().decode(SSHAgentConfiguration.self, from: data)
    else { return SSHAgentConfiguration() }
    return config
}

@discardableResult
public func saveSSHAgentConfiguration(_ config: SSHAgentConfiguration) -> OSStatus {
    guard let data = try? JSONEncoder().encode(config) else { return errSecParam }
    return saveKeychainData(data, service: sshAgentConfigurationService,
                           account: "configuration", accessibility: .afterFirstUnlock)
}

public func sshAgentSocketURL(
    home: URL = FileManager.default.homeDirectoryForCurrentUser,
    xdgDataHome: String? = ProcessInfo.processInfo.environment["XDG_DATA_HOME"]
) -> URL {
    let directory = xdgDataHome.flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0) : nil }
        ?? home.appendingPathComponent(".local/share")
    return directory.appendingPathComponent("automic-vault/ssh-agent.sock")
}

public func validSSHSigningArguments(_ arguments: [String]) -> Bool {
    guard arguments.count == 3 else { return false }
    for (value, prefix) in zip(arguments.prefix(2), ["payload-sha256=", "public-key-sha256="]) {
        guard value.hasPrefix(prefix) else { return false }
        let digest = value.dropFirst(prefix.count)
        guard digest.utf8.count == 64,
              digest.utf8.allSatisfy({ 48...57 ~= $0 || 97...102 ~= $0 }) else { return false }
    }
    return arguments[2] == "signature-flags=0"
}

private let sshConfigStart = "# BEGIN Automic Vault SSH Agent\n"
private let sshConfigEnd = "# END Automic Vault SSH Agent\n"

/// OpenSSH uses the first value encountered. Keep the managed block before user configuration.
public func sshAgentConfig(_ existing: String, socketPath: String?) throws -> String {
    var remaining = existing
    if remaining.contains(sshConfigStart) || remaining.contains(sshConfigEnd) {
        guard remaining.hasPrefix(sshConfigStart),
              let end = remaining.range(of: sshConfigEnd),
              !remaining[end.upperBound...].contains(sshConfigStart),
              !remaining[end.upperBound...].contains(sshConfigEnd)
        else { throw SSHAgentError.invalidConfiguration }
        remaining = String(remaining[end.upperBound...])
    }
    guard let socketPath else { return remaining }
    guard socketPath.hasPrefix("/"), !socketPath.contains(where: { "\n\r\"\\$%".contains($0) })
    else { throw SSHAgentError.invalidConfiguration }
    return sshConfigStart + """
    Host *
      IdentityAgent "\(socketPath)"
      IdentityFile none
      ForwardAgent no
      AddKeysToAgent no
      UseKeychain no
    """ + "\n" + sshConfigEnd + remaining
}

public func configureOpenSSHAgent(enabled: Bool, home: URL = FileManager.default.homeDirectoryForCurrentUser) throws {
    let directory = home.appendingPathComponent(".ssh")
    let file = directory.appendingPathComponent("config")
    let fm = FileManager.default
    if !fm.fileExists(atPath: directory.path) {
        try fm.createDirectory(at: directory, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
    }
    let attributes = try fm.attributesOfItem(atPath: directory.path)
    guard attributes[.type] as? FileAttributeType == .typeDirectory,
          (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else {
        throw SSHAgentError.invalidConfiguration
    }
    // Keep even the atomic replacement's temporary file private.
    try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    let existing: String
    if let attributes = try? fm.attributesOfItem(atPath: file.path) {
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else {
            throw SSHAgentError.invalidConfiguration
        }
        existing = try String(contentsOf: file, encoding: .utf8)
    } else { existing = "" }
    let updated = try sshAgentConfig(existing, socketPath: enabled ? sshAgentSocketURL(home: home).path : nil)
    try updated.write(to: file, atomically: true, encoding: .utf8)
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
}

public enum SSHAgentError: LocalizedError {
    case invalidConfiguration
    case failed(String)
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: "The SSH configuration cannot be safely updated. Check its path and Automic Vault block."
        case .failed(let message): message
        }
    }
}
