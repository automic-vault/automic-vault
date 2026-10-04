import Foundation
import Darwin
import Security
import CryptoKit

public let sshCredentialSecretName = "AV_SSH_CREDENTIAL"
public let sshAgentConfigurationService = "com.automicvault.ssh-agent-configuration"

/// The legacy identity is reserved for the original credential and its policy.
public struct SSHAgentCredential: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public var name: String
    public let publicKey: String
    public var secretName: String { id == "legacy" ? sshCredentialSecretName : "AV_SSH_CREDENTIAL_" + id }
    public var gateID: String { id == "legacy" ? "ssh-agent" : "ssh-agent/" + id }
    public var publicKeyData: Data? {
        let fields = publicKey.split(separator: " ")
        guard fields.count >= 2 else { return nil }
        return Data(base64Encoded: String(fields[1]))
    }
    public var publicKeyDigest: String? {
        publicKeyData.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() }
    }
    public var fingerprint: String {
        publicKeyData.map { "SHA256:" + Data(SHA256.hash(data: $0)).base64EncodedString()
            .replacingOccurrences(of: "=", with: "") } ?? "Invalid public key"
    }
    public init(id: String = UUID().uuidString, name: String, publicKey: String) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
    }
}

public func isSSHAgentGateID(_ id: String) -> Bool {
    id == "ssh-agent" || id.hasPrefix("ssh-agent/")
}

public struct SSHAgentConfiguration: Codable, Equatable, Sendable {
    public var generation: UUID = UUID()
    public var enabled: Bool
    public var credentials: [SSHAgentCredential]
    public init(enabled: Bool = false, publicKey: String = "") {
        self.enabled = enabled
        credentials = publicKey.isEmpty ? [] : [SSHAgentCredential(id: "legacy", name: "Original Key", publicKey: publicKey)]
    }
    public init(enabled: Bool, credentials: [SSHAgentCredential]) {
        self.enabled = enabled
        self.credentials = credentials
    }
    private enum CodingKeys: String, CodingKey { case generation, enabled, credentials, publicKey, version }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        generation = try values.decode(UUID.self, forKey: .generation)
        enabled = try values.decode(Bool.self, forKey: .enabled)
        if values.contains(.version) {
            guard try values.decode(Int.self, forKey: .version) == 2 else { throw SSHAgentError.invalidConfiguration }
            credentials = try values.decode([SSHAgentCredential].self, forKey: .credentials)
        } else {
            // Never interpret a damaged new catalog as legacy, losing denial or key identity.
            guard !values.contains(.credentials) else { throw SSHAgentError.invalidConfiguration }
            let publicKey = try values.decode(String.self, forKey: .publicKey)
            credentials = publicKey.isEmpty ? [] : [SSHAgentCredential(id: "legacy", name: "Original Key", publicKey: publicKey)]
        }
        guard isValid else { throw SSHAgentError.invalidConfiguration }
    }
    public func encode(to encoder: Encoder) throws {
        guard isValid else { throw SSHAgentError.invalidConfiguration }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(2, forKey: .version)
        try values.encode(generation, forKey: .generation)
        try values.encode(enabled, forKey: .enabled)
        try values.encode(credentials, forKey: .credentials)
    }
    public var isValid: Bool {
        credentials.count <= 32
            && Set(credentials.map(\.id)).count == credentials.count
            && Set(credentials.compactMap(\.publicKeyDigest)).count == credentials.count
            && credentials.allSatisfy {
                ($0.id == "legacy" || UUID(uuidString: $0.id)?.uuidString == $0.id)
                    && !$0.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    && $0.name.utf8.count <= 128 && !$0.name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
                    && $0.publicKey.utf8.count <= 4096 && $0.publicKeyData?.isEmpty == false
            }
    }
    public func credential(publicKeyDigest: String) -> SSHAgentCredential? {
        guard enabled, isValid else { return nil }
        return credentials.first { $0.publicKeyDigest == publicKeyDigest }
    }
}

/// Derive exact routes from the signed static SSH definition, never from user paths.
public func sshAgentGateDescriptors(_ descriptors: [SecretGateDescriptor],
                                    configuration: SSHAgentConfiguration) -> [SecretGateDescriptor] {
    descriptors.flatMap { descriptor in
        guard descriptor.id == "ssh-agent" else { return [descriptor] }
        guard configuration.isValid else { return [] }
        return configuration.credentials.map { credential in
            SecretGateDescriptor(id: credential.gateID, keyPatterns: [credential.secretName],
                routes: descriptor.routes.map { route in
                    SecretGateRoute(operation: route.operation, scriptPath: route.scriptPath,
                        targetPath: route.targetPath, callerIdentifiers: route.callerIdentifiers,
                        keyPatterns: [credential.secretName], replaceExistingEnv: route.replaceExistingEnv,
                        allowMissingKeys: route.allowMissingKeys)
                })
        }
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
    guard config.isValid, let data = try? JSONEncoder().encode(config) else { return errSecParam }
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
        if remaining.hasPrefix("\n") { remaining.removeFirst() }
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
    """ + "\n" + sshConfigEnd + (remaining.isEmpty ? "" : "\n" + remaining)
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
