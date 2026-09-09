import Foundation

public let uvCredentialSecretName = "UV_CREDENTIALS"
public let uvOfficialTarget = "/opt/av/uv/0.12.12/uv"
public let uvKeyringHelper = "/opt/av/uv/bin/keyring"
public let uvLauncherStub = "#!/usr/local/bin/av uv\n"
public let uvxLauncherStub = "#!/usr/local/bin/av uvx\n"
public let uvKeyringStub = "#!/usr/local/bin/av uv-keyring\n"

// Reviewed against astral-sh/uv 0.12.12; mirror src/uv.rs.
public func uvCredentialCommand(_ args: [String]) -> String? {
    guard !args.contains(where: { ["-h", "--help", "-V", "--version"].contains($0) }) else { return nil }
    guard let index = uvCommandOffset(args) else { return nil }
    guard index < args.count else { return nil }
    let command = ["v", "virtualenv"].contains(args[index]) ? "venv" : args[index]
    if ["add", "remove", "sync", "lock", "upgrade", "tree", "export", "audit", "check", "run",
        "build", "publish", "version", "venv"].contains(command) { return command }
    guard index + 1 < args.count else { return nil }
    guard let offset = uvCommandOffset(Array(args.dropFirst(index + 1)), pip: command == "pip"),
          index + 1 + offset < args.count else { return nil }
    let raw = args[index + 1 + offset]
    let subcommand = raw == "ls" ? "list" : (command == "tool" && raw == "update" ? "upgrade" : raw)
    if command == "pip", ["compile", "install", "sync", "uninstall", "list", "tree"].contains(subcommand) {
        return "pip \(subcommand)"
    }
    if command == "tool", ["run", "uvx", "install", "upgrade", "list"].contains(subcommand) {
        return subcommand == "uvx" ? "tool run" : "tool \(subcommand)"
    }
    return nil
}

private func uvCommandOffset(_ args: [String], pip: Bool = false) -> Int? {
    var values: Set<String> = ["--color", "--cache-dir", "--directory", "--project", "--config-file",
        "--allow-insecure-host", "--trusted-host", "--preview-feature", "--preview-features", "--no-preview-features"]
    if pip { values.insert("--cert") }
    let flags: Set<String> = ["-q", "--quiet", "-v", "--verbose", "-n", "--no-cache", "--no-config",
        "--offline", "--no-offline", "--no-system-certs", "--no-native-tls", "--no-progress", "--system-certs", "--native-tls", "--managed-python",
        "--no-managed-python", "--no-python-downloads", "--preview", "--no-preview"]
    var index = 0
    while index < args.count {
        let arg = args[index]
        let flag = String(arg.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)[0])
        if values.contains(flag) {
            if arg.contains("=") {
                guard !arg.hasSuffix("=") else { return nil }
            } else {
                index += 1
                guard index < args.count, !args[index].isEmpty, !args[index].hasPrefix("-") else { return nil }
            }
        } else if flags.contains(flag) {
            guard !arg.contains("=") else { return nil }
        } else if arg.hasPrefix("-"), arg.count > 1, arg.dropFirst().allSatisfy({ $0 == "q" || $0 == "v" }) {
            // clap accepts combined/repeated verbosity flags.
        } else if arg.hasPrefix("-") { return nil }
        else { break }
        index += 1
    }
    return index
}

public func uvRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    // Even list/tree may execute a selected Python interpreter. A direct child
    // can exec the signed helper and retain uv as its original parent. The nonce
    // binds the complete operation; it does not isolate code inside that operation.
    // Never auto-authorize these commands as Read Only or Local Write.
    uvCredentialCommand(args) == "publish" ? .mutating : .unknown
}

public struct UVKeyringCredential: Equatable, Sendable {
    public let username: String
    public let password: String
}

private func uvHTTPSService(_ value: String) -> URLComponents? {
    guard value.utf8.count <= 8192,
          !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
          let url = URLComponents(string: value), url.scheme == "https",
          let host = url.host, !host.isEmpty,
          url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
          url.url != nil else { return nil }
    return url
}

public func validUVKeyringScope(service: String, username: String?) -> Bool {
    uvHTTPSService(service) != nil && (username.map {
        !$0.isEmpty && $0.utf8.count <= 1024 && !$0.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
    } ?? true)
}

/// Same-origin, segment-boundary prefix matching; ambiguous usernames fail closed.
/// Only the selected password crosses the helper boundary, never the credential bundle.
public func uvKeyringCredential(_ stored: String, service: String, username: String?) -> UVKeyringCredential? {
    guard validUVKeyringScope(service: service, username: username),
          let requested = uvHTTPSService(service),
          let data = stored.data(using: .utf8), data.count <= 1024 * 1024,
          let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          Set(object.keys) == ["credential"],
          let entries = object["credential"] as? [[String: String]],
          !entries.isEmpty, entries.count <= 256 else { return nil }
    var matches: [(Int, UVKeyringCredential)] = []
    for entry in entries {
        guard Set(entry.keys) == ["service", "username", "password"],
              let service = entry["service"], let scope = uvHTTPSService(service),
              let user = entry["username"], let password = entry["password"],
              validUVKeyringScope(service: service, username: user), !password.isEmpty, password.last?.isWhitespace == false,
              !password.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return nil }
        guard scope.host?.lowercased() == requested.host?.lowercased(),
              (scope.port ?? 443) == (requested.port ?? 443),
              username == nil || username == user else { continue }
        let prefix = scope.percentEncodedPath.isEmpty ? "/" : scope.percentEncodedPath
        let path = requested.percentEncodedPath.isEmpty ? "/" : requested.percentEncodedPath
        guard path == prefix || path.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/") else { continue }
        matches.append((prefix.utf8.count, UVKeyringCredential(username: user, password: password)))
    }
    guard let longest = matches.map(\.0).max() else { return nil }
    let selected = matches.filter { $0.0 == longest }
    return selected.count == 1 ? selected[0].1 : nil
}

public struct UVRegisteredInvocation: Sendable {
    public let nonce: String
    public let arguments: [String]
    public let cwd: String
    public let processStart: UInt64
    public let effectiveUID: UInt32
    public let auditSession: UInt32
    public var targetPIDVersion: Int32?

    public init(nonce: String, arguments: [String], cwd: String, processStart: UInt64,
                effectiveUID: UInt32, auditSession: UInt32) {
        self.nonce = nonce; self.arguments = arguments; self.cwd = cwd
        self.processStart = processStart; self.effectiveUID = effectiveUID; self.auditSession = auditSession
    }

    public func matches(nonce: String, arguments: [String], processStart: UInt64,
                        effectiveUID: UInt32, auditSession: UInt32, pidVersion: Int32) -> Bool {
        self.nonce == nonce && self.arguments == arguments && self.processStart == processStart
            && self.effectiveUID == effectiveUID && self.auditSession == auditSession
            && (targetPIDVersion == nil || targetPIDVersion == pidVersion)
            && uvCredentialCommand(arguments) != nil
    }
}
