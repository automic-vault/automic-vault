import CryptoKit
import Darwin
import Foundation
import Security

public let blessedScriptsKeychainService = "com.automicvault.blessed-scripts"
public let blessedScriptsKeychainAccount = "BlessedScriptsV1"
public let blessedScriptMaximumBytes = 1024 * 1024

private enum BlessedScriptFileError: Error {
    case invalid
}

public func readBlessedScript(path: String) throws -> Data {
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw BlessedScriptFileError.invalid }
    defer { close(descriptor) }

    var info = stat()
    var resolvedPath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    var canonicalPath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    guard fcntl(descriptor, F_GETPATH, &resolvedPath) == 0,
          path.withCString({ realpath($0, &canonicalPath) }) != nil
    else {
        throw BlessedScriptFileError.invalid
    }
    let openedPath = String(
        decoding: resolvedPath.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
    let canonicalPathString = String(
        decoding: canonicalPath.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
    guard fstat(descriptor, &info) == 0,
          info.st_mode & S_IFMT == S_IFREG,
          info.st_size <= blessedScriptMaximumBytes,
          openedPath == canonicalPathString
    else {
        throw BlessedScriptFileError.invalid
    }

    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while data.count <= blessedScriptMaximumBytes {
        let limit = min(buffer.count, blessedScriptMaximumBytes + 1 - data.count)
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(descriptor, $0.baseAddress, limit)
        }
        if count == 0 { return data }
        if count < 0 {
            if errno == EINTR { continue }
            throw BlessedScriptFileError.invalid
        }
        data.append(contentsOf: buffer.prefix(count))
    }
    throw BlessedScriptFileError.invalid
}

public struct BlessedScriptManifest: Equatable, Sendable {
    public let capabilities: [String: SecretGateProtection]

    public init(capabilities: [String: SecretGateProtection]) {
        self.capabilities = capabilities
    }
}

public struct BlessedScriptLauncher: Codable, Equatable, Sendable {
    public let bundleIdentifier: String
    public let requirement: String

    public init(bundleIdentifier: String, requirement: String) {
        self.bundleIdentifier = bundleIdentifier
        self.requirement = requirement
    }
}

public struct BlessedScript: Codable, Equatable, Identifiable, Sendable {
    public let path: String
    public let checksum: String
    public let keys: [String]
    public let target: String
    public let replaceExistingEnv: Bool
    public let allowMissingKeys: Bool
    public let capabilities: [String: SecretGateProtection]
    public let launchers: [BlessedScriptLauncher]
    public let blessedAt: Date

    public var id: String { path }

    public init(
        path: String,
        checksum: String,
        keys: [String],
        target: String,
        replaceExistingEnv: Bool,
        allowMissingKeys: Bool,
        capabilities: [String: SecretGateProtection],
        launchers: [BlessedScriptLauncher],
        blessedAt: Date = Date()
    ) {
        self.path = path
        self.checksum = checksum
        self.keys = keys.sorted()
        self.target = target
        self.replaceExistingEnv = replaceExistingEnv
        self.allowMissingKeys = allowMissingKeys
        self.capabilities = capabilities
        self.launchers = launchers
        self.blessedAt = blessedAt
    }
}

public enum BlessedScriptManifestError: Error, Equatable, LocalizedError {
    case invalidUTF8
    case missingShebang
    case invalidShebang
    case missingManifest
    case malformedManifest(String)

    public var errorDescription: String? {
        switch self {
        case .invalidUTF8: "script must be valid UTF-8"
        case .missingShebang: "script must start with an av inject shebang"
        case .invalidShebang: "invalid av inject shebang"
        case .missingManifest: "script has no Automic Vault manifest"
        case .malformedManifest(let reason): "invalid Automic Vault manifest: \(reason)"
        }
    }
}

public struct BlessedScriptDeclaration: Equatable, Sendable {
    public let checksum: String
    public let keys: [String]
    public let target: String
    public let replaceExistingEnv: Bool
    public let allowMissingKeys: Bool
    public let manifest: BlessedScriptManifest
}

public func blessedScriptDeclaration(data: Data) throws -> BlessedScriptDeclaration {
    guard let source = String(data: data, encoding: .utf8) else {
        throw BlessedScriptManifestError.invalidUTF8
    }
    let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    guard let shebang = lines.first, shebang.hasPrefix("#!") else {
        throw BlessedScriptManifestError.missingShebang
    }
    let injection = try parseInjectShebang(shebang)
    let manifest = try parseBlessedScriptManifest(lines: lines)
    return BlessedScriptDeclaration(
        checksum: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
        keys: injection.keys,
        target: injection.target,
        replaceExistingEnv: injection.replaceExistingEnv,
        allowMissingKeys: injection.allowMissingKeys,
        manifest: manifest
    )
}

private func parseInjectShebang(
    _ line: String
) throws -> (keys: [String], target: String, replaceExistingEnv: Bool, allowMissingKeys: Bool) {
    var words = line.dropFirst(2).split(whereSeparator: \.isWhitespace).map(String.init)
    guard let interpreter = words.first,
          interpreter.hasPrefix("/"),
          URL(fileURLWithPath: interpreter).lastPathComponent == "av"
    else {
        throw BlessedScriptManifestError.invalidShebang
    }
    words.removeFirst()
    guard words.first == "inject" else { throw BlessedScriptManifestError.invalidShebang }
    words.removeFirst()

    var keys = Set<String>()
    var replaceExistingEnv = false
    var allowMissingKeys = false
    while let word = words.first {
        words.removeFirst()
        switch word {
        case "--replace-existing-env":
            replaceExistingEnv = true
        case "--allow-missing-keys":
            allowMissingKeys = true
        case "--":
            guard let target = words.first, target.hasPrefix("/"), !keys.isEmpty else {
                throw BlessedScriptManifestError.invalidShebang
            }
            return (keys.sorted(), target, replaceExistingEnv, allowMissingKeys)
        default:
            if word.hasPrefix("+") {
                let key = String(word.dropFirst())
                guard validBlessedSecretKey(key), keys.insert(key).inserted else {
                    throw BlessedScriptManifestError.invalidShebang
                }
            } else {
                guard !keys.isEmpty, word.hasPrefix("/") else {
                    throw BlessedScriptManifestError.invalidShebang
                }
                return (keys.sorted(), word, replaceExistingEnv, allowMissingKeys)
            }
        }
    }
    throw BlessedScriptManifestError.invalidShebang
}

private func validBlessedSecretKey(_ key: String) -> Bool {
    guard let first = key.first, first == "_" || first.isASCII && first.isLetter else { return false }
    return key.dropFirst().allSatisfy { $0 == "_" || $0.isASCII && ($0.isLetter || $0.isNumber) }
}

private func parseBlessedScriptManifest(lines: [String]) throws -> BlessedScriptManifest {
    guard lines.count > 1, lines[1] == "# --- automic-vault" else {
        throw BlessedScriptManifestError.missingManifest
    }
    var capabilities: [String: SecretGateProtection] = [:]
    var index = 2
    guard index < lines.count, lines[index] == "# capabilities:" else {
        throw BlessedScriptManifestError.malformedManifest("expected `capabilities:`")
    }
    index += 1
    while index < lines.count, lines[index] != "# ---" {
        let line = lines[index]
        guard line.hasPrefix("#   "),
              let separator = line.firstIndex(of: ":")
        else {
            throw BlessedScriptManifestError.malformedManifest("line \(index + 1)")
        }
        let gate = line[line.index(line.startIndex, offsetBy: 4)..<separator]
        let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
        guard validGateID(String(gate)),
              let protection = manifestProtection(value),
              capabilities.updateValue(protection, forKey: String(gate)) == nil
        else {
            throw BlessedScriptManifestError.malformedManifest("line \(index + 1)")
        }
        index += 1
    }
    guard index < lines.count, lines[index] == "# ---", !capabilities.isEmpty else {
        throw BlessedScriptManifestError.malformedManifest("missing closing marker or capabilities")
    }
    return BlessedScriptManifest(capabilities: capabilities)
}

private func validGateID(_ value: String) -> Bool {
    !value.isEmpty && value.count <= 64 && value.allSatisfy {
        $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_")
    }
}

private func manifestProtection(_ value: String) -> SecretGateProtection? {
    switch value {
    case "read-only": .readOnly
    case "local-write": .readOnlyAndLocalWrites
    case "read-and-updates": .readOnlyAndUpdates
    case "trusted": .fullExceptSecretDumps
    case "full": .fullIncludingSecretDumps
    default: nil
    }
}

public func loadBlessedScripts(
    service: String = blessedScriptsKeychainService,
    account: String = blessedScriptsKeychainAccount
) -> [BlessedScript] {
    guard case .success(let data) = loadKeychainDataResult(service: service, account: account),
          let scripts = try? JSONDecoder().decode([BlessedScript].self, from: data)
    else {
        return []
    }
    return scripts.sorted { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
}

@discardableResult
public func saveBlessedScript(
    _ script: BlessedScript,
    service: String = blessedScriptsKeychainService,
    account: String = blessedScriptsKeychainAccount
) -> OSStatus {
    var scripts = loadBlessedScripts(service: service, account: account)
    scripts.removeAll { $0.path == script.path }
    scripts.append(script)
    return saveBlessedScripts(scripts, service: service, account: account)
}

@discardableResult
public func removeBlessedScript(
    path: String,
    service: String = blessedScriptsKeychainService,
    account: String = blessedScriptsKeychainAccount
) -> OSStatus {
    let scripts = loadBlessedScripts(service: service, account: account).filter { $0.path != path }
    if scripts.isEmpty {
        let status = deleteStoredSecret(account: account, service: service)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
    return saveBlessedScripts(scripts, service: service, account: account)
}

private func saveBlessedScripts(_ scripts: [BlessedScript], service: String, account: String) -> OSStatus {
    guard let data = try? JSONEncoder().encode(scripts.sorted {
        $0.path.localizedStandardCompare($1.path) == .orderedAscending
    }) else {
        return errSecParam
    }
    return saveKeychainData(
        data,
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    )
}
