import CryptoKit
import Darwin
import Foundation
import Security

public let blessedScriptsKeychainService = "com.automicvault.blessed-scripts"
public let blessedScriptsKeychainAccount = "BlessedScriptsV1"
public let blessedScriptMaximumBytes = 1024 * 1024

private enum BlessedScriptFileError: Error, LocalizedError {
    case cannotOpen
    case cannotVerifyPath
    case cannotReadMetadata
    case notRegularFile
    case tooLarge
    case pathChanged
    case cannotRead

    var errorDescription: String? {
        switch self {
        case .cannotOpen: "script could not be opened securely"
        case .cannotVerifyPath: "script path could not be verified"
        case .cannotReadMetadata: "script metadata could not be read"
        case .notRegularFile: "script is not a regular file"
        case .tooLarge: "script exceeds the 1 MiB size limit"
        case .pathChanged: "script path changed while it was being verified"
        case .cannotRead: "script contents could not be read"
        }
    }
}

public func readBlessedScript(path: String) throws -> Data {
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw BlessedScriptFileError.cannotOpen }
    defer { close(descriptor) }

    var info = stat()
    var resolvedPath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    var canonicalPath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    guard fcntl(descriptor, F_GETPATH, &resolvedPath) == 0,
          path.withCString({ realpath($0, &canonicalPath) }) != nil
    else {
        throw BlessedScriptFileError.cannotVerifyPath
    }
    let openedPath = String(
        decoding: resolvedPath.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
    let canonicalPathString = String(
        decoding: canonicalPath.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
    guard fstat(descriptor, &info) == 0 else { throw BlessedScriptFileError.cannotReadMetadata }
    guard info.st_mode & S_IFMT == S_IFREG else { throw BlessedScriptFileError.notRegularFile }
    guard info.st_size <= blessedScriptMaximumBytes else { throw BlessedScriptFileError.tooLarge }
    guard openedPath == canonicalPathString else { throw BlessedScriptFileError.pathChanged }

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
            throw BlessedScriptFileError.cannotRead
        }
        data.append(contentsOf: buffer.prefix(count))
    }
    throw BlessedScriptFileError.tooLarge
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

public func launcherEndorsementsForReblessing(
    previouslyEndorsed: [BlessedScriptLauncher],
    requestedLauncher: BlessedScriptLauncher?
) -> [BlessedScriptLauncher] {
    guard let requestedLauncher,
          !previouslyEndorsed.contains(where: { $0.requirement == requestedLauncher.requirement })
    else {
        return previouslyEndorsed
    }
    return previouslyEndorsed + [requestedLauncher]
}

public struct BlessedScript: Codable, Equatable, Identifiable, Sendable {
    public let path: String
    public let checksum: String
    public let keys: [String]
    public let target: String
    public let replaceExistingEnv: Bool
    public let allowMissingKeys: Bool
    public let allowsCanonicalPathExecution: Bool?
    public let capabilities: [String: SecretGateProtection]
    public let launchers: [BlessedScriptLauncher]
    public let blessedAt: Date
    public let reviewedContents: Data?

    public var id: String { path }

    public var verifiedReviewedContents: Data? {
        guard let reviewedContents,
              SHA256.hash(data: reviewedContents).map({ String(format: "%02x", $0) }).joined() == checksum
        else { return nil }
        return reviewedContents
    }

    public func matchesBlessing(path: String, checksum: String) -> Bool {
        self.path == path && self.checksum == checksum
    }

    public func allowsExecution(snapshotIncompatibleInterpreter: String?) -> Bool {
        snapshotIncompatibleInterpreter == nil || allowsCanonicalPathExecution == true
    }

    public func matchesExecution(
        path: String,
        checksum: String,
        keys: [String],
        target: String,
        replaceExistingEnv: Bool,
        allowMissingKeys: Bool
    ) -> Bool {
        self.path == path
            && self.checksum == checksum
            && self.keys == keys.sorted()
            && self.target == target
            && self.replaceExistingEnv == replaceExistingEnv
            && self.allowMissingKeys == allowMissingKeys
    }

    public func matchesExecution(
        path: String,
        checksum: String,
        keys: [String],
        target: String,
        replaceExistingEnv: Bool,
        allowMissingKeys: Bool,
        launcherRequirement: String
    ) -> Bool {
        matchesExecution(
            path: path,
            checksum: checksum,
            keys: keys,
            target: target,
            replaceExistingEnv: replaceExistingEnv,
            allowMissingKeys: allowMissingKeys
        )
            && launchers.contains { $0.requirement == launcherRequirement }
    }

    public init(
        path: String,
        checksum: String,
        keys: [String],
        target: String,
        replaceExistingEnv: Bool,
        allowMissingKeys: Bool,
        allowsCanonicalPathExecution: Bool = false,
        capabilities: [String: SecretGateProtection],
        launchers: [BlessedScriptLauncher],
        blessedAt: Date = Date(),
        reviewedContents: Data? = nil
    ) {
        self.path = path
        self.checksum = checksum
        self.keys = keys.sorted()
        self.target = target
        self.replaceExistingEnv = replaceExistingEnv
        self.allowMissingKeys = allowMissingKeys
        self.allowsCanonicalPathExecution = allowsCanonicalPathExecution
        self.capabilities = capabilities
        self.launchers = launchers
        self.blessedAt = blessedAt
        self.reviewedContents = reviewedContents
    }

    func removingLauncher(requirement: String) -> BlessedScript {
        BlessedScript(
            copying: self,
            launchers: launchers.filter { $0.requirement != requirement },
            reviewedContents: reviewedContents
        )
    }

    fileprivate func recordingReviewedContents(_ contents: Data) -> BlessedScript {
        BlessedScript(copying: self, launchers: launchers, reviewedContents: contents)
    }

    private init(
        copying script: BlessedScript,
        launchers: [BlessedScriptLauncher],
        reviewedContents: Data?
    ) {
        path = script.path
        checksum = script.checksum
        keys = script.keys
        target = script.target
        replaceExistingEnv = script.replaceExistingEnv
        allowMissingKeys = script.allowMissingKeys
        allowsCanonicalPathExecution = script.allowsCanonicalPathExecution
        capabilities = script.capabilities
        self.launchers = launchers
        blessedAt = script.blessedAt
        self.reviewedContents = reviewedContents
    }
}

public func blessedScriptDiff(previous: Data, current: Data) -> [String]? {
    guard let previous = String(data: previous, encoding: .utf8),
          let current = String(data: current, encoding: .utf8)
    else { return nil }
    let old = previous.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    let new = current.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    let changes = new.difference(from: old)
    let removals = Dictionary(uniqueKeysWithValues: changes.removals.map { change in
        if case .remove(let offset, let line, _) = change { return (offset, line) }
        preconditionFailure("Expected a removal")
    })
    let insertions = Dictionary(uniqueKeysWithValues: changes.insertions.map { change in
        if case .insert(let offset, let line, _) = change { return (offset, line) }
        preconditionFailure("Expected an insertion")
    })
    var rows: [(text: String, oldLine: Int?, newLine: Int?)] = []
    var oldIndex = 0
    var newIndex = 0
    while oldIndex < old.count || newIndex < new.count {
        if let removed = removals[oldIndex] {
            rows.append(("- \(removed)", oldIndex + 1, nil))
            oldIndex += 1
        } else if let inserted = insertions[newIndex] {
            rows.append(("+ \(inserted)", nil, newIndex + 1))
            newIndex += 1
        } else if oldIndex < old.count, newIndex < new.count {
            rows.append(("  \(old[oldIndex])", oldIndex + 1, newIndex + 1))
            oldIndex += 1
            newIndex += 1
        } else {
            break
        }
    }

    let context = 3
    let changed = rows.indices.filter { rows[$0].oldLine == nil || rows[$0].newLine == nil }
    var hunks: [Range<Int>] = []
    for index in changed {
        let range = max(rows.startIndex, index - context)..<min(rows.endIndex, index + context + 1)
        if let last = hunks.last, range.lowerBound <= last.upperBound {
            hunks[hunks.count - 1] = last.lowerBound..<max(last.upperBound, range.upperBound)
        } else {
            hunks.append(range)
        }
    }

    var output = ["--- Blessed", "+++ Current"]
    for hunk in hunks {
        let oldLines = hunk.compactMap { rows[$0].oldLine }
        let newLines = hunk.compactMap { rows[$0].newLine }
        output.append("@@ -\(diffRange(oldLines)) +\(diffRange(newLines)) @@")
        output.append(contentsOf: hunk.map { rows[$0].text })
    }
    return output
}

private func diffRange(_ lines: [Int]) -> String {
    guard let first = lines.first else { return "0,0" }
    return lines.count == 1 ? "\(first)" : "\(first),\(lines.count)"
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
    public let snapshotIncompatibleInterpreter: String?
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
        snapshotIncompatibleInterpreter: injection.snapshotIncompatibleInterpreter,
        manifest: manifest
    )
}

private func parseInjectShebang(
    _ line: String
) throws -> (
    keys: [String],
    target: String,
    replaceExistingEnv: Bool,
    allowMissingKeys: Bool,
    snapshotIncompatibleInterpreter: String?
) {
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
            guard let target = words.first, target.hasPrefix("/") else {
                throw BlessedScriptManifestError.invalidShebang
            }
            return (
                keys.sorted(), target, replaceExistingEnv, allowMissingKeys,
                snapshotIncompatibleInterpreter(in: words)
            )
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
                return (
                    keys.sorted(), word, replaceExistingEnv, allowMissingKeys,
                    snapshotIncompatibleInterpreter(in: [word] + words)
                )
            }
        }
    }
    throw BlessedScriptManifestError.invalidShebang
}

private func snapshotIncompatibleInterpreter(in command: [String]) -> String? {
    command.lazy
        .map { URL(fileURLWithPath: $0).lastPathComponent }
        .first { $0 == "uv" }
}

private func validBlessedSecretKey(_ key: String) -> Bool {
    guard let first = key.first, first == "_" || first.isASCII && first.isLetter else { return false }
    return key.dropFirst().allSatisfy { $0 == "_" || $0.isASCII && ($0.isLetter || $0.isNumber) }
}

private func parseBlessedScriptManifest(lines: [String]) throws -> BlessedScriptManifest {
    guard lines.count > 1, lines[1] == "# --- automic-vault" else {
        return BlessedScriptManifest(capabilities: [:])
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
    case "write", "trusted": .fullExceptSecretDumps
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

func blessingByRecordingReviewedContents(
    _ script: BlessedScript,
    contents: Data
) -> BlessedScript? {
    guard script.reviewedContents == nil,
          let declaration = try? blessedScriptDeclaration(data: contents),
          declaration.checksum == script.checksum
    else { return nil }
    return script.recordingReviewedContents(contents)
}

@discardableResult
public func backfillBlessedScriptReviewedContents(
    service: String = blessedScriptsKeychainService,
    account: String = blessedScriptsKeychainAccount
) -> OSStatus {
    var changed = false
    let scripts = loadBlessedScripts(service: service, account: account).map { script in
        guard let contents = try? readBlessedScript(path: script.path),
              let updated = blessingByRecordingReviewedContents(script, contents: contents)
        else { return script }
        changed = true
        return updated
    }
    return changed ? saveBlessedScripts(scripts, service: service, account: account) : errSecSuccess
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

@discardableResult
public func removeLauncherFromBlessedScripts(
    requirement: String,
    service: String = blessedScriptsKeychainService,
    account: String = blessedScriptsKeychainAccount
) -> OSStatus {
    let scripts: [BlessedScript]
    switch loadKeychainDataResult(service: service, account: account) {
    case .notFound: return errSecSuccess
    case .failure(let status): return status
    case .success(let data):
        guard let decoded = try? JSONDecoder().decode([BlessedScript].self, from: data)
        else { return errSecDecode }
        scripts = decoded
    }
    let updated = scripts.map { $0.removingLauncher(requirement: requirement) }
    return saveBlessedScripts(updated, service: service, account: account)
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

public func activeBlessedScriptPromptExplanation(
    script: BlessedScript,
    gateID: String?,
    launcherAllowsOperation: Bool
) -> String {
    guard let gateID, launcherAllowsOperation else {
        return "This request exceeds the stored authority. Approval applies only to this request."
    }
    if script.capabilities[gateID] == nil {
        return "The Blessed Script’s declared Capabilities narrow gate policy for this execution and lack a \(gateID) Capability. Approval applies only to this request."
    } else {
        return "The Blessed Script’s declared Capabilities narrow gate policy for this execution and exceed the declared \(gateID) Capability. Approval applies only to this request."
    }
}
