import CryptoKit
import Foundation
import Security

public let blessedDotenvsKeychainService = "com.automicvault.blessed-dotenvs"
public let blessedDotenvsKeychainAccount = "BlessedDotenvsV1"

public struct DotenvSecretDeclaration: Equatable, Sendable {
    public let item: String
    public let secret: String

    public init(item: String, secret: String) {
        self.item = item
        self.secret = secret
    }
}

public struct BlessedDotenvProcess: Codable, Equatable, Hashable, Sendable {
    public let path: String
    public let arguments: [String]
    public let cwd: String

    public init(path: String, arguments: [String], cwd: String) {
        self.path = path
        self.arguments = arguments
        self.cwd = cwd
    }
}

public struct BlessedDotenv: Codable, Equatable, Identifiable, Sendable {
    public let path: String
    public let checksum: String
    public let processes: [BlessedDotenvProcess]
    public let launchers: [BlessedScriptLauncher]
    public let blessedAt: Date

    public var id: String {
        var data = Data()
        appendIdentity(path, to: &data)
        appendIdentity(String(processes.count), to: &data)
        for process in processes {
            appendIdentity(process.path, to: &data)
            appendIdentity(process.cwd, to: &data)
            appendIdentity(String(process.arguments.count), to: &data)
            process.arguments.forEach { appendIdentity($0, to: &data) }
        }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public init(
        path: String,
        checksum: String,
        processes: [BlessedDotenvProcess],
        launchers: [BlessedScriptLauncher],
        blessedAt: Date = Date()
    ) {
        self.path = path
        self.checksum = checksum
        self.processes = processes
        self.launchers = launchers
        self.blessedAt = blessedAt
    }

    public func matches(
        path: String,
        checksum: String,
        processes: [BlessedDotenvProcess],
        launcherRequirement: String
    ) -> Bool {
        self.path == path
            && self.checksum == checksum
            && self.processes == processes
            && launchers.contains { $0.requirement == launcherRequirement }
    }
}

private func appendIdentity(_ value: String, to data: inout Data) {
    var length = UInt64(value.utf8.count).bigEndian
    withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
    data.append(contentsOf: value.utf8)
}

public func dotenvSchemaDeclaration(
    data: Data,
    item requestedItem: String,
    secret requestedSecret: String
) -> DotenvSecretDeclaration? {
    dotenvSchemaDeclarations(data: data).first {
        $0.item == requestedItem && $0.secret == requestedSecret
    }
}

public func dotenvSchemaDeclarations(data: Data) -> [DotenvSecretDeclaration] {
    guard let source = String(data: data, encoding: .utf8) else { return [] }
    return source.split(separator: "\n", omittingEmptySubsequences: false).compactMap { rawLine in
        let line = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .trimmingCharacters(in: .whitespaces)
        guard let separator = line.firstIndex(of: "=") else { return nil }
        let item = line[..<separator].trimmingCharacters(in: .whitespaces)
        guard validDotenvKey(item) else { return nil }

        let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
        guard value.hasPrefix("av("), value.hasSuffix(")") else { return nil }
        var argument = value.dropFirst(3).dropLast().trimmingCharacters(in: .whitespaces)
        if argument.count >= 2,
           let first = argument.first,
           first == argument.last,
           first == "\"" || first == "'"
        {
            argument = String(argument.dropFirst().dropLast())
        }
        let secret = argument.isEmpty ? item : argument
        guard validDotenvKey(secret) else { return nil }
        return DotenvSecretDeclaration(item: item, secret: secret)
    }
}

public func dotenvSchemaChecksum(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func validDotenvKey(_ key: String) -> Bool {
    guard let first = key.first, first == "_" || first.isASCII && first.isLetter else { return false }
    return key.dropFirst().allSatisfy { $0 == "_" || $0.isASCII && ($0.isLetter || $0.isNumber) }
}

public func loadBlessedDotenvs(
    service: String = blessedDotenvsKeychainService,
    account: String = blessedDotenvsKeychainAccount
) -> [BlessedDotenv] {
    guard case .success(let data) = loadKeychainDataResult(service: service, account: account),
          let dotenvs = try? JSONDecoder().decode([BlessedDotenv].self, from: data)
    else {
        return []
    }
    return dotenvs.sorted { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
}

@discardableResult
public func saveBlessedDotenv(
    _ dotenv: BlessedDotenv,
    service: String = blessedDotenvsKeychainService,
    account: String = blessedDotenvsKeychainAccount
) -> OSStatus {
    var dotenvs = loadBlessedDotenvs(service: service, account: account)
    dotenvs.removeAll { $0.id == dotenv.id }
    dotenvs.append(dotenv)
    return saveBlessedDotenvs(dotenvs, service: service, account: account)
}

@discardableResult
public func removeBlessedDotenv(
    id: String,
    service: String = blessedDotenvsKeychainService,
    account: String = blessedDotenvsKeychainAccount
) -> OSStatus {
    let dotenvs = loadBlessedDotenvs(service: service, account: account).filter { $0.id != id }
    if dotenvs.isEmpty {
        let status = deleteStoredSecret(account: account, service: service)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
    return saveBlessedDotenvs(dotenvs, service: service, account: account)
}

private func saveBlessedDotenvs(
    _ dotenvs: [BlessedDotenv],
    service: String,
    account: String
) -> OSStatus {
    guard let data = try? JSONEncoder().encode(dotenvs.sorted {
        $0.id.localizedStandardCompare($1.id) == .orderedAscending
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
