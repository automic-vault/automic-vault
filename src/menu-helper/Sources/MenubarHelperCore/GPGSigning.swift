import Foundation
import Security

public let gpgDefaultPrivateKeySecretName = "AV_GPG_PRIVATE_KEY"
public let gpgDefaultPassphraseSecretName = "AV_GPG_PASSPHRASE"
public let gpgAlternatePrivateKeySecretName = "AV_GPG_AGENT_PRIVATE_KEY"
public let gpgAlternatePassphraseSecretName = "AV_GPG_AGENT_PASSPHRASE"

private let legacyGPGSecretNames = [
    ("AUTOMIC_GPG_SIGNING_PRIVATE_KEY", gpgDefaultPrivateKeySecretName),
    ("AUTOMIC_GPG_SIGNING_PASSPHRASE", gpgDefaultPassphraseSecretName),
    ("AUTOMIC_GPG_AGENT_SIGNING_PRIVATE_KEY", gpgAlternatePrivateKeySecretName),
    ("AUTOMIC_GPG_AGENT_SIGNING_PASSPHRASE", gpgAlternatePassphraseSecretName),
]

public let gpgSigningConfigurationService = "com.automicvault.gpg-signing-configuration"
public let gpgSigningConfigurationAccount = "configuration"

public struct GPGSigningConfiguration: Codable, Equatable, Sendable {
    public var alternateKeyLaunchers: [BlessedScriptLauncher]

    public init(alternateKeyLaunchers: [BlessedScriptLauncher] = []) {
        self.alternateKeyLaunchers = alternateKeyLaunchers
    }
}

public func loadGPGSigningConfiguration() -> GPGSigningConfiguration {
    loadGPGSigningConfiguration(
        service: gpgSigningConfigurationService,
        account: gpgSigningConfigurationAccount
    )
}

func loadGPGSigningConfiguration(service: String, account: String) -> GPGSigningConfiguration {
    guard case .success(let data) = loadKeychainDataResult(service: service, account: account),
          let configuration = try? JSONDecoder().decode(GPGSigningConfiguration.self, from: data)
    else { return GPGSigningConfiguration() }
    return configuration
}

@discardableResult
public func saveGPGSigningConfiguration(
    _ configuration: GPGSigningConfiguration
) -> OSStatus {
    saveGPGSigningConfiguration(
        configuration,
        service: gpgSigningConfigurationService,
        account: gpgSigningConfigurationAccount
    )
}

@discardableResult
func saveGPGSigningConfiguration(
    _ configuration: GPGSigningConfiguration,
    service: String,
    account: String
) -> OSStatus {
    guard let data = try? JSONEncoder().encode(configuration) else { return errSecParam }
    return saveKeychainData(
        data,
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    )
}

public func gpgSigningSecretNames(
    configuration: GPGSigningConfiguration,
    launcherRequirements: [String],
    storedSecretNames: Set<String>
) -> [String] {
    let useAlternate = configuration.alternateKeyLaunchers.contains { launcher in
        launcherRequirements.contains(launcher.requirement)
    }
    let names = useAlternate
        ? [gpgAlternatePrivateKeySecretName, gpgAlternatePassphraseSecretName]
        : [gpgDefaultPrivateKeySecretName, gpgDefaultPassphraseSecretName]
    return [names[0]] + names.dropFirst().filter(storedSecretNames.contains)
}

@discardableResult
public func saveGPGSigningCredential(
    privateKey: String,
    passphrase: String,
    alternate: Bool
) -> OSStatus {
    saveGPGSigningCredential(
        privateKey: privateKey,
        passphrase: passphrase,
        alternate: alternate,
        load: loadGPGStoredValue,
        save: { account, value in saveStoredSecret(account: account, value: value) },
        delete: { account in
            let status = deleteStoredSecretValueRevokingDirectAccessIfLast(
                secretName: account,
                source: .global
            )
            return status == errSecItemNotFound ? errSecSuccess : status
        }
    )
}

enum GPGStoredValueLoad {
    case value(String)
    case missing
    case failure(OSStatus)
}

private func loadGPGStoredValue(_ account: String) -> GPGStoredValueLoad {
    switch loadKeychainDataResult(service: automicVaultKeychainService, account: account) {
    case .success(let data):
        guard let value = String(data: data, encoding: .utf8) else {
            return .failure(errSecDecode)
        }
        return .value(value)
    case .notFound: return .missing
    case .failure(let status): return .failure(status)
    }
}

@discardableResult
public func migrateLegacyGPGSigningSecrets() -> OSStatus {
    migrateLegacyGPGSigningSecrets(
        load: loadGPGStoredValue,
        saveIfAbsentOrEqual: { account, value in
            saveStoredSecretIfAbsentOrEqual(account: account, value: value)
        },
        delete: { account in
            deleteStoredSecretValueRevokingDirectAccessIfLast(
                secretName: account,
                source: .global
            )
        }
    )
}

func migrateLegacyGPGSigningSecrets(
    load: (String) -> GPGStoredValueLoad,
    saveIfAbsentOrEqual: (String, String) -> OSStatus,
    delete: (String) -> OSStatus
) -> OSStatus {
    for (legacyName, currentName) in legacyGPGSecretNames {
        switch load(legacyName) {
        case .value(let value):
            if !value.isEmpty {
                let saveStatus = saveIfAbsentOrEqual(currentName, value)
                guard saveStatus == errSecSuccess else { return saveStatus }
            }
            let deleteStatus = delete(legacyName)
            guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
                return deleteStatus
            }
        case .failure(let status):
            return status
        case .missing:
            continue
        }
    }
    return migrateEmptyGPGSigningPassphrases(load: load, delete: delete)
}

@discardableResult
public func migrateEmptyGPGSigningPassphrases() -> OSStatus {
    migrateEmptyGPGSigningPassphrases(
        load: loadGPGStoredValue,
        delete: { account in
            deleteStoredSecretValueRevokingDirectAccessIfLast(
                secretName: account,
                source: .global
            )
        }
    )
}

func migrateEmptyGPGSigningPassphrases(
    load: (String) -> GPGStoredValueLoad,
    delete: (String) -> OSStatus
) -> OSStatus {
    for name in [gpgDefaultPassphraseSecretName, gpgAlternatePassphraseSecretName] {
        switch load(name) {
        case .value(let value) where value.isEmpty:
            let status = delete(name)
            if status != errSecSuccess && status != errSecItemNotFound { return status }
        case .failure(let status):
            return status
        case .value, .missing:
            continue
        }
    }
    return errSecSuccess
}

func saveGPGSigningCredential(
    privateKey: String,
    passphrase: String,
    alternate: Bool,
    load: (String) -> GPGStoredValueLoad,
    save: (String, String) -> OSStatus,
    delete: (String) -> OSStatus
) -> OSStatus {
    let keyName = alternate ? gpgAlternatePrivateKeySecretName : gpgDefaultPrivateKeySecretName
    let passphraseName = alternate
        ? gpgAlternatePassphraseSecretName : gpgDefaultPassphraseSecretName
    let previousPassphrase = load(passphraseName)
    if case .failure(let status) = previousPassphrase { return status }
    if passphrase.isEmpty {
        let keyStatus = save(keyName, privateKey)
        guard keyStatus == errSecSuccess else { return keyStatus }
        return delete(passphraseName)
    }
    let passphraseStatus = save(passphraseName, passphrase)
    guard passphraseStatus == errSecSuccess else { return passphraseStatus }
    let keyStatus = save(keyName, privateKey)
    guard keyStatus != errSecSuccess else { return errSecSuccess }
    let rollbackStatus = switch previousPassphrase {
    case .value(let previous): save(passphraseName, previous)
    case .missing: delete(passphraseName)
    case .failure: errSecInternalError
    }
    return rollbackStatus == errSecSuccess ? keyStatus : rollbackStatus
}

public func hasGPGSigningCredential(alternate: Bool) -> Bool {
    let name = alternate ? gpgAlternatePrivateKeySecretName : gpgDefaultPrivateKeySecretName
    return loadStoredSecrets().contains { $0.account == name }
}

public func configureGitForGPGSigning(
    gitURL: URL = URL(fileURLWithPath: "/usr/bin/git"),
    programURL: URL,
    environment: [String: String]? = nil
) throws {
    guard programURL.path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: programURL.path)
    else { throw GPGSigningConfigurationError.programUnavailable(programURL.path) }
    for arguments in [
        ["config", "--global", "gpg.program", programURL.path],
        ["config", "--global", "commit.gpgSign", "true"],
        ["config", "--global", "gpg.format", "openpgp"],
    ] {
        let process = Process()
        process.executableURL = gitURL
        process.arguments = arguments
        if let environment { process.environment = environment }
        let errorPipe = Pipe()
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(
                decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                as: UTF8.self
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            throw GPGSigningConfigurationError.gitFailed(detail)
        }
    }
}

public enum GPGSigningConfigurationError: LocalizedError {
    case programUnavailable(String)
    case bundledExecutableUnavailable(String)
    case credentialFailed(String)
    case gitFailed(String)

    public var errorDescription: String? {
        switch self {
        case .programUnavailable(let path): "The bundled Git signing adapter is unavailable at \(path)."
        case .bundledExecutableUnavailable(let path): "The bundled Automic Vault executable is unavailable or invalid at \(path)."
        case .credentialFailed(let detail): "Could not process the GPG credential\(detail.isEmpty ? "." : ": \(detail)")"
        case .gitFailed(let detail): "Git configuration failed\(detail.isEmpty ? "." : ": \(detail)")"
        }
    }
}

public func bundledExecutableURL(
    named name: String,
    beside mainExecutableURL: URL?,
    fileManager: FileManager = .default
) throws -> URL {
    guard let mainExecutableURL,
          mainExecutableURL.isFileURL,
          mainExecutableURL.path.hasPrefix("/"),
          !name.isEmpty,
          name == URL(fileURLWithPath: name).lastPathComponent
    else { throw GPGSigningConfigurationError.bundledExecutableUnavailable(name) }
    let candidate = mainExecutableURL.deletingLastPathComponent().appendingPathComponent(name)
    let attributes = try? fileManager.attributesOfItem(atPath: candidate.path)
    guard attributes?[.type] as? FileAttributeType == .typeRegular,
          fileManager.isExecutableFile(atPath: candidate.path)
    else { throw GPGSigningConfigurationError.bundledExecutableUnavailable(candidate.path) }
    return candidate
}
