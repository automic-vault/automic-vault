import Foundation
import Security
import Testing
@testable import MenubarHelperCore

@Test func gpgSecretNamesUseAVPrefix() {
    #expect(gpgDefaultPrivateKeySecretName == "AV_GPG_PRIVATE_KEY")
    #expect(gpgDefaultPassphraseSecretName == "AV_GPG_PASSPHRASE")
    #expect(gpgAlternatePrivateKeySecretName == "AV_GPG_AGENT_PRIVATE_KEY")
    #expect(gpgAlternatePassphraseSecretName == "AV_GPG_AGENT_PASSPHRASE")
}

@Test func launcherListSelectsTheAlternateSigningCredential() {
    let launcher = BlessedScriptLauncher(bundleIdentifier: "com.openai.codex", requirement: "codex")
    let configuration = GPGSigningConfiguration(alternateKeyLaunchers: [launcher])

    #expect(gpgSigningSecretNames(
        configuration: configuration,
        launcherRequirements: ["codex"],
        storedSecretNames: [
            gpgAlternatePrivateKeySecretName,
            gpgAlternatePassphraseSecretName,
        ]
    ) == [gpgAlternatePrivateKeySecretName, gpgAlternatePassphraseSecretName])
    #expect(gpgSigningSecretNames(
        configuration: configuration,
        launcherRequirements: ["terminal"],
        storedSecretNames: [gpgDefaultPrivateKeySecretName]
    ) == [gpgDefaultPrivateKeySecretName])
}

@Test(.enabled(if: dataProtectionKeychainAvailable(), "requires an entitled Keychain test host"))
func gpgSigningConfigurationIsAvailableAfterFirstUnlock() {
    let service = "com.automicvault.tests.gpg-config.\(UUID().uuidString)"
    let account = "configuration"
    defer { _ = deleteStoredSecret(account: account, service: service) }

    #expect(saveGPGSigningConfiguration(
        GPGSigningConfiguration(),
        service: service,
        account: account
    ) == errSecSuccess)
    #expect(
        keychainAccessibility(account: account, service: service)
            == kSecAttrAccessibleAfterFirstUnlock as String
    )
}

@Test func gitConfigurationPreservesAnAppPathContainingSpaces() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("Automic Vault Tests \(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let program = directory.appendingPathComponent("av-gpg")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: program)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: program.path)
    let gitConfig = directory.appendingPathComponent("gitconfig")

    let environment = ProcessInfo.processInfo.environment.merging(
        ["GIT_CONFIG_GLOBAL": gitConfig.path],
        uniquingKeysWith: { _, configured in configured }
    )
    try configureGitForGPGSigning(programURL: program, environment: environment)

    let configured = try String(contentsOf: gitConfig, encoding: .utf8)
    #expect(configured.contains(program.path))
    #expect(configured.contains("gpgSign = true"))
    #expect(configured.contains("format = openpgp"))
}

@Test func bundledExecutableResolutionNeverFallsBackOutsideTheApp() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("Automic Vault Bundle Tests \(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let mainExecutable = directory.appendingPathComponent("AutomicVaultMenubar")
    let bundledAV = directory.appendingPathComponent("av")
    try Data().write(to: mainExecutable)

    #expect(throws: GPGSigningConfigurationError.self) {
        try bundledExecutableURL(named: "av", beside: mainExecutable)
    }

    try Data().write(to: bundledAV)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bundledAV.path)
    #expect(try bundledExecutableURL(named: "av", beside: mainExecutable) == bundledAV)
}

@Test func emptyPassphraseIsNotStored() {
    var values: [String: String] = [:]
    let status = saveGPGSigningCredential(
        privateKey: "private",
        passphrase: "",
        alternate: false,
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        save: { account, value in
            values[account] = value
            return errSecSuccess
        },
        delete: { account in
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecSuccess)
    #expect(values[gpgDefaultPrivateKeySecretName] == "private")
    #expect(values[gpgDefaultPassphraseSecretName] == nil)
}

@Test func emptyStoredPassphraseIsMigratedWithoutTouchingNonemptyPassphrases() {
    var values = [
        gpgDefaultPassphraseSecretName: "",
        gpgAlternatePassphraseSecretName: "alternate-passphrase",
    ]
    let status = migrateEmptyGPGSigningPassphrases(
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        delete: { account in
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecSuccess)
    #expect(values[gpgDefaultPassphraseSecretName] == nil)
    #expect(values[gpgAlternatePassphraseSecretName] == "alternate-passphrase")
}

@Test func legacyGPGSecretNamesAreMigratedWithoutLosingCredentials() {
    var values = [
        "AUTOMIC_GPG_SIGNING_PRIVATE_KEY": "private",
        "AUTOMIC_GPG_SIGNING_PASSPHRASE": "",
        "AUTOMIC_GPG_AGENT_SIGNING_PRIVATE_KEY": "alternate-private",
        "AUTOMIC_GPG_AGENT_SIGNING_PASSPHRASE": "alternate-passphrase",
    ]
    let status = migrateLegacyGPGSigningSecrets(
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        saveIfAbsentOrEqual: { account, value in
            if let existing = values[account] {
                return existing == value ? errSecSuccess : errSecDuplicateItem
            }
            values[account] = value
            return errSecSuccess
        },
        delete: { account in
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecSuccess)
    #expect(values[gpgDefaultPrivateKeySecretName] == "private")
    #expect(values[gpgDefaultPassphraseSecretName] == nil)
    #expect(values[gpgAlternatePrivateKeySecretName] == "alternate-private")
    #expect(values[gpgAlternatePassphraseSecretName] == "alternate-passphrase")
    #expect(values.keys.allSatisfy { !$0.hasPrefix("AUTOMIC_GPG_") })
}

@Test func conflictingGPGSecretNameMigrationFailsClosed() {
    var values = [
        "AUTOMIC_GPG_SIGNING_PRIVATE_KEY": "legacy-private",
        "AV_GPG_PRIVATE_KEY": "current-private",
    ]
    let status = migrateLegacyGPGSigningSecrets(
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        saveIfAbsentOrEqual: { account, value in
            if let existing = values[account] {
                return existing == value ? errSecSuccess : errSecDuplicateItem
            }
            values[account] = value
            return errSecSuccess
        },
        delete: { account in
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecDuplicateItem)
    #expect(values["AUTOMIC_GPG_SIGNING_PRIVATE_KEY"] == "legacy-private")
    #expect(values[gpgDefaultPrivateKeySecretName] == "current-private")
}

@Test func failedPrivateKeySaveRemovesANewPassphrase() {
    var values: [String: String] = [:]
    let status = saveGPGSigningCredential(
        privateKey: "private",
        passphrase: "new-passphrase",
        alternate: false,
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        save: { account, value in
            if account == gpgDefaultPrivateKeySecretName { return errSecAuthFailed }
            values[account] = value
            return errSecSuccess
        },
        delete: { account in
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecAuthFailed)
    #expect(values[gpgDefaultPassphraseSecretName] == nil)
    #expect(values[gpgDefaultPrivateKeySecretName] == nil)
}

@Test func failedPrivateKeyReplacementRestoresThePreviousPassphrase() {
    var values = [gpgDefaultPassphraseSecretName: "old-passphrase"]
    let status = saveGPGSigningCredential(
        privateKey: "replacement",
        passphrase: "new-passphrase",
        alternate: false,
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        save: { account, value in
            if account == gpgDefaultPrivateKeySecretName { return errSecAuthFailed }
            values[account] = value
            return errSecSuccess
        },
        delete: { account in
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecAuthFailed)
    #expect(values[gpgDefaultPassphraseSecretName] == "old-passphrase")
}

@Test func failedPrivateKeyReplacementDoesNotRemoveThePreviousPassphrase() {
    var values = [gpgDefaultPassphraseSecretName: "old-passphrase"]
    var deleted = false
    let status = saveGPGSigningCredential(
        privateKey: "replacement",
        passphrase: "",
        alternate: false,
        load: { values[$0].map(GPGStoredValueLoad.value) ?? .missing },
        save: { account, value in
            if account == gpgDefaultPrivateKeySecretName { return errSecAuthFailed }
            values[account] = value
            return errSecSuccess
        },
        delete: { account in
            deleted = true
            values.removeValue(forKey: account)
            return errSecSuccess
        }
    )

    #expect(status == errSecAuthFailed)
    #expect(!deleted)
    #expect(values[gpgDefaultPassphraseSecretName] == "old-passphrase")
}
