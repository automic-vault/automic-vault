import Foundation
import Security
import Testing
@testable import MenubarHelperCore

private func syncFixture(_ enabled: Bool, project: Bool = false) -> StoredSecretValue {
    let source: StoredSecretValueSource = project ? .projectDirectory("/missing/project") : .global
    return StoredSecretValue(source: source,
        keychainAccount: storedSecretKeychainAccount(secretName: "TOKEN", source: source),
        accessibility: .whenUnlocked, keychainProperties: [], synchronizable: enabled)
}

@Test func secretSynchronizationDefaultsOffAndRejectsMixedCustody() throws {
    let local = syncFixture(false)
    let mixed = StoredSecret(account: "TOKEN", values: [local, syncFixture(true, project: true)])
    #expect(!StoredSecret(account: "NEW").synchronizable)
    #expect(!mixed.hasConsistentSynchronization)
    #expect(throws: StoredSecretSelectionError.inconsistentSynchronization("TOKEN")) {
        try resolveStoredSecretValues(names: ["TOKEN"], cwd: "", secrets: [mixed], globalOnly: true)
    }
    let synchronized = StoredSecret(account: "TOKEN", values: [syncFixture(true), syncFixture(true, project: true)])
    let selected = try resolveStoredSecretValues(names: ["TOKEN"], cwd: "", secrets: [synchronized], globalOnly: true)
    #expect(selected["TOKEN"] == syncFixture(true))
}

@Test func secretSynchronizationRecordsBeforeWritingOnlyReviewedAccounts() {
    let secret = StoredSecret(account: "TOKEN", values: [syncFixture(false), syncFixture(false, project: true)])
    var steps: [String] = []
    let status = commitSecretSynchronization(true, expected: secret,
        load: { .success([secret]) },
        record: { steps.append("record"); return true },
        write: { accounts in
            #expect(accounts == secret.values.map(\.keychainAccount))
            steps.append("write")
            return errSecSuccess
        })
    #expect(status == errSecSuccess)
    #expect(steps == ["record", "write"])
}

@Test func secretSynchronizationRejectsChangedInventoryAndRecordingFailure() {
    let secret = StoredSecret(account: "TOKEN", values: [syncFixture(false)])
    let changed = StoredSecret(account: "TOKEN", values: [syncFixture(false), syncFixture(false, project: true)])
    for inventory: StoredSecretsLoad in [.failure(errSecInteractionNotAllowed), .success([]), .success([changed])] {
        let status = commitSecretSynchronization(true, expected: secret, load: { inventory },
            record: { Issue.record("Changed inventory must not reach recording"); return true },
            write: { _ in Issue.record("Changed inventory must not reach mutation"); return errSecSuccess })
        #expect(status != errSecSuccess)
    }
    let status = commitSecretSynchronization(true, expected: secret, load: { .success([secret]) },
        record: { false }, write: { _ in Issue.record("Recording failure must deny mutation"); return errSecSuccess })
    #expect(status == errSecIO)
}

@Test func secretSynchronizationNoOpAndExplicitMixedStateRepair() {
    let secret = StoredSecret(account: "TOKEN", values: [syncFixture(true)])
    #expect(commitSecretSynchronization(true, expected: secret, load: { .success([secret]) },
        record: { Issue.record("No-op must not record"); return false },
        write: { _ in Issue.record("No-op must not write"); return errSecIO }) == errSecSuccess)
    let mixed = StoredSecret(account: "TOKEN", values: [syncFixture(true), syncFixture(false, project: true)])
    var recorded = false
    let result = commitSecretSynchronization(false, expected: mixed, load: { .success([mixed]) },
        record: { recorded = true; return true }, write: { _ in
            #expect(recorded)
            return errSecNotAvailable
        })
    #expect(result == errSecNotAvailable)
}

@Test(.enabled(if: dataProtectionKeychainAvailable(), "requires an entitled Keychain test host"))
func secretSynchronizationKeychainLifecycle() throws {
    let service = "com.automicvault.tests.sync.\(UUID().uuidString)"
    defer {
        _ = deleteStoredSecret(account: "TOKEN", service: service)
        _ = deleteStoredSecret(account: "RENAMED", service: service)
    }
    #expect(saveStoredSecret(account: "TOKEN", value: "synthetic-test-value", service: service) == errSecSuccess)
    let original = try #require(loadStoredSecrets(service: service).first)
    #expect(!original.synchronizable)
    #expect(setStoredSecretSynchronization(true, expected: original, service: service, record: { true }) == errSecSuccess)
    #expect(storedSecretExists(account: "TOKEN", service: service))
    #expect(saveStoredSecretIfAbsentOrEqual(account: "TOKEN", value: "synthetic-test-value", service: service) == errSecSuccess)
    #expect(saveStoredSecret(account: "TOKEN", value: "synthetic-project-value", source: .projectDirectory("/missing/project"), service: service) == errSecSuccess)
    var synced = try #require(loadStoredSecrets(service: service).first)
    #expect(synced.values.count == 2)
    #expect(synced.values.allSatisfy { $0.synchronizable })
    #expect(loadStoredSecretValue(synced.values[0], service: service) == .success("synthetic-test-value"))
    #expect(setStoredSecretAccessibility(account: "TOKEN", accessibility: .afterFirstUnlock, service: service) == errSecSuccess)
    #expect(renameStoredSecret(account: "TOKEN", to: "RENAMED", service: service) == errSecSuccess)
    synced = try #require(loadStoredSecrets(service: service).first)
    #expect(synced.account == "RENAMED")
    #expect(synced.values.allSatisfy { $0.synchronizable && $0.accessibility == .afterFirstUnlock })
    #expect(setStoredSecretSynchronization(false, expected: synced, service: service, record: { true }) == errSecSuccess)
    #expect(loadStoredSecrets(service: service).first?.values.allSatisfy { !$0.synchronizable } == true)
}

@Test func secretSynchronizationRepairRetriesOnlyReviewedUnfinishedValues() {
    var values = [syncFixture(false), syncFixture(false, project: true)]
    let accounts = values.map(\.keychainAccount)
    var attempts = 0
    let load = { StoredSecretsLoad.success([StoredSecret(account: "TOKEN", values: values)]) }
    let first = resumeSecretSynchronization(account: "TOKEN", accounts: accounts, enabled: true,
        load: load, update: { value in
            attempts += 1
            if value.source != .global { return errSecInteractionNotAllowed }
            values[0] = syncFixture(true)
            return errSecSuccess
        })
    #expect(first == errSecInteractionNotAllowed)
    #expect(attempts == 2)
    var resumed: [String] = []
    let second = resumeSecretSynchronization(account: "TOKEN", accounts: accounts, enabled: true,
        load: load, update: { value in
            resumed.append(value.keychainAccount)
            values[1] = syncFixture(true, project: true)
            return errSecSuccess
        })
    #expect(second == errSecSuccess)
    #expect(resumed == [accounts[1]])
    // A newly arrived source is outside a journal that reviewed only the Global Value.
    values[1] = syncFixture(false, project: true)
    #expect(resumeSecretSynchronization(account: "TOKEN", accounts: [accounts[0]], enabled: true,
        load: load, update: { _ in Issue.record("Must not enroll an unreviewed source"); return errSecSuccess }) == errSecSuccess)
}

@Test func secretSynchronizationRepairRequiresReadbackAndDoesNotResurrectDeletedValues() {
    let original = StoredSecret(account: "TOKEN", values: [syncFixture(false)])
    let accounts = original.values.map(\.keychainAccount)
    #expect(resumeSecretSynchronization(account: "TOKEN", accounts: accounts, enabled: true,
        load: { .success([original]) }, update: { _ in errSecSuccess }) == errSecDecode)
    #expect(resumeSecretSynchronization(account: "TOKEN", accounts: accounts, enabled: true,
        load: { .failure(errSecInteractionNotAllowed) },
        update: { _ in Issue.record("Must not mutate unavailable inventory"); return errSecSuccess }) == errSecInteractionNotAllowed)
    #expect(resumeSecretSynchronization(account: "TOKEN", accounts: accounts, enabled: true,
        load: { .success([]) },
        update: { _ in Issue.record("Must not recreate deleted Values"); return errSecSuccess }) == errSecSuccess)
}

@Test(.enabled(if: dataProtectionKeychainAvailable(), "requires an entitled Keychain test host"))
func secretSynchronizationDuplicateSourcesFailClosed() throws {
    let service = "com.automicvault.tests.sync-conflict.\(UUID().uuidString)"
    defer { _ = deleteStoredSecretValue(secretName: "TOKEN", source: .global, service: service) }
    #expect(saveStoredSecret(account: "TOKEN", value: "synthetic-local", service: service) == errSecSuccess)
    #expect(saveKeychainData(Data("synthetic-synced".utf8), service: service,
        account: "TOKEN", synchronizable: true) == errSecSuccess)
    guard case .failure(let status) = loadStoredSecretsResult(service: service) else {
        Issue.record("Duplicate sources must fail inventory")
        return
    }
    #expect(status == errSecDecode)
    #expect(loadStoredSecret(account: "TOKEN", service: service) == nil)
    #expect(saveStoredSecret(account: "TOKEN", value: "replacement", service: service) == errSecDecode)
}

@Test func availabilityRepairCompletesAfterRemoteDeletionButRetainsInventoryFailures() {
    let secret = StoredSecret(account: "TOKEN", values: [syncFixture(true), syncFixture(true, project: true)])
    var inventory: StoredSecretsLoad = .success([secret])
    var writes = 0
    let interrupted = resumeSecretAccessibility(account: "TOKEN", accessibility: .afterFirstUnlock,
        load: { inventory }, update: { _ in
            writes += 1
            return writes == 1 ? errSecSuccess : errSecInteractionNotAllowed
        })
    #expect(interrupted == errSecInteractionNotAllowed)
    #expect(writes == 2)
    inventory = .success([])
    let repaired = resumeSecretAccessibility(account: "TOKEN", accessibility: .afterFirstUnlock,
        load: { inventory }, update: { _ in
            Issue.record("Repair must not recreate a deleted Secret")
            return errSecSuccess
        })
    #expect(repaired == errSecSuccess)
    inventory = .failure(errSecInteractionNotAllowed)
    let unavailable = resumeSecretAccessibility(account: "TOKEN", accessibility: .afterFirstUnlock,
        load: { inventory }, update: { _ in
            Issue.record("Unavailable inventory must not be treated as an absent Secret")
            return errSecSuccess
        })
    #expect(unavailable == errSecInteractionNotAllowed)
}
