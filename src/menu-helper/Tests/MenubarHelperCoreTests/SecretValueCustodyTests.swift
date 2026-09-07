import Foundation
import Security
import Testing
@testable import MenubarHelperCore

private struct InMemorySecretValueCustodyAdapter: SecretValueCustodyAdapter {
    let repairStatus: OSStatus
    let pendingNames: Set<String>?
    let inventoryResult: StoredSecretsLoad
    let loadedValues: [String: StoredSecretValueLoad]

    init(
        repairStatus: OSStatus = errSecSuccess,
        pendingNames: Set<String>? = [],
        secrets: [StoredSecret],
        loadedValues: [String: StoredSecretValueLoad]
    ) {
        self.repairStatus = repairStatus
        self.pendingNames = pendingNames
        self.inventoryResult = .success(secrets)
        self.loadedValues = loadedValues
    }

    init(inventoryFailure: OSStatus) {
        repairStatus = errSecSuccess
        pendingNames = []
        inventoryResult = .failure(inventoryFailure)
        loadedValues = [:]
    }

    func repairPendingMutation() -> OSStatus { repairStatus }
    func pendingMutationNames() -> Set<String>? { pendingNames }
    func inventory() -> StoredSecretsLoad { inventoryResult }
    func load(_ value: StoredSecretValue) -> StoredSecretValueLoad {
        loadedValues[value.keychainAccount] ?? .notFound
    }
}

@Test func secretValueCustodyBindsAndLoadsTheNearestProjectValue() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-custody-\(UUID().uuidString)", isDirectory: true)
    let project = root.appendingPathComponent("project", isDirectory: true)
    let workingDirectory = project.appendingPathComponent("Sources", isDirectory: true)
    try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let projectPath = try canonicalProjectDirectory(project.path)
    let cwd = try canonicalProjectDirectory(workingDirectory.path)
    let global = storedValue(source: .global, account: "global")
    let projectValue = storedValue(source: .projectDirectory(projectPath), account: "project")
    let adapter = InMemorySecretValueCustodyAdapter(
        secrets: [StoredSecret(account: "API_TOKEN", values: [global, projectValue])],
        loadedValues: ["global": .success("global-secret"), "project": .success("project-secret")]
    )
    let custody = SecretValueCustody(adapter: adapter)

    let selected = try custody.bind(names: ["API_TOKEN"], cwd: cwd)

    #expect(selected.source(for: "API_TOKEN") == .projectDirectory(projectPath))
    #expect(selected.sourceDisplayNames == ["API_TOKEN": projectPath])
    #expect(try custody.load(selected, names: ["API_TOKEN"]) == ["API_TOKEN": "project-secret"])
}

@Test func secretValueCustodyNeverFallsBackAfterBinding() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let global = storedValue(source: .global, account: "global")
    let project = storedValue(source: .projectDirectory(cwd), account: "project")
    let adapter = InMemorySecretValueCustodyAdapter(
        secrets: [StoredSecret(account: "API_TOKEN", values: [global, project])],
        loadedValues: ["global": .success("global-secret"), "project": .notFound]
    )
    let custody = SecretValueCustody(adapter: adapter)
    let selected = try custody.bind(names: ["API_TOKEN"], cwd: cwd)

    #expect(throws: SecretValueCustodyError.selectedValueMissing("API_TOKEN")) {
        try custody.load(selected, names: ["API_TOKEN"])
    }
}

@Test func secretValueCustodyRejectsEmptySelectedValue() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let global = storedValue(source: .global, account: "global")
    let adapter = InMemorySecretValueCustodyAdapter(
        secrets: [StoredSecret(account: "API_TOKEN", values: [global])],
        loadedValues: ["global": .success("")]
    )
    let custody = SecretValueCustody(adapter: adapter)
    let selected = try custody.bind(names: ["API_TOKEN"], cwd: cwd)

    #expect(throws: SecretValueCustodyError.selectedValueEmpty("API_TOKEN")) {
        try custody.load(selected, names: ["API_TOKEN"])
    }
}

@Test func secretValueCustodyFailsClosedBeforeBindingWhenRepairFails() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let adapter = InMemorySecretValueCustodyAdapter(
        repairStatus: errSecDecode,
        pendingNames: ["API_TOKEN"],
        secrets: [],
        loadedValues: [:]
    )

    #expect(throws: SecretValueCustodyError.repairFailed(errSecDecode)) {
        try SecretValueCustody(adapter: adapter).bind(names: ["API_TOKEN"], cwd: cwd)
    }
}

@Test func secretValueCustodyAllowsUnaffectedSecretsWhileRepairIsPending() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let global = storedValue(source: .global, account: "other")
    let adapter = InMemorySecretValueCustodyAdapter(
        repairStatus: errSecDecode,
        pendingNames: ["BROKEN_TOKEN"],
        secrets: [StoredSecret(account: "API_TOKEN", values: [global])],
        loadedValues: ["other": .success("secret")]
    )
    let custody = SecretValueCustody(adapter: adapter)

    let selected = try custody.bind(names: ["API_TOKEN"], cwd: cwd)

    #expect(try custody.load(selected, names: ["API_TOKEN"]) == ["API_TOKEN": "secret"])
}

@Test func secretValueCustodyFailsClosedWhenInventoryIsUnavailable() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)

    #expect(throws: SecretValueCustodyError.inventoryUnavailable(errSecNotAvailable)) {
        try SecretValueCustody(
            adapter: InMemorySecretValueCustodyAdapter(inventoryFailure: errSecNotAvailable)
        ).bind(names: ["API_TOKEN"], cwd: cwd)
    }
}

@Test func lockedSecretUseRetriesWithAvailableWhileLockedInventory() {
    var requestedAccessibility: [StoredSecretAccessibility?] = []

    let result = retryLockedSecretInventory { accessibility in
        requestedAccessibility.append(accessibility)
        return accessibility == nil
            ? .failure(errSecInteractionNotAllowed)
            : .success([StoredSecret(account: "AVAILABLE")])
    }

    #expect(requestedAccessibility == [nil, .afterFirstUnlock])
    guard case .success(let secrets) = result else {
        Issue.record("available locked inventory was not returned")
        return
    }
    #expect(secrets.map(\.account) == ["AVAILABLE"])

    requestedAccessibility.removeAll()
    let unrelatedFailure = retryLockedSecretInventory { accessibility in
        requestedAccessibility.append(accessibility)
        return .failure(errSecAuthFailed)
    }
    #expect(requestedAccessibility == [nil])
    guard case .failure(errSecAuthFailed) = unrelatedFailure else {
        Issue.record("an unrelated inventory failure was retried")
        return
    }
}

private func storedValue(source: StoredSecretValueSource, account: String) -> StoredSecretValue {
    StoredSecretValue(
        source: source,
        keychainAccount: account,
        accessibility: .whenUnlocked,
        keychainProperties: []
    )
}
