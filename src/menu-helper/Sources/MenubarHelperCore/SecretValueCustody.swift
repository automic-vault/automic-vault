import Foundation
import Security

public enum SecretValueCustodyError: Error, Equatable, LocalizedError, Sendable {
    case repairFailed(OSStatus)
    case inventoryUnavailable(OSStatus)
    case secretMissing(String)
    case selectedValueMissing(String)
    case selectedValueUnavailable(String, OSStatus)
    case selectedValueInvalidUTF8(String)
    case selectedValueEmpty(String)

    public var errorDescription: String? {
        switch self {
        case .repairFailed(let status):
            "secret repair must complete before this request: \(status)"
        case .inventoryUnavailable(let status):
            "failed to inspect stored Secrets: \(status)"
        case .secretMissing(let name):
            "failed to load secret \(name): \(errSecItemNotFound)"
        case .selectedValueMissing(let name):
            "selected value for \(name) no longer exists"
        case .selectedValueUnavailable(let name, let status):
            "failed to load selected value for \(name): \(status)"
        case .selectedValueInvalidUTF8(let name):
            "selected value for \(name) is not valid UTF-8"
        case .selectedValueEmpty(let name):
            "selected value for \(name) is empty"
        }
    }
}

public struct SelectedSecretValues: Equatable, Sendable {
    private let values: [String: StoredSecretValue]

    package init(values: [String: StoredSecretValue]) {
        self.values = values
    }

    public var isEmpty: Bool { values.isEmpty }
    public var names: Set<String> { Set(values.keys) }
    public var sourceDisplayNames: [String: String] {
        values.mapValues { $0.source.displayName }
    }

    public func selecting(names: [String]) -> SelectedSecretValues {
        let requested = Set(names)
        return SelectedSecretValues(values: values.filter { requested.contains($0.key) })
    }

    public func contains(_ name: String) -> Bool {
        values[name] != nil
    }

    public func source(for name: String) -> StoredSecretValueSource? {
        values[name]?.source
    }

    func authorizationIdentity() -> [SelectedSecretValueSourceIdentity] {
        values.map {
            SelectedSecretValueSourceIdentity(name: $0.key, source: $0.value.source)
        }.sorted { lhs, rhs in
            if lhs.name != rhs.name { return lhs.name < rhs.name }
            return String(describing: lhs.source) < String(describing: rhs.source)
        }
    }

    func value(for name: String) -> StoredSecretValue? {
        values[name]
    }
}

struct SelectedSecretValueSourceIdentity: Hashable, Sendable {
    let name: String
    let source: StoredSecretValueSource
}

protocol SecretValueCustodyAdapter: Sendable {
    func repairPendingMutation() -> OSStatus
    func pendingMutationNames() -> Set<String>?
    func inventory() -> StoredSecretsLoad
    func load(_ value: StoredSecretValue) -> StoredSecretValueLoad
}

private struct KeychainSecretValueCustodyAdapter: SecretValueCustodyAdapter {
    func repairPendingMutation() -> OSStatus {
        resumePendingSecretMutation()
    }

    func pendingMutationNames() -> Set<String>? {
        MenubarHelperCore.pendingSecretMutationNames()
    }

    func inventory() -> StoredSecretsLoad {
        loadStoredSecretsForUseResult()
    }

    func load(_ value: StoredSecretValue) -> StoredSecretValueLoad {
        loadStoredSecretValue(value)
    }
}

public struct SecretValueCustody: Sendable {
    private let adapter: any SecretValueCustodyAdapter

    public init() {
        adapter = KeychainSecretValueCustodyAdapter()
    }

    init(adapter: any SecretValueCustodyAdapter) {
        self.adapter = adapter
    }

    public func bind(names: [String], cwd: String) throws -> SelectedSecretValues {
        guard !names.isEmpty else { return SelectedSecretValues(values: [:]) }
        let repairStatus = adapter.repairPendingMutation()
        if repairStatus != errSecSuccess {
            let pendingNames = adapter.pendingMutationNames()
            if pendingNames.map({ !Set(names).isDisjoint(with: $0) }) ?? true {
                throw SecretValueCustodyError.repairFailed(repairStatus)
            }
        }
        let secrets: [StoredSecret]
        switch adapter.inventory() {
        case .success(let inventory):
            secrets = inventory
        case .failure(let status):
            throw SecretValueCustodyError.inventoryUnavailable(status)
        }
        return SelectedSecretValues(
            values: try resolveStoredSecretValues(names: names, cwd: cwd, secrets: secrets)
        )
    }

    public func load(
        _ selected: SelectedSecretValues,
        names: [String],
        allowMissing: Bool = false
    ) throws -> [String: String] {
        var loaded: [String: String] = [:]
        for name in names {
            guard let value = selected.value(for: name) else {
                if allowMissing { continue }
                throw SecretValueCustodyError.secretMissing(name)
            }
            switch adapter.load(value) {
            case .success(let secret):
                guard !secret.isEmpty else {
                    throw SecretValueCustodyError.selectedValueEmpty(name)
                }
                loaded[name] = secret
            case .notFound:
                throw SecretValueCustodyError.selectedValueMissing(name)
            case .failure(let status):
                throw SecretValueCustodyError.selectedValueUnavailable(name, status)
            case .invalidUTF8:
                throw SecretValueCustodyError.selectedValueInvalidUTF8(name)
            }
        }
        return loaded
    }
}
