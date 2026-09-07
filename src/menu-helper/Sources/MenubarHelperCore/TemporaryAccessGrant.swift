import Foundation

public enum AgentProvider: String, Hashable, Sendable {
    case codex
    case claudeCode

    public var environmentVariable: String {
        switch self {
        case .codex: "CODEX_THREAD_ID"
        case .claudeCode: "CLAUDE_CODE_SESSION_ID"
        }
    }

    public var taskLabel: String {
        switch self {
        case .codex: "Codex task"
        case .claudeCode: "Claude session"
        }
    }
}

public struct AgentTaskContext: Hashable, Sendable {
    public let provider: AgentProvider
    public let id: UUID

    public init(provider: AgentProvider, id: UUID) {
        self.provider = provider
        self.id = id
    }

    public init?(environment: [String: String]) {
        let present = AgentProvider.allCases.compactMap { provider in
            environment[provider.environmentVariable].map { (provider, $0) }
        }
        guard present.count == 1,
              let id = UUID(uuidString: present[0].1),
              id.uuidString.caseInsensitiveCompare(present[0].1) == .orderedSame
        else { return nil }
        self = Self(provider: present[0].0, id: id)
    }

    public var abbreviatedID: String { String(id.uuidString.prefix(8)) }
}

extension AgentProvider: CaseIterable {}

public struct TemporaryAccessGrantScope: Hashable, Sendable {
    public let authorizationGateID: String
    public let launcherDesignatedRequirement: String
    public let launcherRuntimeRequirement: LauncherRuntimeRequirement
    public let agentTaskContext: AgentTaskContext
    public let protection: SecretGateProtection

    public init(
        authorizationGateID: String,
        launcherDesignatedRequirement: String,
        launcherRuntimeRequirement: LauncherRuntimeRequirement,
        agentTaskContext: AgentTaskContext
    ) {
        self.authorizationGateID = authorizationGateID
        self.launcherDesignatedRequirement = launcherDesignatedRequirement
        self.launcherRuntimeRequirement = launcherRuntimeRequirement
        self.agentTaskContext = agentTaskContext
        self.protection = SecretGateProtection.fullExceptSecretDumps.normalized(
            forGateID: authorizationGateID
        )
    }

    public func matches(
        authorizationGateID: String,
        launcherDesignatedRequirement: String,
        launcherRuntimeProtection: LauncherRuntimeProtection,
        agentTaskContext: AgentTaskContext,
        classification: SecretGateRequestClassification
    ) -> Bool {
        self.authorizationGateID == authorizationGateID
            && self.launcherDesignatedRequirement == launcherDesignatedRequirement
            && self.agentTaskContext == agentTaskContext
            && launcherRuntimeProtection.secretGateAdmissionRequirement
                == launcherRuntimeRequirement
            && protection == .fullExceptSecretDumps
            && protection.allows(classification)
    }
}

public func operationClassificationTitle(
    _ classification: SecretGateRequestClassification
) -> String {
    switch classification {
    case .readOnly: "Read Only"
    case .localWrite: "Local Write"
    case .update: "Homebrew Update"
    case .mutating: "Local Write, System Write, Remote Write, or a combination"
    case .secretDump: "Elevated Secret Application or Secret Disclosure"
    case .unknown: "Unknown"
    }
}

public func temporaryAccessGrantUnavailableReason(
    hasToolSpecificGate: Bool,
    classification: SecretGateRequestClassification?,
    launcherRuntimeProtection: LauncherRuntimeProtection?,
    agentTaskContext: AgentTaskContext?
) -> String? {
    guard hasToolSpecificGate else {
        return "10-minute Write Access is unavailable at the Direct Secret Gate."
    }
    guard let classification else {
        return "10-minute Write Access is unavailable because this operation could not be classified."
    }
    switch classification {
    case .readOnly:
        return "10-minute Write Access is available only for recognized write operations."
    case .secretDump:
        return "10-minute Write Access excludes Elevated Secret Application and Secret Disclosure."
    case .unknown:
        return "10-minute Write Access excludes Unknown operations."
    case .localWrite, .update, .mutating:
        break
    }
    guard launcherRuntimeProtection?.secretGateAdmissionRequirement != nil else {
        return "10-minute Write Access requires an eligible Verified Launcher and runtime posture."
    }
    guard agentTaskContext != nil else {
        return "10-minute Write Access requires a recognized Codex task or Claude Code session."
    }
    return nil
}

public struct TemporaryAccessGrantSnapshot: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let generation: UUID
    public let scope: TemporaryAccessGrantScope
    public let launcherName: String
    public let authorizationGateName: String
    public let grantedAt: Date
    public let expiresAt: Date
    public let monotonicDeadline: TimeInterval
    public let useCount: Int
    public let lastUsedAt: Date
    public let suspendedRemaining: TimeInterval?

    public var isCountdownSuspended: Bool { suspendedRemaining != nil }

    public func remaining(wallNow: Date, monotonicNow: TimeInterval) -> TimeInterval {
        suspendedRemaining
            ?? max(0, min(expiresAt.timeIntervalSince(wallNow), monotonicDeadline - monotonicNow))
    }
}

public final class TemporaryAccessGrantController: @unchecked Sendable {
    public static let duration: TimeInterval = 10 * 60

    private struct Grant {
        let id: UUID
        let generation: UUID
        let scope: TemporaryAccessGrantScope
        let launcherName: String
        let authorizationGateName: String
        let grantedAt: Date
        var expiresAt: Date
        var monotonicDeadline: TimeInterval
        var useCount: Int
        var lastUsedAt: Date
        var suspendedRemaining: TimeInterval?

        var snapshot: TemporaryAccessGrantSnapshot {
            TemporaryAccessGrantSnapshot(
                id: id,
                generation: generation,
                scope: scope,
                launcherName: launcherName,
                authorizationGateName: authorizationGateName,
                grantedAt: grantedAt,
                expiresAt: expiresAt,
                monotonicDeadline: monotonicDeadline,
                useCount: useCount,
                lastUsedAt: lastUsedAt,
                suspendedRemaining: suspendedRemaining
            )
        }

        func remaining(wallNow: Date, monotonicNow: TimeInterval) -> TimeInterval {
            suspendedRemaining
                ?? max(0, min(expiresAt.timeIntervalSince(wallNow), monotonicDeadline - monotonicNow))
        }

        func isExpired(wallNow: Date, monotonicNow: TimeInterval) -> Bool {
            suspendedRemaining == nil
                && (wallNow >= expiresAt || monotonicNow >= monotonicDeadline)
        }

        func canAuthorize(wallNow: Date, monotonicNow: TimeInterval) -> Bool {
            suspendedRemaining == nil && !isExpired(wallNow: wallNow, monotonicNow: monotonicNow)
        }
    }

    private let lock = NSLock()
    private var grants: [UUID: Grant] = [:]

    public init() {}

    @discardableResult
    public func start(
        scope: TemporaryAccessGrantScope,
        launcherName: String,
        authorizationGateName: String,
        wallNow: Date? = nil,
        monotonicNow: TimeInterval? = nil
    ) -> TemporaryAccessGrantSnapshot {
        startWithLease(
            scope: scope,
            launcherName: launcherName,
            authorizationGateName: authorizationGateName,
            wallNow: wallNow,
            monotonicNow: monotonicNow
        ) { _ in }.0
    }

    @discardableResult
    public func startWithLease<Result>(
        scope: TemporaryAccessGrantScope,
        launcherName: String,
        authorizationGateName: String,
        wallNow: Date? = nil,
        monotonicNow: TimeInterval? = nil,
        _ body: (TemporaryAccessGrantSnapshot) throws -> Result
    ) rethrows -> (TemporaryAccessGrantSnapshot, Result) {
        lock.lock()
        defer { lock.unlock() }
        let wallNow = wallNow ?? Date()
        let monotonicNow = monotonicNow ?? ProcessInfo.processInfo.systemUptime
        removeExpired(wallNow: wallNow, monotonicNow: monotonicNow)
        let id = grants.values.first(where: { $0.scope == scope })?.id ?? UUID()
        let grant = Grant(
            id: id,
            generation: UUID(),
            scope: scope,
            launcherName: launcherName,
            authorizationGateName: authorizationGateName,
            grantedAt: wallNow,
            expiresAt: wallNow.addingTimeInterval(Self.duration),
            monotonicDeadline: monotonicNow + Self.duration,
            useCount: 1,
            lastUsedAt: wallNow,
            suspendedRemaining: nil
        )
        grants[id] = grant
        return try (grant.snapshot, body(grant.snapshot))
    }

    public func snapshots(
        wallNow: Date? = nil,
        monotonicNow: TimeInterval? = nil
    ) -> [TemporaryAccessGrantSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        let wallNow = wallNow ?? Date()
        let monotonicNow = monotonicNow ?? ProcessInfo.processInfo.systemUptime
        removeExpired(wallNow: wallNow, monotonicNow: monotonicNow)
        return grants.values.map(\.snapshot).sorted {
            let left = $0.remaining(wallNow: wallNow, monotonicNow: monotonicNow)
            let right = $1.remaining(wallNow: wallNow, monotonicNow: monotonicNow)
            return left == right ? $0.id.uuidString < $1.id.uuidString : left < right
        }
    }

    @discardableResult
    public func cancel(id: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return grants.removeValue(forKey: id) != nil
    }

    public func cancelAll() {
        lock.lock()
        defer { lock.unlock() }
        grants.removeAll()
    }

    @discardableResult
    public func setCountdownSuspended(
        id: UUID,
        suspended: Bool,
        wallNow: Date? = nil,
        monotonicNow: TimeInterval? = nil
    ) -> TemporaryAccessGrantSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        let wallNow = wallNow ?? Date()
        let monotonicNow = monotonicNow ?? ProcessInfo.processInfo.systemUptime
        removeExpired(wallNow: wallNow, monotonicNow: monotonicNow)
        guard var grant = grants[id] else { return nil }
        let wasSuspended = grant.suspendedRemaining != nil
        guard wasSuspended != suspended else { return grant.snapshot }
        if suspended {
            grant.suspendedRemaining = grant.remaining(
                wallNow: wallNow,
                monotonicNow: monotonicNow
            )
        } else if let remaining = grant.suspendedRemaining {
            grant.expiresAt = wallNow.addingTimeInterval(remaining)
            grant.monotonicDeadline = monotonicNow + remaining
            grant.suspendedRemaining = nil
        }
        grants[id] = grant
        return grant.snapshot
    }

    @discardableResult
    public func addTenMinutes(
        id: UUID,
        wallNow: Date? = nil,
        monotonicNow: TimeInterval? = nil
    ) -> TemporaryAccessGrantSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        let wallNow = wallNow ?? Date()
        let monotonicNow = monotonicNow ?? ProcessInfo.processInfo.systemUptime
        removeExpired(wallNow: wallNow, monotonicNow: monotonicNow)
        guard var grant = grants[id] else { return nil }
        if let remaining = grant.suspendedRemaining {
            grant.suspendedRemaining = remaining + Self.duration
        } else {
            grant.expiresAt.addTimeInterval(Self.duration)
            grant.monotonicDeadline += Self.duration
        }
        grants[id] = grant
        return grant.snapshot
    }

    public func withActiveLease(
        authorizationGateID: String,
        launcherDesignatedRequirement: String,
        launcherRuntimeProtection: LauncherRuntimeProtection,
        agentTaskContext: AgentTaskContext,
        classification: SecretGateRequestClassification,
        wallNow: Date? = nil,
        monotonicNow: TimeInterval? = nil,
        _ didUse: (TemporaryAccessGrantSnapshot) throws -> Bool
    ) rethrows -> Bool? {
        lock.lock()
        defer { lock.unlock() }
        let wallNow = wallNow ?? Date()
        let monotonicNow = monotonicNow ?? ProcessInfo.processInfo.systemUptime
        removeExpired(wallNow: wallNow, monotonicNow: monotonicNow)
        guard var grant = grants.values.first(where: {
            $0.scope.matches(
                authorizationGateID: authorizationGateID,
                launcherDesignatedRequirement: launcherDesignatedRequirement,
                launcherRuntimeProtection: launcherRuntimeProtection,
                agentTaskContext: agentTaskContext,
                classification: classification
            )
                && $0.canAuthorize(wallNow: wallNow, monotonicNow: monotonicNow)
        }) else { return nil }
        if try didUse(grant.snapshot) {
            grant.useCount += 1
            grant.lastUsedAt = wallNow
            grants[grant.id] = grant
        }
        return true
    }

    private func removeExpired(wallNow: Date, monotonicNow: TimeInterval) {
        grants = grants.filter { !$0.value.isExpired(wallNow: wallNow, monotonicNow: monotonicNow) }
    }
}
