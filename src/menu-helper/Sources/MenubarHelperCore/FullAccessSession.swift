import Foundation

public let fullAccessSessionMaximumDuration: TimeInterval = 60 * 60

public struct FullAccessSessionSnapshot: Equatable, Sendable {
    public let expiresAt: Date
    private let expiresAtUptime: TimeInterval

    public init(expiresAt: Date, expiresAtUptime: TimeInterval) {
        self.expiresAt = expiresAt
        self.expiresAtUptime = expiresAtUptime
    }

    public func isActive(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) -> Bool {
        expiresAt > date && expiresAtUptime > uptime
    }

    public func remaining(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) -> TimeInterval {
        max(0, min(
            expiresAt.timeIntervalSince(date),
            expiresAtUptime - uptime
        ))
    }
}

public struct FullAccessSessionLease: Equatable, Sendable {
    fileprivate let id: UUID
    public let snapshot: FullAccessSessionSnapshot
}

public final class FullAccessSessionController: @unchecked Sendable {
    private struct State {
        let id: UUID
        let snapshot: FullAccessSessionSnapshot
    }

    private let lock = NSLock()
    private var state: State?

    public init() {}

    @discardableResult
    public func start(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime,
        duration: TimeInterval = fullAccessSessionMaximumDuration
    ) -> Bool {
        guard uptime.isFinite, duration.isFinite, duration > 0 else { return false }
        let boundedDuration = min(duration, fullAccessSessionMaximumDuration)
        let expiresAtUptime = uptime + boundedDuration
        guard expiresAtUptime.isFinite else { return false }
        let newState = State(
            id: UUID(),
            snapshot: FullAccessSessionSnapshot(
                expiresAt: date.addingTimeInterval(boundedDuration),
                expiresAtUptime: expiresAtUptime
            )
        )
        lock.withLock { state = newState }
        return true
    }

    public func end() {
        lock.withLock { state = nil }
    }

    public func snapshot(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) -> FullAccessSessionSnapshot? {
        lease(at: date, uptime: uptime)?.snapshot
    }

    public func lease(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) -> FullAccessSessionLease? {
        lock.withLock {
            guard let state = activeState(at: date, uptime: uptime) else { return nil }
            return FullAccessSessionLease(
                id: state.id,
                snapshot: state.snapshot
            )
        }
    }

    public func withActiveLease<Result>(
        _ lease: FullAccessSessionLease,
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime,
        _ release: () throws -> Result
    ) rethrows -> Result? {
        try lock.withLock {
            guard activeState(at: date, uptime: uptime)?.id == lease.id else { return nil }
            return try release()
        }
    }

    public func isActive(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) -> Bool {
        snapshot(at: date, uptime: uptime) != nil
    }

    private func activeState(at date: Date, uptime: TimeInterval) -> State? {
        guard let state,
              state.snapshot.isActive(at: date, uptime: uptime)
        else {
            self.state = nil
            return nil
        }
        return state
    }
}

public func fullAccessSessionProtection(
    for gate: SecretGate,
    classification: SecretGateRequestClassification,
    launcherEligible: Bool,
    sessionActive: Bool
) -> SecretGateProtection? {
    guard launcherEligible, sessionActive else { return nil }
    let protection = gate.normalizedProtection(.fullIncludingSecretDumps)
    return protection.allows(classification) ? protection : nil
}
