import Foundation

public let fullAccessSessionMaximumDuration: TimeInterval = 60 * 60

public struct FullAccessSessionSnapshot: Equatable, Sendable {
    public let expiresAt: Date

    public init(expiresAt: Date) {
        self.expiresAt = expiresAt
    }

    public func isActive(at date: Date = Date()) -> Bool {
        expiresAt > date
    }

    public func remaining(at date: Date = Date()) -> TimeInterval {
        max(0, expiresAt.timeIntervalSince(date))
    }
}

public final class FullAccessSessionController: @unchecked Sendable {
    private struct State {
        let expiresAt: Date
        let expiresAtUptime: TimeInterval
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
            expiresAt: date.addingTimeInterval(boundedDuration),
            expiresAtUptime: expiresAtUptime
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
        lock.withLock {
            guard let state,
                  state.expiresAt > date,
                  state.expiresAtUptime > uptime
            else {
                self.state = nil
                return nil
            }
            return FullAccessSessionSnapshot(expiresAt: state.expiresAt)
        }
    }

    public func isActive(
        at date: Date = Date(),
        uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
    ) -> Bool {
        snapshot(at: date, uptime: uptime) != nil
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
