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
    private let lock = NSLock()
    private var expiresAt: Date?

    public init() {}

    @discardableResult
    public func start(
        at date: Date = Date(),
        duration: TimeInterval = fullAccessSessionMaximumDuration
    ) -> Bool {
        guard duration.isFinite, duration > 0 else { return false }
        let expiration = date.addingTimeInterval(min(duration, fullAccessSessionMaximumDuration))
        lock.lock()
        expiresAt = expiration
        lock.unlock()
        return true
    }

    public func end() {
        lock.lock()
        expiresAt = nil
        lock.unlock()
    }

    public func snapshot(at date: Date = Date()) -> FullAccessSessionSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        guard let expiresAt, expiresAt > date else {
            self.expiresAt = nil
            return nil
        }
        return FullAccessSessionSnapshot(expiresAt: expiresAt)
    }

    public func isActive(at date: Date = Date()) -> Bool {
        snapshot(at: date) != nil
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
