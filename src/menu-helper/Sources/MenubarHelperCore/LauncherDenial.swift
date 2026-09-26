import Foundation

public let launcherDenialDidChange = Notification.Name("AutomicVaultLauncherDenialDidChange")

public extension SecretGate {
    /// Complement of the preceding supported allow preset. Invalid thresholds fail closed.
    func denies(_ classification: SecretGateRequestClassification, at threshold: SecretGateProtection) -> Bool {
        guard let index = availableProtections.firstIndex(of: threshold), index > 0 else { return true }
        return !availableProtections[index - 1].allows(classification)
    }

    func weakeningDenial(from old: SecretGateProtection?, to new: SecretGateProtection?) -> Bool {
        guard let old else { return false }
        return SecretGateRequestClassification.allCases.contains { classification in
            denies(classification, at: old) && !(new.map { denies(classification, at: $0) } ?? false)
        }
    }
}

/// Only explicit user actions populate denials. Prompt counts never authorize or deny.
public final class TemporaryLauncherDenials: @unchecked Sendable {
    public static let shared = TemporaryLauncherDenials()
    private static let clockOrigin = ContinuousClock.now
    /// Continuous elapsed time includes sleep and is unaffected by wall-clock changes.
    public static var now: TimeInterval {
        let elapsed = clockOrigin.duration(to: .now).components
        return Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
    }
    private let lock = NSLock()
    private var deadlines: [String: TimeInterval] = [:]
    private var prompts: [String: [TimeInterval]] = [:]

    public init() {}

    public func deny(_ requirement: String, now: TimeInterval = TemporaryLauncherDenials.now) {
        guard !requirement.isEmpty else { return }
        lock.withLock {
            deadlines = deadlines.filter { $0.value > now }
            deadlines[requirement] = now + 120
            prompts.removeValue(forKey: requirement)
        }
        NotificationCenter.default.post(name: launcherDenialDidChange, object: nil)
    }

    public func isDenied(_ requirement: String, now: TimeInterval = TemporaryLauncherDenials.now) -> Bool {
        lock.withLock { (deadlines[requirement] ?? 0) > now }
    }

    /// Three presentations within thirty seconds, capped at three timestamps per identity.
    public func recordPrompt(_ requirement: String, now: TimeInterval = TemporaryLauncherDenials.now) -> Bool {
        guard !requirement.isEmpty else { return false }
        return lock.withLock {
            prompts = prompts.filter { ($0.value.last ?? 0) >= now - 30 }
            if prompts[requirement] == nil, prompts.count >= 256,
               let oldest = prompts.min(by: { ($0.value.last ?? 0) < ($1.value.last ?? 0) })?.key {
                prompts.removeValue(forKey: oldest)
            }
            let recent = (prompts[requirement] ?? []).filter { $0 >= now - 30 }
            prompts[requirement] = Array((recent + [now]).suffix(3))
            return recent.count >= 2
        }
    }
}
