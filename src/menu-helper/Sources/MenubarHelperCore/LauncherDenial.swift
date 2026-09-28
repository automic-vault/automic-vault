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

/// A recorded operation scope is descriptive metadata, never allow authority.
public struct TemporaryLauncherDenialScope: Codable, Equatable, Sendable {
    public let gateID: String
    public let gateName: String
    public let threshold: SecretGateProtection

    public init?(gate: SecretGate, classification: SecretGateRequestClassification) {
        guard let threshold = gate.availableProtections.first(where: { $0.allows(classification) }) else { return nil }
        self.gateID = gate.id
        self.gateName = gate.displayName
        self.threshold = threshold
    }

    public var operationTitle: String {
        switch gateID {
        case "ssh-agent": return "SSH authentication"
        case "gpg-signing": return "GPG signing"
        default:
            switch threshold {
            case .noAccess, .readOnly, .readOnlyAndUpdates: return "all requests"
            case .readOnlyAndLocalWrites: return "local writes and above"
            case .fullExceptSecretDumps: return "writes and above"
            case .fullIncludingSecretDumps: return "Full Access operations"
            }
        }
    }

    public var actionTitle: String { "Deny \(operationTitle) for 2 minutes" }
}

public struct TemporaryLauncherDenial: Identifiable, Sendable {
    public let id: UUID
    public let requirement: String
    public let launcherName: String
    public let scope: TemporaryLauncherDenialScope
    public let deadline: TimeInterval
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
    private struct PromptKey: Hashable {
        let requirement: String
        let gateID: String
    }
    private let lock = NSLock()
    private var denials: [TemporaryLauncherDenial] = []
    private var prompts: [PromptKey: [TimeInterval]] = [:]

    public init() {}

    public func deny(_ requirement: String, launcherName: String, scope: TemporaryLauncherDenialScope,
                     now: TimeInterval = TemporaryLauncherDenials.now) {
        guard !requirement.isEmpty, !scope.gateID.isEmpty else { return }
        lock.withLock {
            denials.removeAll { $0.deadline <= now || ($0.requirement == requirement
                && $0.scope.gateID == scope.gateID && $0.scope.threshold == scope.threshold) }
            denials.append(TemporaryLauncherDenial(id: UUID(), requirement: requirement,
                launcherName: launcherName, scope: scope, deadline: now + 120))
            prompts.removeValue(forKey: PromptKey(requirement: requirement, gateID: scope.gateID))
        }
        NotificationCenter.default.post(name: launcherDenialDidChange, object: nil)
    }

    public func active(now: TimeInterval = TemporaryLauncherDenials.now) -> [TemporaryLauncherDenial] {
        lock.withLock {
            denials.removeAll { $0.deadline <= now }
            return denials
        }
    }

    public func cancel(_ id: UUID) {
        let changed = lock.withLock {
            let count = denials.count
            denials.removeAll { $0.id == id }
            return denials.count != count
        }
        if changed { NotificationCenter.default.post(name: launcherDenialDidChange, object: nil) }
    }

    public func isDenied(_ requirement: String, gate: SecretGate, classification: SecretGateRequestClassification,
                         now: TimeInterval = TemporaryLauncherDenials.now) -> Bool {
        active(now: now).contains {
            $0.requirement == requirement && $0.scope.gateID == gate.id && gate.denies(classification, at: $0.scope.threshold)
        }
    }

    public func deadline(for requirement: String, scope: TemporaryLauncherDenialScope,
                         now: TimeInterval = TemporaryLauncherDenials.now) -> TimeInterval? {
        active(now: now).first {
            $0.requirement == requirement && $0.scope.gateID == scope.gateID && $0.scope.threshold == scope.threshold
        }?.deadline
    }

    /// Preview the next prompt's action without counting an attempted presentation.
    public func shouldOfferDenialOnNextPrompt(_ requirement: String, gateID: String,
                                            now: TimeInterval = TemporaryLauncherDenials.now) -> Bool {
        lock.withLock { (prompts[PromptKey(requirement: requirement, gateID: gateID)] ?? []).filter { $0 >= now - 30 }.count >= 1 }
    }

    /// Two presentations within thirty seconds, capped at two timestamps per Launcher/gate.
    public func recordPrompt(_ requirement: String, gateID: String, now: TimeInterval = TemporaryLauncherDenials.now) -> Bool {
        guard !requirement.isEmpty, !gateID.isEmpty else { return false }
        let key = PromptKey(requirement: requirement, gateID: gateID)
        return lock.withLock {
            prompts = prompts.filter { ($0.value.last ?? 0) >= now - 30 }
            if prompts[key] == nil, prompts.count >= 256,
               let oldest = prompts.min(by: { ($0.value.last ?? 0) < ($1.value.last ?? 0) })?.key {
                prompts.removeValue(forKey: oldest)
            }
            let recent = (prompts[key] ?? []).filter { $0 >= now - 30 }
            prompts[key] = Array((recent + [now]).suffix(2))
            return recent.count >= 1
        }
    }
}
