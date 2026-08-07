import Foundation
import LocalAuthentication
import MenubarHelperCore
import SwiftUI

struct FullAccessSessionConfirmationPresentation: Equatable {
    let title: String
    let message: String
    let actionTitle: String
}

let fullAccessSessionConfirmationPresentation = FullAccessSessionConfirmationPresentation(
    title: "Start Full Access Session?",
    message: "For the selected duration, every valid recognized operation from every verified app may be automically authorized, including operations that use or disclose protected secrets. Unknown, invalid, and unverifiable requests still require approval or fail closed.",
    actionTitle: "Continue to Touch ID"
)

extension FullAccessSessionLifetime {
    var title: String {
        switch self {
        case .oneHour: "1 hour"
        case .eightHours: "8 hours"
        case .untilEnded: "Until turned off"
        }
    }
}

@MainActor
final class FullAccessSessionModel: ObservableObject {
    typealias Authenticate = @MainActor (FullAccessSessionLifetime) async throws -> Bool

    @Published private(set) var snapshot: FullAccessSessionSnapshot?
    @Published private(set) var isAuthenticating = false
    @Published private(set) var authenticationError: String?
    @Published var selectedLifetime: FullAccessSessionLifetime = .untilEnded

    private let controller: FullAccessSessionController
    private let authenticate: Authenticate
    private var authenticationAttempt: UUID?
    private var authenticationTask: Task<Void, Never>?
    private var expirationTask: Task<Void, Never>?
    var onChange: (() -> Void)?

    init(
        controller: FullAccessSessionController,
        authenticate: @escaping Authenticate = authenticateFullAccessSession
    ) {
        self.controller = controller
        self.authenticate = authenticate
        snapshot = controller.snapshot()
    }

    var isActive: Bool { snapshot != nil }

    func start() {
        guard !isActive, !isAuthenticating else { return }
        authenticationTask = Task { [weak self] in
            await self?.authenticateAndStart()
        }
    }

    func authenticateAndStart() async {
        guard !isActive, !isAuthenticating else { return }
        let attempt = UUID()
        let lifetime = selectedLifetime
        authenticationAttempt = attempt
        isAuthenticating = true
        authenticationError = nil
        onChange?()
        do {
            let authenticated = try await authenticate(lifetime)
            guard authenticationAttempt == attempt, !Task.isCancelled else { return }
            authenticationAttempt = nil
            authenticationTask = nil
            guard authenticated else {
                isAuthenticating = false
                onChange?()
                return
            }
            guard controller.start(lifetime: lifetime) else {
                throw FullAccessSessionAuthenticationError.couldNotStart
            }
            isAuthenticating = false
            refresh()
        } catch {
            guard authenticationAttempt == attempt else { return }
            authenticationAttempt = nil
            authenticationTask = nil
            isAuthenticating = false
            authenticationError = error.localizedDescription
            onChange?()
        }
    }

    func end() {
        let wasAuthenticating = isAuthenticating
        authenticationAttempt = nil
        authenticationTask?.cancel()
        authenticationTask = nil
        isAuthenticating = false
        expirationTask?.cancel()
        expirationTask = nil
        controller.end()
        refresh()
        if wasAuthenticating, snapshot == nil {
            onChange?()
        }
    }

    func refresh(at date: Date = Date()) {
        let updated = controller.snapshot(at: date)
        guard updated != snapshot else { return }
        snapshot = updated
        if let expiresAt = updated?.expiresAt {
            scheduleExpiration(at: expiresAt)
        } else {
            expirationTask?.cancel()
            expirationTask = nil
        }
        onChange?()
    }

    func clearAuthenticationError() {
        authenticationError = nil
    }

    private func scheduleExpiration(at date: Date) {
        expirationTask?.cancel()
        let nanoseconds = UInt64(max(0, date.timeIntervalSinceNow) * 1_000_000_000)
        expirationTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled else { return }
            self?.refresh()
        }
    }
}

@MainActor
private func authenticateFullAccessSession(
    lifetime: FullAccessSessionLifetime
) async throws -> Bool {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.touchIDAuthenticationAllowableReuseDuration = 0
    var error: NSError?
    guard context.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        error: &error
    ) else {
        throw error ?? FullAccessSessionAuthenticationError.biometryUnavailable
    }
    return try await context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: "Start a Full Access Session for \(lifetime.title) that automically authorizes every valid recognized operation from verified apps."
    )
}

private enum FullAccessSessionAuthenticationError: LocalizedError {
    case biometryUnavailable
    case couldNotStart

    var errorDescription: String? {
        switch self {
        case .biometryUnavailable:
            "Touch ID is unavailable. Full Access Session was not started."
        case .couldNotStart:
            "Full Access Session could not be started."
        }
    }
}

func fullAccessSessionRemainingLabel(
    _ snapshot: FullAccessSessionSnapshot,
    at date: Date = Date(),
    uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
) -> String {
    guard let interval = snapshot.remaining(at: date, uptime: uptime) else {
        return "Until turned off"
    }
    let remaining = Int(ceil(interval))
    let hours = remaining / 3_600
    let minutes = remaining / 60
    let seconds = remaining % 60
    if hours > 0 {
        return "\(hours)h \(minutes % 60)m remaining"
    }
    return minutes > 0 ? "\(minutes)m \(seconds)s remaining" : "\(seconds)s remaining"
}

struct FullAccessSessionMenuPresentation: Equatable {
    let title: String
    let isEnabled: Bool
    let showsWarning: Bool
}

func fullAccessSessionMenuPresentation(
    snapshot: FullAccessSessionSnapshot?,
    isAuthenticating: Bool,
    at date: Date = Date(),
    uptime: TimeInterval = ProcessInfo.processInfo.systemUptime
) -> FullAccessSessionMenuPresentation {
    if let snapshot {
        let remaining = fullAccessSessionRemainingLabel(
            snapshot,
            at: date,
            uptime: uptime
        )
        return FullAccessSessionMenuPresentation(
            title: "End Full Access Session (\(remaining))",
            isEnabled: true,
            showsWarning: true
        )
    }
    return FullAccessSessionMenuPresentation(
        title: isAuthenticating ? "Waiting for Touch ID…" : "Start Full Access Session…",
        isEnabled: !isAuthenticating,
        showsWarning: false
    )
}
