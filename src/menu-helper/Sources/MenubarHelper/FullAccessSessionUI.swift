import Foundation
import LocalAuthentication
import MenubarHelperCore
import SwiftUI

@MainActor
final class FullAccessSessionModel: ObservableObject {
    typealias Authenticate = @MainActor () async throws -> Bool

    @Published private(set) var snapshot: FullAccessSessionSnapshot?
    @Published private(set) var isAuthenticating = false
    @Published private(set) var authenticationError: String?

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
        authenticationAttempt = attempt
        isAuthenticating = true
        authenticationError = nil
        onChange?()
        do {
            let authenticated = try await authenticate()
            guard authenticationAttempt == attempt, !Task.isCancelled else { return }
            authenticationAttempt = nil
            authenticationTask = nil
            guard authenticated else {
                isAuthenticating = false
                onChange?()
                return
            }
            guard controller.start() else {
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
        if let updated {
            scheduleExpiration(at: updated.expiresAt)
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
private func authenticateFullAccessSession() async throws -> Bool {
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
        localizedReason: "Start a one-hour Full Access Session that automatically authorizes every recognized operation from verified apps."
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
    at date: Date = Date()
) -> String {
    let remaining = Int(ceil(snapshot.remaining(at: date)))
    let minutes = remaining / 60
    let seconds = remaining % 60
    return minutes > 0 ? "\(minutes)m \(seconds)s remaining" : "\(seconds)s remaining"
}
