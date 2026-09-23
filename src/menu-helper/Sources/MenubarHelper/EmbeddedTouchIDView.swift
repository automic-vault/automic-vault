import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

@MainActor
final class EmbeddedTouchIDAttempt: ObservableObject {
    private var context: LAContext?

    func prepare() -> LAContext {
        cancel()
        let context = LAContext()
        self.context = context
        return context
    }

    func finish(_ context: LAContext, approved: Bool, completion: () -> Void) {
        guard self.context === context else { return }
        cancel()
        if approved { completion() }
    }

    func cancel() {
        let previous = context
        context = nil
        previous?.invalidate()
    }
}

struct EmbeddedTouchIDView: NSViewRepresentable {
    let attempt: EmbeddedTouchIDAttempt
    let approve: () -> Void

    func makeCoordinator() -> EmbeddedTouchIDAttempt { attempt }

    func makeNSView(context: Context) -> AuthenticationView {
        let authenticationContext = attempt.prepare()
        let view = AuthenticationView(context: authenticationContext, controlSize: .mini)
        view.start = { [weak view] in
            guard let view, view.window?.isVisible == true else { return }
            TouchIDApproval.authenticate(
                reason: String(localized: "Approve this exact Automic Vault request once"),
                context: authenticationContext
            ) { [weak view] approved in
                attempt.finish(authenticationContext, approved: approved && view?.window?.isVisible == true) {
                    approve()
                }
            }
        }
        return view
    }

    func updateNSView(_ nsView: AuthenticationView, context: Context) {}

    static func dismantleNSView(_ nsView: AuthenticationView, coordinator: EmbeddedTouchIDAttempt) {
        nsView.start = nil
        coordinator.finish(nsView.context, approved: false) {}
    }

    final class AuthenticationView: LAAuthenticationView {
        var start: (() -> Void)?

        override var acceptsFirstResponder: Bool { false }
        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard window != nil else {
                context.invalidate()
                return
            }
            // The non-activating Approval panel is ordered front after layout.
            RunLoop.main.perform(inModes: [.modalPanel, .default]) { [weak self] in
                MainActor.assumeIsolated {
                    let start = self?.start
                    self?.start = nil
                    start?()
                }
            }
        }
    }
}

@MainActor
func embeddedTouchIDAttemptSelfCheck() -> Bool {
    let indicator = EmbeddedTouchIDView.AuthenticationView(context: LAContext(), controlSize: .mini)
    guard indicator.fittingSize == NSSize(width: 16, height: 16),
          !indicator.acceptsFirstResponder,
          indicator.hitTest(.zero) == nil else { return false }
    let attempt = EmbeddedTouchIDAttempt()
    var approvals = 0
    let canceled = attempt.prepare()
    attempt.cancel()
    attempt.finish(canceled, approved: true) { approvals += 1 }
    let replaced = attempt.prepare()
    let current = attempt.prepare()
    attempt.finish(replaced, approved: true) { approvals += 1 }
    attempt.finish(current, approved: false) { approvals += 1 }
    attempt.finish(current, approved: true) { approvals += 1 }
    guard approvals == 0 else { return false }
    let successful = attempt.prepare()
    attempt.finish(successful, approved: true) { approvals += 1 }
    attempt.finish(successful, approved: true) { approvals += 1 }
    return approvals == 1
}
