import Foundation
import SwiftUI

@MainActor
var authorityChangeUsesIPhone: Bool {
    PhoneApprovalCoordinator.shared.isEnabled
        && !(TouchIDApproval.isEnabled && TouchIDApproval.isAvailable)
}

/// UI request lifetimes only; the coordinator still verifies every Approval.
@MainActor
final class AuthorityApprovalState: ObservableObject {
    private struct Pending {
        let attempt = UUID()
        let usesPhone: Bool
        var requestID: UUID?
    }

    @Published private var pending: [String: Pending] = [:]

    func isPending(_ action: String) -> Bool { pending[action] != nil }
    func usesPhone(_ action: String) -> Bool {
        pending[action]?.usesPhone ?? authorityChangeUsesIPhone
    }

    func request(
        _ action: String,
        title: String,
        detail: String,
        authorize: @MainActor (String, String, @escaping (Bool) -> Void) -> UUID? = requestAuthorityChangeApproval,
        completion: @escaping (Bool) -> Void
    ) {
        guard !isPending(action) else { return }
        let item = Pending(usesPhone: authorityChangeUsesIPhone)
        pending[action] = item
        let requestID = authorize(title, detail) { [weak self] approved in
            guard let self, self.pending[action]?.attempt == item.attempt else { return }
            self.pending.removeValue(forKey: action)
            completion(approved)
        }
        if pending[action]?.attempt == item.attempt {
            pending[action]?.requestID = requestID
        }
    }

    func cancel(_ action: String, cancelRequest: @MainActor (UUID) -> Void = PhoneApprovalCoordinator.shared.cancel) {
        guard let item = pending.removeValue(forKey: action) else { return }
        if let requestID = item.requestID { cancelRequest(requestID) }
    }

    func cancelAll() {
        for action in Array(pending.keys) { cancel(action) }
    }
}

struct AuthorityApprovalLabel: View {
    let title: String
    @ObservedObject var approval: AuthorityApprovalState
    let action: String
    var requiresApproval = true
    @AppStorage(phoneApprovalEnabledDefaultsKey) private var phoneEnabled = false

    var body: some View {
        let pending = approval.isPending(action)
        let phone = pending ? approval.usesPhone(action) : (requiresApproval && phoneEnabled && authorityChangeUsesIPhone)
        HStack(spacing: 6) {
            if pending {
                ProgressView().controlSize(.small).accessibilityHidden(true)
            }
            if phone {
                Image(systemName: "iphone").accessibilityHidden(true)
            }
            Text(pending ? (phone ? "Waiting for iPhone…" : "Waiting for Approval…") : title)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(pending ? "\(title), waiting for Approval\(phone ? " on iPhone" : "")" : title)
        .help(phone ? "\(title) requires Approval on iPhone." : title)
    }
}

struct AuthorityApprovalButton: View {
    let title: String
    @ObservedObject var approval: AuthorityApprovalState
    let action: String
    let perform: () -> Void

    var body: some View {
        Button {
            guard !approval.isPending(action) else { return }
            perform()
        } label: {
            AuthorityApprovalLabel(title: title, approval: approval, action: action)
        }
        .disabled(approval.isPending(action))
    }
}

@MainActor
func authorityApprovalStateSelfCheck() -> Bool {
    let state = AuthorityApprovalState()
    let requestID = UUID()
    var replies: [(Bool) -> Void] = []
    var outcomes: [Bool] = []
    let authorize: @MainActor (String, String, @escaping (Bool) -> Void) -> UUID? = { _, _, reply in
        replies.append(reply)
        return requestID
    }
    func press() {
        state.request("blessing", title: "Bless Script", detail: "Fixture", authorize: authorize) {
            outcomes.append($0)
        }
    }
    for _ in 0..<4 { press() }
    guard state.isPending("blessing"), replies.count == 1, outcomes.isEmpty else { return false }
    replies[0](false)
    guard !state.isPending("blessing"), outcomes == [false] else { return false }
    press()
    var canceled: UUID?
    state.cancel("blessing") { canceled = $0 }
    guard canceled == requestID, !state.isPending("blessing") else { return false }
    press()
    replies[1](true) // A late Approval must not complete the replacement request.
    guard state.isPending("blessing"), outcomes == [false] else { return false }
    replies[2](true)
    replies[2](true)
    guard !state.isPending("blessing"), outcomes == [false, true] else { return false }
    state.request("local", title: "Local", detail: "", authorize: { _, _, reply in
        reply(true)
        return nil
    }) { outcomes.append($0) }
    return !state.isPending("local") && outcomes == [false, true, true]
}
