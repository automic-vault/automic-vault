#!/usr/bin/env python3
"""Run the real response methods with suspended authentication and relay delivery."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "src/ios/ApprovalApp/ApprovalApp.swift").read_text()
methods = source[source.index("    private func respond(to request:"):
                 source.index("    private func subscriptionPermits(")]
methods += source[source.index("    func handleNotificationResponse("):
                  source.index("    func handleBackgroundNotification(")]
methods = methods.replace("private func", "func")
startup_state = source[source.index("    enum ConnectionState:"):
                       source.index("    static var biometricProtectionEnabled:")]
startup_state += source[source.index("    private(set) var isStarting"):
                        source.index("    private(set) var notificationPreferences")]
views = (Path(__file__).resolve().parents[1] /
         "src/ios/ApprovalApp/ApprovalViews.swift").read_text()
# Approval content must outrank the startup gate, which must outrank empty/setup UI.
assert views.index("if let request = notificationRequest") < views.index("else if let ticket")
assert views.index("else if !model.pending.isEmpty") < views.index("model.isStarting || subscription.state == .loading")
assert views.index("model.isStarting || subscription.state == .loading") < views.index("else if model.state == .setup")
history_visibility = views[views.index("    private var showsActivity:"):
                           views.index("    @ViewBuilder\n    private func destination")]
history_visibility = history_visibility.replace("private var", "var")
fixture = r'''
import Foundation

enum PhoneApprovalOutcome { case approved, denied, temporaryWriteAccess }
struct PhoneApprovalRequest { let id = UUID() }
struct PhoneApprovalTicket {
    let requestID: UUID
    let requestDigest = "digest"
    var requiresFullReview = false
    var canceled = false
}
let UNNotificationDefaultActionIdentifier = "default"
struct UNNotificationResponse {
    let actionIdentifier: String
    let notification = Notification()
    struct Notification { let request = Request() }
    struct Request { let content = Content() }
    struct Content { let userInfo: [AnyHashable: Any] = [:] }
}
struct PhoneApprovalResponse {
    init(request: PhoneApprovalRequest, outcome: PhoneApprovalOutcome, deviceID: String) throws {}
    init(requestID: UUID, requestDigest: String, outcome: PhoneApprovalOutcome, deviceID: String) throws {}
}
struct PhoneApprovalActivity {
    init?(canceled ticket: PhoneApprovalTicket) { if !ticket.canceled { return nil } }
    init(request: PhoneApprovalRequest, outcome: PhoneApprovalOutcome) {}
    init(ticket: PhoneApprovalTicket, outcome: PhoneApprovalOutcome) {}
}
enum ApprovalRelayClientError: Error { case disconnected }
enum Message { case response(PhoneApprovalResponse), sync }
@MainActor final class Relay {
    var sends = 0
    var fails = false
    var onSend: () async -> Void = {}
    func send(_ message: Message) async throws {
        sends += 1
        await onSend()
        if fails { throw ApprovalRelayClientError.disconnected }
    }
}
@MainActor final class Model {
STARTUP_STATE
    func setConnectionState(_ value: ConnectionState) { state = value }
    var notificationReviewTicket: PhoneApprovalTicket?
    var notificationReviewRequestID: UUID?
    var notificationReviewSequence: UInt64 = 0
    var incomingTicket: PhoneApprovalTicket?
    var onConnect: () -> Void = {}
    func ticket(from info: [AnyHashable: Any]) async -> PhoneApprovalTicket? { incomingTicket }
    var respondingRequestIDs: Set<UUID> = []
    var pending: [PhoneApprovalRequest] = []
    var biometricProtectionEnabled = true
    var authenticates = true
    var subscribed = true
    var authentications = 0
    var onAuthenticate: () async -> Void = {}
    var relay: Relay? = Relay()
    var errorMessage: String?
    let deviceID = "fixture"
    func authenticateBiometrically() async -> Bool {
        authentications += 1
        await onAuthenticate()
        return authenticates
    }
    func subscriptionPermits(_ outcome: PhoneApprovalOutcome) async -> Bool {
        outcome == .denied || subscribed
    }
    func connect() async { onConnect() }
    func recordActivity(_ item: PhoneApprovalActivity) {}
    func removeDeliveredNotifications(for id: UUID) async {}
METHODS
}
@MainActor struct HistoryVisibility {
    let model: Model
    let subscription = Subscription()
    struct Subscription {
        enum State { case active }
        let state = State.active
    }
HISTORY_VISIBILITY
}
@main struct Check {
    @MainActor static func main() async {
        for resolved in [Model.ConnectionState.setup, .connected,
                         .unavailable("failure"), .reconnecting("offline")] {
            let startup = Model()
            assert(startup.isStarting)
            startup.setConnectionState(.connecting)
            assert(startup.isStarting)
            startup.setConnectionState(resolved)
            assert(!startup.isStarting)
            startup.setConnectionState(.connecting)
            assert(!startup.isStarting) // Subsequent retries never restart the gate.
            let history = HistoryVisibility(model: startup)
            assert(history.showsActivity) // Reconnecting must keep the same history screen.
            for state in [Model.ConnectionState.connected, .reconnecting("offline"), .unavailable("failed")] {
                startup.setConnectionState(state)
                assert(history.showsActivity)
            }
            startup.setConnectionState(.setup)
            assert(!history.showsActivity)
        }
        for usesTicket in [false, true] {
            for outcome in [PhoneApprovalOutcome.approved, .temporaryWriteAccess, .denied] {
                let model = Model()
                let request = PhoneApprovalRequest()
                let ticket = PhoneApprovalTicket(requestID: request.id)
                model.pending = [request]
                let respond: () async -> Void = {
                    if usesTicket { await model.respond(to: ticket, outcome: outcome) }
                    else { await model.respond(to: request, outcome: outcome) }
                }
                let checkBusy: () async -> Void = {
                    assert(model.respondingRequestIDs == [request.id])
                    // Reentrant taps and notification actions cannot send competing responses.
                    await model.respond(to: request, outcome: .approved)
                    await model.respond(to: ticket, outcome: .denied)
                    assert(model.respondingRequestIDs == [request.id])
                }
                model.onAuthenticate = checkBusy
                model.relay!.onSend = checkBusy
                model.relay!.fails = true
                await respond()
                assert(model.respondingRequestIDs.isEmpty)
                assert(model.pending.count == 1 && model.errorMessage != nil)
                assert(model.relay!.sends == 1)
                assert(model.authentications == (outcome == .denied ? 0 : 1))

                // Failed delivery clears busy state and allows retry.
                model.relay!.fails = false
                await respond()
                assert(model.respondingRequestIDs.isEmpty && model.pending.isEmpty)
                assert(model.relay!.sends == 2)

                // Canceled authentication and unavailable subscriptions fail closed.
                if outcome != .denied {
                    model.pending = [request]
                    model.authenticates = false
                    await respond()
                    assert(model.respondingRequestIDs.isEmpty && model.pending.count == 1)
                    model.authenticates = true
                    model.subscribed = false
                    await respond()
                    assert(model.respondingRequestIDs.isEmpty && model.pending.count == 1)
                    assert(model.relay!.sends == 2)
                }
            }
        }
        let model = Model()
        model.relay = nil
        let id = UUID()
        model.incomingTicket = PhoneApprovalTicket(requestID: id, requiresFullReview: true)
        var connects = 0
        model.onConnect = {
            connects += 1
            // Authenticated summary and routing must be ready before any relay wait.
            assert(model.notificationReviewTicket?.requestID == id)
            assert(model.notificationReviewRequestID == id)
            assert(model.notificationReviewSequence > 0)
            assert(model.isStarting) // Notification review bypasses unresolved startup.
        }
        for action in ["AV_REVIEW", UNNotificationDefaultActionIdentifier] {
            await model.handleNotificationResponse(.init(actionIdentifier: action))
        }
        assert(connects == 2 && model.notificationReviewSequence == 2)
        model.dismissNotificationReview()
        assert(model.notificationReviewTicket == nil && model.notificationReviewRequestID == nil)
        model.incomingTicket = nil
        await model.handleNotificationResponse(.init(actionIdentifier: "AV_REVIEW"))
        assert(model.notificationReviewTicket == nil && connects == 2)
        model.incomingTicket = PhoneApprovalTicket(requestID: id, canceled: true)
        await model.handleNotificationResponse(.init(actionIdentifier: "AV_REVIEW"))
        assert(model.notificationReviewTicket == nil && connects == 2)
        print("iPhone approval progress and notification routing checks passed")
    }
}
'''.replace("METHODS", methods).replace("STARTUP_STATE", startup_state).replace("HISTORY_VISIBILITY", history_visibility)
with tempfile.TemporaryDirectory(prefix="av-approval-progress-") as directory:
    path = Path(directory)
    (path / "check.swift").write_text(fixture)
    subprocess.run(["xcrun", "swiftc", "-swift-version", "6", "-parse-as-library",
                    str(path / "check.swift"), "-o", str(path / "check")], check=True)
    subprocess.run([str(path / "check")], check=True, timeout=30)
