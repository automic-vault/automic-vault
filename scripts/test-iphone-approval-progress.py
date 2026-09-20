#!/usr/bin/env python3
"""Run the real response methods with suspended authentication and relay delivery."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "src/ios/ApprovalApp/ApprovalApp.swift").read_text()
methods = source[source.index("    private func respond(to request:"):
                 source.index("    private func subscriptionPermits(")]
methods = methods.replace("private func", "func")
fixture = r'''
import Foundation

enum PhoneApprovalOutcome { case approved, denied, temporaryWriteAccess }
struct PhoneApprovalRequest { let id = UUID() }
struct PhoneApprovalTicket { let requestID: UUID; let requestDigest = "digest" }
struct PhoneApprovalResponse {
    init(request: PhoneApprovalRequest, outcome: PhoneApprovalOutcome, deviceID: String) throws {}
    init(requestID: UUID, requestDigest: String, outcome: PhoneApprovalOutcome, deviceID: String) throws {}
}
struct PhoneApprovalActivity {
    init(request: PhoneApprovalRequest, outcome: PhoneApprovalOutcome) {}
    init(ticket: PhoneApprovalTicket, outcome: PhoneApprovalOutcome) {}
}
enum ApprovalRelayClientError: Error { case disconnected }
enum Message { case response(PhoneApprovalResponse) }
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
    func connect() async {}
    func recordActivity(_ item: PhoneApprovalActivity) {}
    func removeDeliveredNotifications(for id: UUID) async {}
METHODS
}
@main struct Check {
    @MainActor static func main() async {
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
        print("iPhone approval progress checks passed")
    }
}
'''.replace("METHODS", methods)
with tempfile.TemporaryDirectory(prefix="av-approval-progress-") as directory:
    path = Path(directory)
    (path / "check.swift").write_text(fixture)
    subprocess.run(["xcrun", "swiftc", "-swift-version", "6", "-parse-as-library",
                    str(path / "check.swift"), "-o", str(path / "check")], check=True)
    subprocess.run([str(path / "check")], check=True, timeout=30)
