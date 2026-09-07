import ApprovalCore
import CryptoKit
import Foundation
import Testing

@Test func requestMutationCannotReuseResponse() throws {
    let key = Data(repeating: 7, count: ApprovalCrypto.rootKeyByteCount)
    let crypto = try ApprovalCrypto(rootKeyData: key)
    let request = try sampleRequest(command: "aws s3 ls")
    let response = try PhoneApprovalResponse(
        request: request,
        outcome: .approved,
        deviceID: "phone"
    )
    try response.validate(for: request)

    let changed = try sampleRequest(id: request.id, command: "aws s3 rm s3://bucket --recursive")
    #expect(throws: ApprovalProtocolError.mismatchedResponse) {
        try response.validate(for: changed)
    }

    let plaintext = try JSONEncoder().encode(ApprovalWireMessage.request(request))
    let sealed = try crypto.seal(plaintext, purpose: "transport")
    #expect(try crypto.open(sealed, purpose: "transport") == plaintext)
    #expect(throws: (any Error).self) {
        try crypto.open(sealed, purpose: "notification")
    }

    let ticket = try PhoneApprovalTicket(request: request)
    let notificationResponse = try PhoneApprovalResponse(
        requestID: ticket.requestID,
        requestDigest: ticket.requestDigest,
        outcome: .approved,
        deviceID: "phone"
    )
    try notificationResponse.validate(for: request)
}

@Test func addressesAndRegistrationProofsAreStableAndSeparated() throws {
    let crypto = try ApprovalCrypto(rootKeyData: Data(repeating: 9, count: 32))
    #expect(crypto.address.room.count == 43)
    #expect(crypto.address.credential.count == 43)
    #expect(crypto.address.room != crypto.address.credential)
    #expect(crypto.registrationProof(deviceID: "a") != crypto.registrationProof(deviceID: "b"))
}

@Test func presenceAndSyncRoundTrip() throws {
    let messages: [ApprovalWireMessage] = [
        .sync,
        .presence(try ApprovalMacPresence(macID: "mac", macName: "Studio", sentAtMilliseconds: 42)),
    ]
    for message in messages {
        let data = try JSONEncoder().encode(message)
        #expect(try JSONDecoder().decode(ApprovalWireMessage.self, from: data) == message)
    }
}

@Test func longRequestFitsNotificationEnvelopeWithoutChangingDigest() throws {
    let request = try sampleRequest(command: String(repeating: "x", count: 8_000))
    let ticket = try PhoneApprovalTicket(request: request)
    let requestDigest = try request.digest()
    let crypto = try ApprovalCrypto(rootKeyData: Data(repeating: 7, count: 32))
    let notification = try JSONEncoder().encode(
        crypto.seal(JSONEncoder().encode(ticket), purpose: "notification")
    )

    #expect(ticket.requestDigest == requestDigest)
    #expect(notification.count <= ApprovalRelayClient.maximumNotificationBytes)
}

@Test func temporaryWriteAccessRequiresExplicitRequestCapability() throws {
    let request = try sampleRequest(
        command: "gh repo create",
        temporaryAccessGrantScope: "Ghostty, GH Authorization Gate, and Codex task AAAAAAAA"
    )
    let response = try PhoneApprovalResponse(
        request: request,
        outcome: .temporaryWriteAccess,
        deviceID: "phone"
    )
    try response.validate(for: request)

    let ineligible = try sampleRequest(command: "aws s3 ls")
    #expect(throws: ApprovalProtocolError.invalidRequest) {
        try PhoneApprovalResponse(
            request: ineligible,
            outcome: .temporaryWriteAccess,
            deviceID: "phone"
        )
    }

    let forged = try JSONDecoder().decode(
        PhoneApprovalResponse.self,
        from: JSONSerialization.data(withJSONObject: [
            "version": 1,
            "requestID": ineligible.id.uuidString,
            "requestDigest": try ineligible.digest().base64EncodedString(),
            "outcome": "temporaryWriteAccess",
            "deviceID": "phone",
            "decidedAtMilliseconds": 1,
        ])
    )
    #expect(throws: ApprovalProtocolError.mismatchedResponse) {
        try forged.validate(for: ineligible)
    }
}

@Test func subscriptionFailureFailsClosedWithoutBlockingDenial() {
    #expect(PhoneApprovalSubscriptionAccess.active.permits(.approved))
    #expect(PhoneApprovalSubscriptionAccess.active.permits(.temporaryWriteAccess))
    #expect(PhoneApprovalSubscriptionAccess.active.permits(.denied))
    #expect(!PhoneApprovalSubscriptionAccess.unavailable.permits(.approved))
    #expect(!PhoneApprovalSubscriptionAccess.unavailable.permits(.temporaryWriteAccess))
    #expect(PhoneApprovalSubscriptionAccess.unavailable.permits(.denied))
}

@Test func iPhoneActivityIsNewestFirstDeduplicatedAndBounded() throws {
    var activity: [PhoneApprovalActivity] = []
    for index in 0...PhoneApprovalActivity.maximumItems {
        let request = try sampleRequest(
            id: UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", index))!,
            command: "command-\(index)"
        )
        activity = PhoneApprovalActivity.adding(
            .init(request: request, outcome: .approved),
            to: activity
        )
    }

    #expect(activity.count == PhoneApprovalActivity.maximumItems)
    #expect(activity.first?.command == "command-50")
    #expect(activity.last?.command == "command-1")

    let oldest = try #require(activity.last)
    let replacement = try sampleRequest(id: oldest.id, command: "replacement")
    activity = PhoneApprovalActivity.adding(
        .init(request: replacement, outcome: .denied),
        to: activity
    )
    #expect(activity.count == PhoneApprovalActivity.maximumItems)
    #expect(activity.first?.command == "replacement")
    #expect(activity.first?.outcome == .denied)

    let canceled = try sampleRequest(id: activity.last!.id, command: "canceled")
    activity = PhoneApprovalActivity.adding(.init(canceled: canceled, at: 42), to: activity)
    let restored = try JSONDecoder().decode(
        [PhoneApprovalActivity].self,
        from: JSONEncoder().encode(activity)
    )
    #expect(restored.count == PhoneApprovalActivity.maximumItems)
    #expect(restored.first?.command == "canceled")
    #expect(restored.first?.outcome == .canceled)
    #expect(restored.first?.respondedAtMilliseconds == 42)
}

@Test func canceledNotificationCreatesHistoryWithoutPendingRequest() throws {
    let request = try sampleRequest(command: "git rebase --continue")
    let ticket = try PhoneApprovalTicket(canceled: request, at: 42)
    let restored = try JSONDecoder().decode(
        PhoneApprovalTicket.self,
        from: JSONEncoder().encode(ticket)
    )
    let activity = try #require(PhoneApprovalActivity(canceled: restored))

    #expect(activity.id == request.id)
    #expect(activity.command == "git rebase --continue")
    #expect(activity.outcome == .canceled)
    #expect(activity.respondedAtMilliseconds == 42)

    let crypto = try ApprovalCrypto(rootKeyData: Data(repeating: 9, count: 32))
    #expect(crypto.notificationIdentifier(for: request.id).count == 43)
    #expect(crypto.notificationIdentifier(for: request.id) != crypto.address.room)
}

private func sampleRequest(
    id: UUID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
    command: String,
    temporaryAccessGrantScope: String? = nil
) throws -> PhoneApprovalRequest {
    try PhoneApprovalRequest(
        id: id,
        createdAtMilliseconds: 1_700_000_000_000,
        macName: "MacBook Pro",
        launcher: "Terminal",
        tool: "aws",
        command: command,
        cwd: "/tmp",
        secretNames: ["AWS_ACCESS_KEY_ID"],
        reason: "Unknown operation requires Approval",
        risks: [.unknown],
        details: [],
        temporaryAccessGrantScope: temporaryAccessGrantScope
    )
}
