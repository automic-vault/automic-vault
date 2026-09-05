import Foundation
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private let handlerLock = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        handlerLock.withLock { handler = contentHandler }
        content = request.content.mutableCopy() as? UNMutableNotificationContent
        guard let content, let value = request.content.userInfo["av"] else {
            finish(with: request.content)
            return
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: value)
            let envelope = try JSONDecoder().decode(ApprovalCiphertext.self, from: data)
            let key = try ICloudApprovalRootKey().load()
            let crypto = try ApprovalCrypto(rootKeyData: key)
            let plaintext = try crypto.open(envelope, purpose: "notification")
            guard let ticket = try? JSONDecoder().decode(PhoneApprovalTicket.self, from: plaintext) else {
                let cancellation = try JSONDecoder().decode(PhoneApprovalCancellation.self, from: plaintext)
                let center = UNUserNotificationCenter.current()
                center.removeDeliveredNotifications(withIdentifiers: [
                    crypto.notificationIdentifier(requestID: cancellation.requestID),
                ])
                let empty = UNMutableNotificationContent()
                self.content = empty
                center.getDeliveredNotifications { [weak self] notifications in
                    let identifiers = notifications
                        .filter { $0.request.content.threadIdentifier == cancellation.requestID.uuidString }
                        .map(\.request.identifier)
                    center.removeDeliveredNotifications(withIdentifiers: identifiers)
                    self?.finish(with: empty)
                }
                return
            }
            content.title = "Approval waiting"
            let preferences = (try? ApprovalNotificationPreferences.load()) ?? .init()
            var details: [String] = []
            if preferences.showsHost { details.append("Host: \(ticket.macName)") }
            if preferences.showsApprovalType {
                details.append("Approval type: \(ticket.requiresFullReview ? "Full review" : "Routine")")
            }
            content.body = (["Review the full request on your Mac or open Automic Vault."] + details)
                .joined(separator: "\n")
            content.categoryIdentifier = ticket.requiresFullReview ? "AV_REVIEW" : "AV_ROUTINE"
            content.threadIdentifier = ticket.requestID.uuidString
            finish(with: content)
        } catch {
            content.title = "Approval waiting"
            content.body = "Open Automic Vault to review."
            content.categoryIdentifier = "AV_REVIEW"
            finish(with: content)
        }
    }

    override func serviceExtensionTimeWillExpire() {
        if let content { finish(with: content) }
    }

    private func finish(with content: UNNotificationContent) {
        let callback: ((UNNotificationContent) -> Void)? = handlerLock.withLock {
            defer { handler = nil }
            return handler
        }
        callback?(content)
    }
}
