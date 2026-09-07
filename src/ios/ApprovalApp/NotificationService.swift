import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        handler = contentHandler
        content = request.content.mutableCopy() as? UNMutableNotificationContent
        guard let content, let value = request.content.userInfo["av"] else {
            contentHandler(request.content)
            return
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: value)
            let envelope = try JSONDecoder().decode(ApprovalCiphertext.self, from: data)
            let key = try ICloudApprovalRootKey().load()
            let plaintext = try ApprovalCrypto(rootKeyData: key).open(envelope, purpose: "notification")
            let ticket = try JSONDecoder().decode(PhoneApprovalTicket.self, from: plaintext)
            content.threadIdentifier = ticket.requestID.uuidString
            if ticket.canceledAtMilliseconds != nil {
                content.title = "Approval canceled"
                let preferences = (try? ApprovalNotificationPreferences.load()) ?? .init()
                content.body = preferences.showsHost
                    ? "The request from \(ticket.macName) is no longer waiting."
                    : "The request is no longer waiting."
                content.categoryIdentifier = ""
                contentHandler(content)
                handler = nil
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
            contentHandler(content)
            handler = nil
        } catch {
            content.title = "Automic Vault update"
            content.body = "Open Automic Vault to review."
            content.categoryIdentifier = "AV_REVIEW"
            contentHandler(content)
            handler = nil
        }
    }

    override func serviceExtensionTimeWillExpire() {
        if let handler, let content { handler(content) }
        handler = nil
    }
}
