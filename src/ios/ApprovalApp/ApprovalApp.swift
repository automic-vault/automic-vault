import LocalAuthentication
import Observation
import SwiftUI
@preconcurrency import UserNotifications

@main
struct AutomicVaultApprovalApp: App {
    @UIApplicationDelegateAdaptor(ApprovalAppDelegate.self) private var delegate

    var body: some Scene {
        WindowGroup {
            ApprovalRootView(model: .shared, subscription: .shared)
                .tint(.purple)
                .task {
                    await ApprovalSubscription.shared.start()
                    await ApprovalModel.shared.start()
                }
        }
    }
}

final class ApprovalAppDelegate: NSObject, UIApplicationDelegate, @preconcurrency UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        Self.registerNotificationCategories()
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
        Task { await ApprovalModel.shared.register(deviceToken: token) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { ApprovalModel.shared.registrationFailed(error) }
    }

    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any]
    ) async -> UIBackgroundFetchResult {
        await ApprovalModel.shared.handleBackgroundNotification(userInfo)
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        Task {
            await ApprovalModel.shared.handleNotificationResponse(response)
            completionHandler()
        }
    }

    static func registerNotificationCategories() {
        let deny = UNNotificationAction(identifier: "AV_DENY", title: "Deny")
        let approvalOptions: UNNotificationActionOptions = ApprovalModel.biometricProtectionEnabled
            ? [.foreground, .authenticationRequired]
            : [.authenticationRequired]
        let approve = UNNotificationAction(
            identifier: "AV_APPROVE",
            title: "Approve Once",
            options: approvalOptions
        )
        let review = UNNotificationAction(
            identifier: "AV_REVIEW",
            title: "Review",
            options: [.foreground, .authenticationRequired]
        )
        UNUserNotificationCenter.current().setNotificationCategories([
            UNNotificationCategory(
                identifier: "AV_ROUTINE",
                actions: [deny, approve],
                intentIdentifiers: [],
                hiddenPreviewsBodyPlaceholder: "Approval details hidden"
            ),
            UNNotificationCategory(
                identifier: "AV_REVIEW",
                actions: [deny, review],
                intentIdentifiers: [],
                hiddenPreviewsBodyPlaceholder: "Approval details hidden"
            ),
        ])
    }
}

@MainActor @Observable
final class ApprovalModel {
    static let shared = ApprovalModel()
    static let biometricDefaultsKey = "approvalBiometricProtection"

    enum ConnectionState: Equatable {
        case setup
        case connecting
        case connected
        case unavailable(String)
        case reconnecting(String)
    }

    static var biometricProtectionEnabled: Bool {
        UserDefaults.standard.bool(forKey: biometricDefaultsKey)
    }

    private(set) var pending: [PhoneApprovalRequest] = []
    private(set) var activity: [PhoneApprovalActivity] = []
    private(set) var state: ConnectionState = .setup
    private(set) var notificationPreferences = ApprovalNotificationPreferences()
    private(set) var notificationReviewRequestID: UUID?
    private(set) var notificationReviewSequence: UInt64 = 0
    var errorMessage: String?
    var biometricProtectionEnabled = UserDefaults.standard.bool(forKey: biometricDefaultsKey) {
        didSet {
            UserDefaults.standard.set(biometricProtectionEnabled, forKey: Self.biometricDefaultsKey)
            ApprovalAppDelegate.registerNotificationCategories()
        }
    }

    private let endpoint = URL(string: Bundle.main.object(forInfoDictionaryKey: "ApprovalRelayURL") as? String ?? "")
    private let deviceID: String
    private var relay: ApprovalRelayClient?
    private var deviceToken: Data?
    private var receiveTask: Task<Void, Never>?
    private var started = false
    private var isConnecting = false
    private var reconnectDelay: UInt64 = 1

    private init() {
        if let existing = UserDefaults.standard.string(forKey: "approvalDeviceID") {
            deviceID = existing
        } else {
            let value = UUID().uuidString.lowercased()
            UserDefaults.standard.set(value, forKey: "approvalDeviceID")
            deviceID = value
        }
        do {
            activity = try PhoneApprovalActivityStore.load()
        } catch {
            errorMessage = "Request History could not be loaded."
        }
        notificationPreferences = (try? ApprovalNotificationPreferences.load()) ?? .init()
    }

    func start() async {
        guard !started else { return }
        started = true
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
            state = .setup
            return
        }
        UIApplication.shared.registerForRemoteNotifications()
        await connect()
    }

    func enable() async {
        guard await subscriptionPermits(.approved) else { return }
        guard ICloudApprovalRootKey.hasActiveICloudAccount() else {
            state = .unavailable("Sign in to iCloud and enable iCloud Keychain to use iPhone Approval.")
            return
        }
        do {
            guard try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) else {
                state = .unavailable("Notifications are required so Approval requests can reach this iPhone.")
                return
            }
            UIApplication.shared.registerForRemoteNotifications()
            await connect()
        } catch {
            state = .unavailable(error.localizedDescription)
        }
    }

    func register(deviceToken: Data) async {
        self.deviceToken = deviceToken
        await connect()
        await registerIfPossible()
    }

    func registrationFailed(_ error: Error) {
        state = .unavailable("Push registration failed: \(error.localizedDescription)")
    }

    func refresh() async {
        guard case .reconnecting = state else { return }
        reconnectDelay = 1
        await connect()
    }

    func approve(_ request: PhoneApprovalRequest) async {
        await approve(request, outcome: .approved)
    }

    func allowTemporaryWriteAccess(_ request: PhoneApprovalRequest) async {
        await approve(request, outcome: .temporaryWriteAccess)
    }

    private func approve(_ request: PhoneApprovalRequest, outcome: PhoneApprovalOutcome) async {
        if biometricProtectionEnabled {
            guard await authenticateBiometrically() else { return }
        }
        await respond(to: request, outcome: outcome)
    }

    func deny(_ request: PhoneApprovalRequest) async {
        await respond(to: request, outcome: .denied)
    }

    func denyAll() async {
        for request in pending { await deny(request) }
    }

    func setBiometricProtection(_ enabled: Bool) async {
        guard enabled != biometricProtectionEnabled else { return }
        let authenticated: Bool
        if enabled {
            authenticated = await authenticateBiometrically()
        } else {
            authenticated = await authenticateSecuritySettingChange()
        }
        guard authenticated else { return }
        biometricProtectionEnabled = enabled
    }

    func setNotificationHostVisible(_ enabled: Bool) {
        saveNotificationPreferences { $0.showsHost = enabled }
    }

    func setNotificationApprovalTypeVisible(_ enabled: Bool) {
        saveNotificationPreferences { $0.showsApprovalType = enabled }
    }

    func handleNotificationResponse(_ response: UNNotificationResponse) async {
        guard let ticket = await ticket(from: response.notification.request.content.userInfo) else { return }
        if let activity = PhoneApprovalActivity(canceled: ticket) {
            recordActivity(activity)
            pending.removeAll { $0.id == ticket.requestID }
            await removeDeliveredNotifications(for: ticket.requestID)
            return
        }
        switch response.actionIdentifier {
        case "AV_DENY": await respond(to: ticket, outcome: .denied)
        case "AV_APPROVE" where !ticket.requiresFullReview:
            if biometricProtectionEnabled {
                guard await authenticateBiometrically() else { return }
            }
            await respond(to: ticket, outcome: .approved)
        case "AV_REVIEW", UNNotificationDefaultActionIdentifier:
            notificationReviewRequestID = ticket.requestID
            notificationReviewSequence &+= 1
            if !pending.contains(where: { $0.id == ticket.requestID }) {
                if relay == nil { await connect() }
                if let relay { try? await relay.send(.sync) }
            }
        default: break
        }
    }

    func handleBackgroundNotification(_ userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult {
        guard let ticket = await ticket(from: userInfo),
              let activity = PhoneApprovalActivity(canceled: ticket) else { return .noData }
        recordActivity(activity)
        pending.removeAll { $0.id == ticket.requestID }
        await removeDeliveredNotifications(for: ticket.requestID)
        return .newData
    }

    private func connect() async {
        guard !isConnecting, receiveTask == nil, let endpoint else {
            if endpoint == nil { state = .unavailable("The Approval relay URL is invalid.") }
            return
        }
        isConnecting = true
        defer { isConnecting = false }
        do {
            state = .connecting
            let key = try ICloudApprovalRootKey().loadOrCreate()
            let relay = try ApprovalRelayClient(endpoint: endpoint, rootKeyData: key)
            try await relay.connect(peerID: "phone-\(deviceID)")
            self.relay = relay
            state = .connected
            try await relay.send(.sync)
            reconnectDelay = 1
            await registerIfPossible()
            receiveTask = Task { [weak self] in await self?.receive(relay) }
        } catch {
            if let relay { await relay.disconnect() }
            relay = nil
            scheduleReconnect("Relay unavailable: \(error.localizedDescription)")
        }
    }

    private func registerIfPossible() async {
        guard let relay, let deviceToken else { return }
        do {
            #if DEBUG
            let environment = ApprovalDeviceRegistration.Environment.sandbox
            #else
            let environment = ApprovalDeviceRegistration.Environment.production
            #endif
            try await relay.register(deviceID: deviceID, token: deviceToken, environment: environment)
            state = .connected
        } catch {
            state = .unavailable("Could not register this iPhone: \(error.localizedDescription)")
        }
    }

    private func receive(_ relay: ApprovalRelayClient) async {
        while !Task.isCancelled {
            do {
                switch try await relay.receive() {
                case .request(let request):
                    if !pending.contains(where: { $0.id == request.id }) { pending.append(request) }
                case .response(let response):
                    pending.removeAll { $0.id == response.requestID }
                    await removeDeliveredNotifications(for: response.requestID)
                case .cancel(let requestID):
                    if let request = pending.first(where: { $0.id == requestID }) {
                        recordActivity(.init(canceled: request))
                    }
                    pending.removeAll { $0.id == requestID }
                    await removeDeliveredNotifications(for: requestID)
                case .presence:
                    break
                case .sync:
                    break
                }
            } catch {
                await relay.disconnect()
                self.relay = nil
                receiveTask = nil
                scheduleReconnect("Relay disconnected. Reconnecting automatically…")
                return
            }
        }
    }

    private func respond(to request: PhoneApprovalRequest, outcome: PhoneApprovalOutcome) async {
        guard await subscriptionPermits(outcome) else { return }
        do {
            guard let relay else { throw ApprovalRelayClientError.disconnected }
            let response = try PhoneApprovalResponse(request: request, outcome: outcome, deviceID: deviceID)
            try await relay.send(.response(response))
            recordActivity(.init(request: request, outcome: outcome))
            pending.removeAll { $0.id == request.id }
            await removeDeliveredNotifications(for: request.id)
        } catch {
            errorMessage = "The response was not delivered. The request remains pending."
        }
    }

    private func respond(to ticket: PhoneApprovalTicket, outcome: PhoneApprovalOutcome) async {
        guard await subscriptionPermits(outcome) else { return }
        do {
            if relay == nil { await connect() }
            guard let relay else { throw ApprovalRelayClientError.disconnected }
            let response = try PhoneApprovalResponse(
                requestID: ticket.requestID,
                requestDigest: ticket.requestDigest,
                outcome: outcome,
                deviceID: deviceID
            )
            try await relay.send(.response(response))
            recordActivity(.init(ticket: ticket, outcome: outcome))
            pending.removeAll { $0.id == ticket.requestID }
            await removeDeliveredNotifications(for: ticket.requestID)
        } catch {
            errorMessage = "The response was not delivered. Open Automic Vault and try again."
        }
    }

    private func subscriptionPermits(_ outcome: PhoneApprovalOutcome) async -> Bool {
        if PhoneApprovalSubscriptionAccess.unavailable.permits(outcome) { return true }
        let access: PhoneApprovalSubscriptionAccess = await ApprovalSubscription.shared.refresh()
            ? .active
            : .unavailable
        guard access.permits(outcome) else {
            errorMessage = "An active iPhone Approval subscription is required to approve."
            return false
        }
        return true
    }

    private func ticket(from userInfo: [AnyHashable: Any]) async -> PhoneApprovalTicket? {
        do {
            guard let value = userInfo["av"] else { return nil }
            let data = try JSONSerialization.data(withJSONObject: value)
            let envelope = try JSONDecoder().decode(ApprovalCiphertext.self, from: data)
            let key = try ICloudApprovalRootKey().load()
            let plaintext = try ApprovalCrypto(rootKeyData: key).open(envelope, purpose: "notification")
            return try JSONDecoder().decode(PhoneApprovalTicket.self, from: plaintext)
        } catch {
            errorMessage = "This Approval notification could not be authenticated."
            return nil
        }
    }

    private func removeDeliveredNotifications(for requestID: UUID) async {
        let center = UNUserNotificationCenter.current()
        let identifiers = await center.deliveredNotifications()
            .filter { $0.request.content.threadIdentifier == requestID.uuidString }
            .map(\.request.identifier)
        center.removeDeliveredNotifications(withIdentifiers: identifiers)
    }

    private func authenticateBiometrically() async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            errorMessage = "Face ID or Touch ID is unavailable. Turn off biometric protection deliberately in Settings to approve without it."
            return false
        }
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Approve this Automic Vault request"
            )
        } catch {
            errorMessage = "Approval was not authenticated."
            return false
        }
    }

    private func authenticateSecuritySettingChange() async -> Bool {
        do {
            return try await LAContext().evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Turn off biometric protection for future Approvals"
            )
        } catch {
            errorMessage = "The security setting was not changed."
            return false
        }
    }

    private func scheduleReconnect(_ message: String) {
        state = .reconnecting(message)
        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, 30)
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            await self?.connect()
        }
    }

    private func saveNotificationPreferences(
        _ change: (inout ApprovalNotificationPreferences) -> Void
    ) {
        var preferences = notificationPreferences
        change(&preferences)
        do {
            try preferences.save()
            notificationPreferences = preferences
        } catch {
            errorMessage = "Notification detail settings could not be saved."
        }
    }

    private func recordActivity(_ item: PhoneApprovalActivity) {
        activity = PhoneApprovalActivity.adding(item, to: activity)
        do {
            try PhoneApprovalActivityStore.save(activity)
        } catch {
            errorMessage = "Request History could not be saved."
        }
    }

}

private enum PhoneApprovalActivityStore {
    static func load() throws -> [PhoneApprovalActivity] {
        let url = try fileURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return Array(try JSONDecoder().decode([PhoneApprovalActivity].self, from: Data(contentsOf: url))
            .prefix(PhoneApprovalActivity.maximumItems))
    }

    static func save(_ activity: [PhoneApprovalActivity]) throws {
        try JSONEncoder().encode(activity).write(
            to: fileURL(),
            options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        )
    }

    private static func fileURL() throws -> URL {
        let directory = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appending(path: "iPhone Activity", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        )
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: directory.path
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var protectedDirectory = directory
        try protectedDirectory.setResourceValues(values)
        return directory.appending(path: "responses.json")
    }
}
