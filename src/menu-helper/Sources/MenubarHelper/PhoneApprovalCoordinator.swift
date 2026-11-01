import AppKit
import ApprovalCore
import Foundation
import LocalAuthentication
import MenubarHelperCore
import Security

let phoneApprovalEnabledDefaultsKey = "phoneApprovalEnabled"
private let phoneApprovalMacIDDefaultsKey = "phoneApprovalMacID"
private let phoneApprovalRelayURL = URL(string: "https://approval-relay.automicvault.com")!

nonisolated func phoneApprovalIsEnabled() -> Bool {
    UserDefaults.standard.bool(forKey: phoneApprovalEnabledDefaultsKey)
}

enum PhoneApprovalResult: Sendable {
    case approved
    case denied
    case temporaryWriteAccess
    case temporaryDenial
    case canceled
}

enum TouchIDApprovalError: LocalizedError {
    case unavailable
    case authenticationFailed
    case storage(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unavailable:
            "Touch ID is unavailable or not enrolled on this Mac."
        case .authenticationFailed:
            "Touch ID authentication was canceled or failed."
        case .storage(let status):
            "Could not update Touch ID Approval: \(SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)")"
        }
    }
}

@MainActor
enum TouchIDApproval {
    static var isEnabled: Bool { touchIDApprovalIsEnabled() }

    static var isAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
            && context.biometryType == .touchID
    }

    static func authenticate(reason: String, context: LAContext = LAContext()) async -> Bool {
        // Only main-window actions use this overload; background Approval panels
        // use the callback API and must not activate the app when they finish.
        weak var originatingWindow = NSApp.isActive ? NSApp.keyWindow as? AutomicVaultWindow : nil
        let approved = await withCheckedContinuation { continuation in
            authenticate(reason: reason, context: context) { approved in
                continuation.resume(returning: approved)
            }
        }
        if approved, let window = originatingWindow,
           window.isVisible, !window.isMiniaturized, !NSApp.isHidden {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        return approved
    }

    static func authenticate(
        reason: String,
        context: LAContext = LAContext(),
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
              context.biometryType == .touchID
        else {
            completion(false)
            return
        }
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        ) { approved, _ in
            RunLoop.main.perform(inModes: [.modalPanel, .default]) {
                MainActor.assumeIsolated {
                    completion(approved)
                }
            }
        }
    }

    static func enable() async throws {
        guard isAvailable else { throw TouchIDApprovalError.unavailable }
        guard await authenticate(reason: "Enable Touch ID Approval on this Mac") else {
            throw TouchIDApprovalError.authenticationFailed
        }
        let status = setTouchIDApprovalEnabled(true)
        guard status == errSecSuccess else { throw TouchIDApprovalError.storage(status) }
        Task { @MainActor in
            abortActiveApprovalPrompt()
        }
    }

    static func disable() throws {
        let status = setTouchIDApprovalEnabled(false)
        guard status == errSecSuccess else { throw TouchIDApprovalError.storage(status) }
        Task { @MainActor in
            abortActiveApprovalPrompt()
        }
    }
}

enum PhoneApprovalSetupError: LocalizedError {
    case iCloudUnavailable
    case noRegisteredPhone
    case pendingLimit

    var errorDescription: String? {
        switch self {
        case .iCloudUnavailable:
            "Sign in to iCloud and enable iCloud Keychain before enabling iPhone Approval."
        case .noRegisteredPhone:
            "No iPhone has registered recently. Open Automic Vault on an iPhone using this iCloud account, allow notifications, then try again."
        case .pendingLimit:
            "This Mac already has 100 pending iPhone Approvals."
        }
    }
}

private actor PhoneApprovalRelayWorker {
    typealias ResultHandler = @Sendable (UUID, PhoneApprovalResult) -> Void

    private let macID: String
    private let resultHandler: ResultHandler
    private var generation: UInt64
    private var pending: [UUID: PhoneApprovalRequest] = [:]
    private var cancellations: [UUID: PhoneApprovalRequest] = [:]
    private var canceled: Set<UUID> = []
    private var published: Set<UUID> = []
    private var relay: ApprovalRelayClient?
    private var connectionTask: Task<Void, Never>?
    private var connectionID: UUID?

    init(macID: String, generation: UInt64, resultHandler: @escaping ResultHandler) {
        self.macID = macID
        self.generation = generation
        self.resultHandler = resultHandler
    }

    func start(generation: UInt64) async {
        guard generation >= self.generation else { return }
        if generation > self.generation { await reset(generation: generation) }
    }

    func submit(_ request: PhoneApprovalRequest, generation: UInt64) async {
        guard self.generation == generation,
              canceled.remove(request.id) == nil else { return }
        pending[request.id] = request
        startConnectionIfNeeded()
        guard let relay else { return }
        do {
            try await publishIfNeeded(request, relay: relay)
        } catch {
            await relay.disconnect()
        }
    }

    func cancel(_ requestID: UUID, generation: UInt64) async {
        guard self.generation == generation else { return }
        canceled.insert(requestID)
        guard let request = pending.removeValue(forKey: requestID) else { return }
        canceled.remove(requestID)
        published.remove(requestID)
        cancellations[requestID] = request
        startConnectionIfNeeded()
        if let relay {
            do {
                try await publishCancellationIfNeeded(request, relay: relay)
            } catch {
                await relay.disconnect()
            }
        }
        await disconnectIfIdle()
    }

    func stop(generation: UInt64) async {
        guard generation >= self.generation else { return }
        await reset(generation: generation)
    }

    private func reset(generation: UInt64) async {
        self.generation = generation
        connectionID = nil
        connectionTask?.cancel()
        connectionTask = nil
        if let relay { await relay.disconnect() }
        relay = nil
        pending.removeAll()
        cancellations.removeAll()
        canceled.removeAll()
        published.removeAll()
    }

    private func startConnectionIfNeeded() {
        guard hasWork, connectionTask == nil else { return }
        let connectionID = UUID()
        self.connectionID = connectionID
        connectionTask = Task { [weak self] in
            await self?.runConnection(connectionID: connectionID)
        }
    }

    private func runConnection(connectionID: UUID) async {
        var retrySeconds: UInt64 = 1
        while self.connectionID == connectionID && !Task.isCancelled && hasWork {
            var activeRelay: ApprovalRelayClient?
            var heartbeatTask: Task<Void, Never>?
            do {
                let key = try ICloudApprovalRootKey().loadOrCreate()
                let relay = try ApprovalRelayClient(endpoint: phoneApprovalRelayURL, rootKeyData: key)
                activeRelay = relay
                try await relay.connect(peerID: "mac-\(macID)")
                guard self.connectionID == connectionID, hasWork else {
                    await relay.disconnect()
                    return
                }
                self.relay = relay
                published.removeAll()
                try await relay.send(.presence(try presence()))
                for request in Array(pending.values) {
                    try await publishIfNeeded(request, relay: relay)
                }
                for request in Array(cancellations.values) {
                    try await publishCancellationIfNeeded(request, relay: relay)
                }
                retrySeconds = 1
                heartbeatTask = Task { [weak self] in
                    await self?.maintainConnection(relay, connectionID: connectionID)
                }
                while self.connectionID == connectionID && !Task.isCancelled && hasWork {
                    try await handle(try await relay.receive(), relay: relay)
                }
            } catch {}

            heartbeatTask?.cancel()
            if self.connectionID == connectionID {
                self.relay = nil
                published.removeAll()
            }
            if let activeRelay { await activeRelay.disconnect() }
            guard self.connectionID == connectionID,
                  !Task.isCancelled,
                  hasWork else { break }
            try? await Task.sleep(for: .seconds(retrySeconds))
            retrySeconds = min(retrySeconds * 2, 30)
        }
        if self.connectionID == connectionID {
            self.relay = nil
            self.connectionID = nil
            connectionTask = nil
            published.removeAll()
            startConnectionIfNeeded()
        }
    }

    private func publishIfNeeded(
        _ request: PhoneApprovalRequest,
        relay: ApprovalRelayClient
    ) async throws {
        guard pending[request.id] != nil, published.insert(request.id).inserted else { return }
        do {
            try await relay.publish(request)
        } catch {
            published.remove(request.id)
            throw error
        }
    }

    private func publishCancellationIfNeeded(
        _ request: PhoneApprovalRequest,
        relay: ApprovalRelayClient
    ) async throws {
        guard cancellations[request.id] != nil else { return }
        try await relay.publishCancellation(request)
        cancellations.removeValue(forKey: request.id)
    }

    private func maintainConnection(
        _ relay: ApprovalRelayClient,
        connectionID: UUID
    ) async {
        do {
            while self.connectionID == connectionID && !Task.isCancelled && hasWork {
                try await Task.sleep(for: .seconds(30))
                guard self.connectionID == connectionID,
                      !Task.isCancelled,
                      hasWork else { return }
                try await relay.ping()
            }
        } catch is CancellationError {
            return
        } catch {
            await relay.disconnect()
        }
    }

    private func disconnectIfIdle() async {
        guard !hasWork else { return }
        connectionID = nil
        connectionTask?.cancel()
        connectionTask = nil
        let relay = self.relay
        self.relay = nil
        published.removeAll()
        if let relay { await relay.disconnect() }
    }

    private var hasWork: Bool { !pending.isEmpty || !cancellations.isEmpty }

    private func handle(_ message: ApprovalWireMessage, relay: ApprovalRelayClient) async throws {
        switch message {
        case .response(let response):
            guard let request = pending[response.requestID] else { return }
            try response.validate(for: request)
            pending.removeValue(forKey: response.requestID)
            published.remove(response.requestID)
            let result: PhoneApprovalResult = switch response.outcome {
            case .approved: .approved
            case .denied: .denied
            case .temporaryWriteAccess: .temporaryWriteAccess
            case .temporaryDenial: .temporaryDenial
            }
            resultHandler(response.requestID, result)
        case .sync:
            try await relay.send(.presence(try presence()))
            for request in pending.values { try await relay.send(.request(request)) }
        case .request, .cancel, .presence:
            return
        }
    }

    private func presence() throws -> ApprovalMacPresence {
        try ApprovalMacPresence(
            macID: macID,
            macName: Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        )
    }
}

@MainActor
final class PhoneApprovalCoordinator {
    static let shared = PhoneApprovalCoordinator()

    var isEnabled: Bool { phoneApprovalIsEnabled() }
    var pendingCount: Int { pending.count }

    private struct Pending {
        let completion: (PhoneApprovalResult) -> Void
    }

    private let macID: String
    private var workerGeneration: UInt64 = 0
    private var pending: [UUID: Pending] = [:]
    private lazy var worker = PhoneApprovalRelayWorker(
        macID: macID,
        generation: workerGeneration
    ) { [weak self] requestID, result in
        RunLoop.main.perform(inModes: [.modalPanel, .default]) { [weak self] in
            MainActor.assumeIsolated {
                self?.finish(requestID, with: result)
            }
        }
    }

    private init() {
        if let existing = UserDefaults.standard.string(forKey: phoneApprovalMacIDDefaultsKey) {
            macID = existing
        } else {
            let value = UUID().uuidString.lowercased()
            UserDefaults.standard.set(value, forKey: phoneApprovalMacIDDefaultsKey)
            macID = value
        }
    }

    func registrationStatus() async throws -> ApprovalRegistrationStatus {
        guard ICloudApprovalRootKey.hasActiveICloudAccount() else {
            throw PhoneApprovalSetupError.iCloudUnavailable
        }
        let key = try ICloudApprovalRootKey().loadOrCreate()
        return try await ApprovalRelayClient(
            endpoint: phoneApprovalRelayURL,
            rootKeyData: key
        ).registrationStatus()
    }

    func enable() async throws {
        guard try await registrationStatus().count > 0 else {
            throw PhoneApprovalSetupError.noRegisteredPhone
        }
        UserDefaults.standard.set(true, forKey: phoneApprovalEnabledDefaultsKey)
        workerGeneration += 1
        await worker.start(generation: workerGeneration)
        Task { @MainActor in
            abortActiveApprovalPrompt()
        }
    }

    func submit(
        _ request: PhoneApprovalRequest,
        completion: @escaping (PhoneApprovalResult) -> Void
    ) throws {
        guard pending.count < 100 else { throw PhoneApprovalSetupError.pendingLimit }
        pending[request.id] = Pending(completion: completion)
        let worker = worker
        let generation = workerGeneration
        Task { @concurrent in
            await worker.submit(request, generation: generation)
        }
    }

    @discardableResult
    func approveAuthorityChange(
        title: String,
        detail: String,
        completion: @escaping (Bool) -> Void
    ) -> UUID? {
        guard isEnabled else {
            completion(true)
            return nil
        }
        do {
            let request = try PhoneApprovalRequest(
                macName: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
                launcher: "Automic Vault",
                tool: "Settings",
                command: title,
                cwd: NSHomeDirectory(),
                secretNames: [],
                reason: detail,
                risks: [.securityWarning],
                details: [ApprovalDetailSection(
                    title: "Authority Change",
                    rows: [.init(label: "Change", value: title), .init(label: "Effect", value: detail)]
                )]
            )
            try submit(request) { result in completion(result == .approved) }
            return request.id
        } catch {
            completion(false)
            return nil
        }
    }

    func cancel(_ requestID: UUID) {
        guard let item = pending.removeValue(forKey: requestID) else { return }
        item.completion(.canceled)
        let worker = worker
        let generation = workerGeneration
        Task { @concurrent in
            await worker.cancel(requestID, generation: generation)
        }
    }

    func disableAfterPhoneApproval() {
        UserDefaults.standard.set(false, forKey: phoneApprovalEnabledDefaultsKey)
        stopConnection(cancelPending: true)
        Task { @MainActor in
            abortActiveApprovalPrompt()
        }
    }

    func recoverWithoutIPhone() async throws {
        let context = LAContext()
        guard try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Disable iPhone Approval and invalidate every enrolled device"
        ) else { return }
        let keyStore = ICloudApprovalRootKey()
        let oldKey = try keyStore.load()
        try await ApprovalRelayClient(endpoint: phoneApprovalRelayURL, rootKeyData: oldKey).revokeRoom()
        _ = try keyStore.rotate()
        UserDefaults.standard.set(false, forKey: phoneApprovalEnabledDefaultsKey)
        stopConnection(cancelPending: true)
        Task { @MainActor in
            abortActiveApprovalPrompt()
        }
    }

    private func finish(_ requestID: UUID, with result: PhoneApprovalResult) {
        guard let item = pending.removeValue(forKey: requestID) else { return }
        item.completion(result)
    }

    private func stopConnection(cancelPending: Bool) {
        let worker = worker
        workerGeneration += 1
        let generation = workerGeneration
        Task { @concurrent in
            await worker.stop(generation: generation)
        }
        if cancelPending {
            let items = Array(pending.values)
            pending.removeAll()
            items.forEach { $0.completion(.canceled) }
        }
    }
}

@MainActor
@discardableResult
func requestAuthorityChangeApproval(
    title: String,
    detail: String,
    completion: @escaping (Bool) -> Void
) -> UUID? {
    if TouchIDApproval.isEnabled {
        if TouchIDApproval.isAvailable {
            Task {
                completion(await TouchIDApproval.authenticate(
                    reason: "\(title)\n\n\(detail)"
                ))
            }
            return nil
        }
        guard PhoneApprovalCoordinator.shared.isEnabled else {
            completion(false)
            return nil
        }
    }
    return PhoneApprovalCoordinator.shared.approveAuthorityChange(
        title: title,
        detail: detail,
        completion: completion
    )
}

#if DEBUG
private final class FocusCheckContext: LAContext {
    let approved: Bool
    let beforeReply: @MainActor @Sendable () -> Void

    init(approved: Bool = true, beforeReply: @escaping @MainActor @Sendable () -> Void = {}) {
        self.approved = approved
        self.beforeReply = beforeReply
        super.init()
    }

    override var biometryType: LABiometryType { .touchID }
    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool { true }
    override func evaluatePolicy(
        _ policy: LAPolicy, localizedReason: String,
        reply: @escaping @Sendable (Bool, (any Error)?) -> Void
    ) {
        let approved = approved
        let beforeReply = beforeReply
        Task { @MainActor in
            // Simulate the system prompt handing key focus to another window.
            NSApp.windows.first { $0.title == "Focus check cover" }?.makeKeyAndOrderFront(nil)
            beforeReply()
            reply(approved, nil)
        }
    }
}

@MainActor
func touchIDWindowFocusSelfCheck() async -> Bool {
    NSApp.setActivationPolicy(.accessory)
    let window = AutomicVaultWindow(contentRect: NSRect(x: 0, y: 0, width: 200, height: 100),
        styleMask: [.titled, .closable], backing: .buffered, defer: false)
    let cover = NSWindow(contentRect: window.frame, styleMask: .titled, backing: .buffered, defer: false)
    cover.title = "Focus check cover"
    window.isReleasedWhenClosed = false
    cover.isReleasedWhenClosed = false
    defer { window.close(); cover.close() }
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
    let deadline = Date().addingTimeInterval(3)
    while !NSApp.isActive && Date() < deadline { try? await Task.sleep(for: .milliseconds(10)) }
    window.makeKeyAndOrderFront(nil)
    guard NSApp.keyWindow === window else {
        fputs("Focus check could not establish the originating window\n", stderr)
        return false
    }
    let approved = await TouchIDApproval.authenticate(reason: "Focus self-check", context: FocusCheckContext())
    guard approved, NSApp.keyWindow === window else {
        fputs("Touch ID completion did not restore the originating main window\n", stderr)
        return false
    }
    // The callback API used by Approval panels must never restore the main window.
    let panelApproved = await withCheckedContinuation { continuation in
        TouchIDApproval.authenticate(reason: "Panel focus self-check", context: FocusCheckContext()) {
            continuation.resume(returning: $0)
        }
    }
    guard panelApproved, NSApp.keyWindow === cover else { return false }
    let noOrigin = await TouchIDApproval.authenticate(reason: "No main-window origin", context: FocusCheckContext())
    guard noOrigin, NSApp.keyWindow === cover else { return false }
    window.makeKeyAndOrderFront(nil)
    let canceled = await TouchIDApproval.authenticate(reason: "Canceled", context: FocusCheckContext(approved: false))
    guard !canceled, NSApp.keyWindow === cover else { return false }
    window.makeKeyAndOrderFront(nil)
    let closed = await TouchIDApproval.authenticate(reason: "Closed origin", context: FocusCheckContext {
        window.close()
    })
    return closed && !window.isVisible && NSApp.keyWindow === cover
}
#endif
