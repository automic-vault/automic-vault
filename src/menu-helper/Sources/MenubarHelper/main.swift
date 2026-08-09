import AppKit
import AppUpdater
import CProcessInfo
import CoreServices
import CryptoKit
import Darwin
import Foundation
import MenubarHelperCore
import Security
import SwiftUI
@preconcurrency import XPC

private let approvalServiceName = "com.automicvault.av2.approval"
private let approvalLaunchAgentName = "com.automicvault.menubar-helper"
private let openMainWindowArgument = "--open-main-window"
private let pendingMainWindowKey = "pendingMainWindow"
private let pendingSecretGateKey = "pendingSecretGate"
let secCodeSignatureAdHoc: UInt32 = 0x2
private let transientApprovalTTL: TimeInterval = 5 * 60
private let scanMaximumDelay: TimeInterval = 5
private let scanQueue = DispatchQueue(label: "com.automicvault.av2.scan")
private let updateCheckInterval: Duration = .seconds(24 * 60 * 60)
private var toastWindows: [NSWindow] = []

private enum AutomaticApprovalFlashSide {
    case left
    case right

    var next: Self { self == .left ? .right : .left }
}

@MainActor
private func makeUpdater(
    sessionConfiguration: URLSessionConfiguration = .default
) -> AppUpdater {
    AppUpdater(
        owner: "automic-vault",
        repo: "automic-vault",
        configuration: .init(
            attestationPolicy: GitHubAttestationPolicy(
                workflow: ".github/workflows/release.yml",
                sourceRef: "refs/heads/main"
            )
        ),
        sessionConfiguration: sessionConfiguration
    )
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let visibleAutoApprovalCount = 5
    private lazy var statusItem = NSStatusBar.system.statusItem(withLength: 15)
    private lazy var scanStatusItem = makeStatusMenuItem(title: "Scan pending")
    private lazy var doctorStatusItem: NSMenuItem = {
        let item = makeStatusMenuItem(title: "")
        item.isHidden = true
        return item
    }()
    private lazy var checkForUpdatesItem = NSMenuItem(
        title: "Check for Updates…",
        action: #selector(checkForUpdates),
        keyEquivalent: ""
    )
    private lazy var installCLIItem = NSMenuItem(
        title: "Install av-cli",
        action: #selector(installCLI),
        keyEquivalent: ""
    )
    private lazy var quitItem = NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q")
    private lazy var quitSeparator = NSMenuItem.separator()
    private var autoApprovalItems: [NSMenuItem] = []
    private var autoApprovalSeparator: NSMenuItem?
    private var autoApprovals: [AutoApprovalRecord] = []
    private let autoApprovalTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.timeStyle = .short
        formatter.dateStyle = .none
        return formatter
    }()
    private var approval: ApprovalServer?
    private var scanWorkItem: DispatchWorkItem?
    private var scanBurstStartedAt: TimeInterval?
    private var eventStream: FSEventStreamRef?
    private var mainWindow: NSWindow?
    private var isUserSessionActive = true
    private var areScreensAwake = true
    private let updater = makeUpdater()
    private var automaticUpdateCheckTask: Task<Void, Never>?
    private var readyUpdate: Update?
    private var isCheckingForUpdates = false
    private var isUpdating = false
    private var menuBeforeUpdate: NSMenu?
    private var automaticApprovalFlashWorkItem: DispatchWorkItem?
    private var preFlashStatusImage: NSImage?
    private var lastAutomaticApprovalFlashSide = AutomaticApprovalFlashSide.right
    private var isStartingUp = false
    #if !DEBUG
    private let postHogTelemetry = PostHogTelemetry.shared
    private var lastTelemetryFindingCount: Int?
    #endif

    func applicationDidFinishLaunching(_ notification: Notification) {
        installStatusMenu()

        if shouldHandOffToLaunchAgent() {
            if shouldOpenMainWindow(pending: false) {
                UserDefaults.standard.set(true, forKey: pendingMainWindowKey)
            }
            if let secretGateID = requestedSecretGateID(arguments: CommandLine.arguments) {
                UserDefaults.standard.set(secretGateID, forKey: pendingSecretGateKey)
            }
            handOffToLaunchAgent()
            return
        }

        startServicesAndOpenMainWindowIfRequested()
        startAutomaticUpdateChecks()
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        let center = NSWorkspace.shared.notificationCenter
        center.addObserver(
            self,
            selector: #selector(userSessionDidResignActive(_:)),
            name: NSWorkspace.sessionDidResignActiveNotification,
            object: nil
        )
        center.addObserver(
            self,
            selector: #selector(userSessionDidBecomeActive(_:)),
            name: NSWorkspace.sessionDidBecomeActiveNotification,
            object: nil
        )
        center.addObserver(
            self,
            selector: #selector(screensDidSleep(_:)),
            name: NSWorkspace.screensDidSleepNotification,
            object: nil
        )
        center.addObserver(
            self,
            selector: #selector(screensDidWake(_:)),
            name: NSWorkspace.screensDidWakeNotification,
            object: nil
        )
    }

    @objc private func userSessionDidResignActive(_ notification: Notification) {
        isUserSessionActive = false
        if NSApp.modalWindow is ApprovalPanel {
            NSApp.abortModal()
        }
    }

    @objc private func userSessionDidBecomeActive(_ notification: Notification) {
        isUserSessionActive = true
        _ = migrateBackgroundKeychainItems()
    }

    @objc private func screensDidSleep(_ notification: Notification) {
        areScreensAwake = false
        if NSApp.modalWindow is ApprovalPanel {
            NSApp.abortModal()
        }
    }

    @objc private func screensDidWake(_ notification: Notification) {
        areScreensAwake = true
    }

    private func installStatusMenu() {
        statusItem.button?.image = brandImage()

        let menu = NSMenu()
        menu.addItem(scanStatusItem)
        menu.addItem(doctorStatusItem)
        menu.addItem(.separator())
        checkForUpdatesItem.target = self
        menu.addItem(checkForUpdatesItem)
        menu.addItem(.separator())
        let openItem = NSMenuItem(title: "Open Automic Vault", action: #selector(openMainWindow), keyEquivalent: "")
        setVersionBadge(appVersion(), on: openItem)
        openItem.target = self
        menu.addItem(openItem)
        installCLIItem.target = self
        installCLIItem.isHidden = FileManager.default.fileExists(atPath: installedAVCLIPath)
        menu.addItem(installCLIItem)
        menu.addItem(quitSeparator)
        menu.addItem(quitItem)
        menu.delegate = self
        statusItem.menu = menu
    }

    private func handOffToLaunchAgent() {
        isStartingUp = true
        statusItem.button?.image = brandImage()
        statusItem.button?.alphaValue = 0.5
        setStatusMenuItemTitle("Starting Automic Vault", on: scanStatusItem)
        updateMenuVisibility(
            statusItem.menu?.items ?? [],
            startingUp: true,
            visibleDuringStartup: [scanStatusItem, quitSeparator, quitItem]
        )
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try handOffToLaunchAgentIfNeeded() }
            DispatchQueue.main.async {
                switch result {
                case .success(true):
                    NSApp.terminate(nil)
                case .success(false):
                    self.startServicesAndOpenMainWindowIfRequested()
                case .failure(let error):
                    UserDefaults.standard.removeObject(forKey: pendingMainWindowKey)
                    UserDefaults.standard.removeObject(forKey: pendingSecretGateKey)
                    NSAlert(error: error).runModal()
                    NSApp.terminate(nil)
                }
            }
        }
    }

    private func consumePendingMainWindow() -> Bool {
        guard UserDefaults.standard.bool(forKey: pendingMainWindowKey) else { return false }
        UserDefaults.standard.removeObject(forKey: pendingMainWindowKey)
        return true
    }

    private func consumePendingSecretGate() -> String? {
        guard let id = UserDefaults.standard.string(forKey: pendingSecretGateKey) else { return nil }
        UserDefaults.standard.removeObject(forKey: pendingSecretGateKey)
        return validSecretGateID(id) ? id : nil
    }

    private func startServicesAndOpenMainWindowIfRequested() {
        startServices()
        let secretGateID = consumePendingSecretGate()
        let shouldOpen = shouldOpenMainWindow(pending: consumePendingMainWindow())
        if secretGateID != nil || shouldOpen {
            showMainWindow(secretGateID: secretGateID)
        }
    }

    private func startServices() {
        if isStartingUp {
            isStartingUp = false
            updateMenuVisibility(
                statusItem.menu?.items ?? [],
                startingUp: false,
                visibleDuringStartup: []
            )
            doctorStatusItem.isHidden = doctorStatusItem.title.isEmpty
            installCLIItem.isHidden = FileManager.default.fileExists(atPath: installedAVCLIPath)
        }
        statusItem.button?.image = brandImage()
        statusItem.button?.alphaValue = 1
        _ = migrateBackgroundKeychainItems()
        autoApprovals = loadAccessRequestRecords().compactMap(autoApprovalRecord)
        refreshAutoApprovalMenuItems()
        refreshCLIInstallState()
        do {
            let approval = try ApprovalServer(serviceName: approvalServiceName) { [weak self] event in
                self?.recordAutoApproval(event)
            } onAccessRequest: { [weak self] record in
                let recorded = appendAccessRequestRecord(record)
                if recorded {
                    Task { @MainActor in self?.didRecordAccessRequest(record) }
                }
                return recorded
            } onBlessRequest: { [weak self] request, completion in
                guard let self else {
                    completion("Automic Vault is unavailable")
                    return
                }
                guard !self.isUpdating else {
                    completion("Automic Vault is updating")
                    return
                }
                self.showMainWindow(secretGateID: nil)
                guard let controller = self.mainWindow?.contentViewController
                    as? AutomicVaultMainWindowController
                else {
                    completion("Automic Vault could not open the blessing review")
                    return
                }
                controller.reviewBlessing(request, completion: completion)
            } canRequestHumanApproval: { [weak self] in
                self?.isUserSessionActive == true && self?.areScreensAwake == true
            }
            try approval.start()
            self.approval = approval
            scheduleScan(after: 0)
            startHomeWatcher()
        } catch {
            NSAlert(error: error).runModal()
            NSApp.terminate(nil)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        automaticUpdateCheckTask?.cancel()
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        stopServices()
    }

    private func stopServices() {
        automaticApprovalFlashWorkItem?.cancel()
        automaticApprovalFlashWorkItem = nil
        preFlashStatusImage = nil
        scanWorkItem?.cancel()
        scanWorkItem = nil
        scanBurstStartedAt = nil
        if let eventStream {
            FSEventStreamStop(eventStream)
            FSEventStreamInvalidate(eventStream)
            FSEventStreamRelease(eventStream)
            self.eventStream = nil
        }
        approval?.stop()
        approval = nil
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openMainWindow()
        return true
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        if urls.contains(where: isCLIInstallCompletionURL) {
            refreshCLIInstallState()
            (mainWindow?.contentViewController as? AutomicVaultMainWindowController)?.reload()
        }
        guard let secretGateID = urls.lazy.compactMap(secretGateID(from:)).first else { return }
        if shouldHandOffToLaunchAgent() {
            UserDefaults.standard.set(true, forKey: pendingMainWindowKey)
            UserDefaults.standard.set(secretGateID, forKey: pendingSecretGateKey)
            return
        }
        showMainWindow(secretGateID: secretGateID)
    }

    @MainActor @objc private func quit() {
        NSApp.terminate(nil)
    }

    @MainActor @objc private func checkForUpdates() {
        guard !isStartingUp else { return }
        guard !isCheckingForUpdates else { return }
        isCheckingForUpdates = true
        updateCheckControls()

        Task { @MainActor [weak self] in
            await self?.performUpdateCheck()
        }
    }

    @MainActor @objc private func installCLI() {
        guard !isStartingUp else { return }
        do {
            try openCLIInstaller()
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    private func performUpdateCheck() async {
        var stoppedServices = false
        var updatingAlert: NSAlert?
        var restoreMainWindow = false
        defer {
            if let updatingAlert {
                finishUpdating(with: updatingAlert)
            }
            isCheckingForUpdates = false
            updateCheckControls()
        }

        do {
            let update = if let readyUpdate {
                readyUpdate
            } else {
                try await updater.check()
            }
            guard let update else {
                readyUpdate = nil
                let alert = NSAlert()
                alert.messageText = "Automic Vault is up to date"
                alert.runModal()
                return
            }
            readyUpdate = update

            let alert = NSAlert()
            alert.messageText = "An update is ready"
            alert.informativeText = "Install \(update.assetName) and relaunch Automic Vault?"
            alert.addButton(withTitle: "Install and Relaunch")
            alert.addButton(withTitle: "Later")
            guard alert.runModal() == .alertFirstButtonReturn else { return }

            readyUpdate = nil
            restoreMainWindow = beginUpdating(with: alert)
            updatingAlert = alert
            let prepared = try await update.prepareInstallation()
            stopServices()
            stoppedServices = true
            scanQueue.sync {}
            try await prepared.installAndRelaunch()
        } catch {
            if let alert = updatingAlert {
                finishUpdating(with: alert)
                updatingAlert = nil
            }
            if stoppedServices {
                startServices()
            }
            if restoreMainWindow {
                showMainWindow(secretGateID: nil)
            }
            showUpdateError(error)
        }
    }

    private func beginUpdating(with alert: NSAlert) -> Bool {
        let mainWindowWasVisible = mainWindow?.isVisible == true
        mainWindow?.orderOut(nil)
        isUpdating = true
        statusItem.button?.alphaValue = 0.5
        menuBeforeUpdate = statusItem.menu
        statusItem.menu = makeUpdatingMenu()

        configureUpdatingAlert(alert)
        alert.window.center()
        alert.window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        return mainWindowWasVisible
    }

    private func finishUpdating(with alert: NSAlert) {
        alert.window.orderOut(nil)
        statusItem.menu = menuBeforeUpdate
        menuBeforeUpdate = nil
        statusItem.button?.alphaValue = 1
        isUpdating = false
    }

    private func showUpdateError(_ error: Error) {
        guard let updaterError = error as? AppUpdaterError,
              updaterError == .attestationVerificationFailed
        else {
            NSAlert(error: error).runModal()
            return
        }

        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = updateVerificationFailureText
        alert.addButton(withTitle: "Search GitHub Issues")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            NSWorkspace.shared.open(updateVerificationIssuesURL)
        }
    }

    private func startAutomaticUpdateChecks() {
        automaticUpdateCheckTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshAvailableUpdate()
                do {
                    try await Task.sleep(for: updateCheckInterval)
                } catch {
                    return
                }
            }
        }
    }

    private func refreshAvailableUpdate() async {
        guard !isCheckingForUpdates else { return }
        do {
            readyUpdate = try await updater.check()
            updateCheckControls()
        } catch {
            // A transient metadata failure must not hide an update already found.
        }
    }

    private func updateCheckControls() {
        checkForUpdatesItem.title = if isCheckingForUpdates {
            "Checking for Updates…"
        } else if let readyUpdate {
            "Update to v\(readyUpdate.version)…"
        } else {
            "Check for Updates…"
        }
        checkForUpdatesItem.isEnabled = !isCheckingForUpdates
        (mainWindow?.contentViewController as? AutomicVaultMainWindowController)?
            .setAvailableUpdateVersion(readyUpdate?.version)
    }

    @MainActor @objc private func openMainWindow() {
        guard !isStartingUp, !isUpdating else { return }
        showMainWindow(secretGateID: nil)
    }

    @MainActor private func showMainWindow(secretGateID: String?) {
        guard !isUpdating else { return }
        let wasVisible = mainWindow?.isVisible ?? false
        if let mainWindow {
            mainWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            if let secretGateID {
                (mainWindow.contentViewController as? AutomicVaultMainWindowController)?
                    .showSecretGate(id: secretGateID)
            }
            #if !DEBUG
            if wasVisible == false {
                postHogTelemetry.captureMainWindowOpened()
            }
            #endif
            return
        }

        let controller = AutomicVaultMainWindowController { [weak self] in
            self?.checkForUpdates()
        }
        controller.setAvailableUpdateVersion(readyUpdate?.version)
        let defaultWindowSize = NSSize(width: 860, height: 578)
        let window = AutomicVaultWindow(
            contentRect: NSRect(origin: .zero, size: defaultWindowSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.contentViewController = controller
        window.title = "Automic Vault"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.titlebarSeparatorStyle = .none
        window.toolbarStyle = .automatic
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 860, height: 558)
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.mainWindow = window
        if let secretGateID {
            controller.showSecretGate(id: secretGateID)
        }
        NSApp.activate(ignoringOtherApps: true)
        window.setContentSize(defaultWindowSize)
        window.center()
        #if !DEBUG
        postHogTelemetry.captureMainWindowOpened()
        #endif
    }

    @MainActor @objc private func openAutoApproval(_ sender: NSMenuItem) {
        guard let idString = sender.representedObject as? String,
              let id = UUID(uuidString: idString)
        else { return }
        showAutoApproval(id: id)
    }

    private func showAutoApproval(id: UUID) {
        openMainWindow()
        (mainWindow?.contentViewController as? AutomicVaultMainWindowController)?.showAccessRequest(id: id)
    }

    private func startHomeWatcher() {
        // ponytail: one home FSEvents stream; add detector path metadata if rescans get noisy.
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
            guard let info else { return }
            MainActor.assumeIsolated {
                Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue().scheduleScan(after: 1)
            }
        }
        guard let stream = FSEventStreamCreate(
            nil,
            callback,
            &context,
            [FileManager.default.homeDirectoryForCurrentUser.path] as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            1,
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes)
        ) else {
            setStatusMenuItemTitle("Scan watcher unavailable", on: scanStatusItem)
            return
        }
        eventStream = stream
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.main)
        FSEventStreamStart(stream)
    }

    private func scheduleScan(after delay: TimeInterval) {
        let scheduledDelay = boundedScanDelay(
            now: ProcessInfo.processInfo.systemUptime,
            burstStartedAt: &scanBurstStartedAt,
            debounceDelay: delay,
            maximumDelay: scanMaximumDelay
        )
        scanWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            self?.scanWorkItem = nil
            self?.scanBurstStartedAt = nil
            self?.runScan()
        }
        scanWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + scheduledDelay, execute: workItem)
    }

    private func runScan() {
        scanQueue.async { [weak self] in
            let result = scanResult()
            Task { @MainActor in
                self?.applyScanResult(result)
            }
        }
    }

    private func applyScanResult(_ result: ScanResult) {
        switch result {
        case .clean(_):
            updateMainWindowFindings([])
            #if !DEBUG
            lastTelemetryFindingCount = nil
            #endif
            statusItem.button?.image = brandImage()
            setScanStatus(
                "No Vulnerabilities Detected",
                image: shieldImage(symbolName: "shield.fill", color: .systemGreen)
            )
        case .findings(let findings, let detectorCount, let level):
            updateMainWindowFindings(findings)
            let count = findings.count
            #if !DEBUG
            if lastTelemetryFindingCount != detectorCount {
                postHogTelemetry.captureDetectorTriggered(count: detectorCount)
                lastTelemetryFindingCount = detectorCount
            }
            #endif
            statusItem.button?.image = switch level {
            case .medium: brandImage()
            case .high: brandImage(color: .systemRed)
            }
            setScanStatus(
                vulnerabilityStatusTitle(count: count),
                image: shieldImage(color: level.color)
            )
        case .failed:
            statusItem.button?.image = brandImage(color: .systemRed)
            setScanStatus("Scan failed", image: shieldImage(color: .systemRed))
        }
    }

    private func updateMainWindowFindings(_ findings: [DetectorFinding]) {
        (mainWindow?.contentViewController as? AutomicVaultMainWindowController)?
            .updateDetectorFindings(findings)
    }

    private func setScanStatus(_ title: String, image: NSImage?) {
        setStatusMenuItemTitle(title, on: scanStatusItem)
        scanStatusItem.image = image
    }

    private func setDoctorStatus(count: Int) {
        guard let title = doctorStatusTitle(count: count) else {
            doctorStatusItem.isHidden = true
            return
        }
        setStatusMenuItemTitle(title, on: doctorStatusItem)
        doctorStatusItem.image = shieldImage(
            symbolName: "stethoscope",
            accessibilityDescription: "Doctor"
        )
        doctorStatusItem.isHidden = false
    }

    private func refreshDoctorStatus() {
        scanQueue.async { [weak self] in
            let count = loadDoctorIssues(avExecutableURL: avExecutableURL()).count
            Task { @MainActor in
                self?.setDoctorStatus(count: count)
            }
        }
    }

    private func refreshCLIInstallState() {
        scanQueue.async { [weak self] in
            let isCurrent = currentCLIInstallState() == .current
            Task { @MainActor in
                self?.installCLIItem.isHidden = isCurrent
            }
        }
    }

    private func brandImage(color: NSColor? = nil) -> NSImage? {
        let fallback = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "Automic Vault")
        guard let image = Bundle.main.url(forResource: "NSMenuItem", withExtension: "png")
            .flatMap(NSImage.init(contentsOf:)) ?? fallback else { return nil }
        image.size = NSSize(width: 15, height: 18)
        return tinted(image, color: color)
    }

    private func dimmed(_ image: NSImage, side: AutomaticApprovalFlashSide) -> NSImage {
        let result = NSImage(size: image.size, flipped: false) { rect in
            let left = NSRect(x: rect.minX, y: rect.minY, width: rect.width / 2, height: rect.height)
            let right = NSRect(x: left.maxX, y: rect.minY, width: rect.width / 2, height: rect.height)
            image.draw(in: left, from: left, operation: .sourceOver, fraction: side == .left ? 0.5 : 1)
            image.draw(in: right, from: right, operation: .sourceOver, fraction: side == .right ? 0.5 : 1)
            return true
        }
        result.isTemplate = image.isTemplate
        return result
    }

    private func shieldImage(
        symbolName: String = "shield.lefthalf.filled",
        color: NSColor? = nil,
        accessibilityDescription: String = "Shield"
    ) -> NSImage? {
        guard let symbol = NSImage(
            systemSymbolName: symbolName,
            accessibilityDescription: accessibilityDescription
        ) else {
            return nil
        }
        let image = symbol.withSymbolConfiguration(.init(pointSize: 14, weight: .semibold)) ?? symbol
        image.size = NSSize(width: 16, height: 16)
        return tinted(image, color: color)
    }

    private func tinted(_ image: NSImage, color: NSColor?) -> NSImage {
        guard let color else {
            image.isTemplate = true
            return image
        }
        let tinted = NSImage(size: image.size, flipped: false) { rect in
            image.draw(in: rect)
            color.setFill()
            rect.fill(using: .sourceIn)
            return true
        }
        tinted.isTemplate = false
        return tinted
    }

    private func recordAutoApproval(_ record: AutoApprovalRecord) {
        recordMenuAccess(record)
        switch automaticApprovalFeedback() {
        case .notification:
            showAutomaticAccessToast(record, below: statusItem.button)
        case .menuBarFlash:
            flashMenuBarForAutomaticApproval()
        case .none:
            break
        }
    }

    private func flashMenuBarForAutomaticApproval() {
        guard let button = statusItem.button else { return }
        if automaticApprovalFlashWorkItem == nil {
            preFlashStatusImage = button.image
        }
        automaticApprovalFlashWorkItem?.cancel()
        lastAutomaticApprovalFlashSide = lastAutomaticApprovalFlashSide.next

        guard let baseImage = preFlashStatusImage ?? button.image else { return }
        let flashImage = dimmed(baseImage, side: lastAutomaticApprovalFlashSide)
        button.image = flashImage
        let workItem = DispatchWorkItem { [weak self, weak button] in
            guard let self else { return }
            if button?.image === flashImage {
                button?.image = self.preFlashStatusImage
            }
            self.automaticApprovalFlashWorkItem = nil
            self.preFlashStatusImage = nil
        }
        automaticApprovalFlashWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: workItem)
    }

    private func recordMenuAccess(_ record: AutoApprovalRecord) {
        autoApprovals.insert(record, at: 0)
        let capacity = NSScreen.screens.map { screen in
            Self.visibleAutoApprovalCount + autoApprovalSubmenuCapacity(visibleHeight: screen.visibleFrame.height)
        }.max() ?? Self.visibleAutoApprovalCount
        autoApprovals = Array(autoApprovals.prefix(capacity))
        refreshAutoApprovalMenuItems()
    }

    private func didRecordAccessRequest(_ record: AccessRequestRecord) {
        if ["Canceled", "Denied"].contains(record.decision), let menuRecord = autoApprovalRecord(record) {
            recordMenuAccess(menuRecord)
            if shouldShowAutomaticAccessToast(record) {
                showAutomaticAccessToast(menuRecord, below: statusItem.button)
            }
        }
        (mainWindow?.contentViewController as? AutomicVaultMainWindowController)?.reload()
    }

    private func refreshAutoApprovalMenuItems() {
        guard !isUpdating else { return }
        guard let menu = statusItem.menu else { return }
        for item in autoApprovalItems {
            menu.removeItem(item)
        }
        if let separator = autoApprovalSeparator {
            menu.removeItem(separator)
            autoApprovalSeparator = nil
        }
        let groups = groupedAutoApprovals(autoApprovals)
        autoApprovalItems = groups.prefix(Self.visibleAutoApprovalCount).map(autoApprovalMenuItem)
        let submenuGroups = groups.dropFirst(Self.visibleAutoApprovalCount).prefix(
            autoApprovalSubmenuCapacity(
                visibleHeight: statusItem.button?.window?.screen?.visibleFrame.height
                    ?? NSScreen.main?.visibleFrame.height
                    ?? 0
            )
        )
        if !submenuGroups.isEmpty {
            let moreItem = NSMenuItem(title: "More", action: nil, keyEquivalent: "")
            let submenu = NSMenu()
            submenuGroups.map(autoApprovalMenuItem).forEach(submenu.addItem)
            moreItem.submenu = submenu
            autoApprovalItems.append(moreItem)
        }
        for item in autoApprovalItems.reversed() {
            menu.insertItem(item, at: 0)
        }
        if !autoApprovalItems.isEmpty {
            let separator = NSMenuItem.separator()
            menu.insertItem(separator, at: autoApprovalItems.count)
            autoApprovalSeparator = separator
        }
    }

    fileprivate func autoApprovalMenuItem(_ group: AutoApprovalGroup) -> NSMenuItem {
        guard group.count > 1 else { return autoApprovalMenuItem(group.record) }
        let item = NSMenuItem(
            title: autoApprovalTitle(group, formatter: autoApprovalTimeFormatter),
            action: nil,
            keyEquivalent: ""
        )
        let submenu = NSMenu()
        group.records.map(autoApprovalSubmenuItem).forEach(submenu.addItem)
        item.submenu = submenu
        return item
    }

    private func autoApprovalSubmenuItem(_ record: AutoApprovalRecord) -> NSMenuItem {
        let item = autoApprovalMenuItem(record)
        let time = "\(autoApprovalTimeFormatter.string(from: record.date))  "
        let title = NSMutableAttributedString(
            string: time,
            attributes: [
                .font: NSFont.menuFont(ofSize: 0),
                .foregroundColor: NSColor.disabledControlTextColor,
            ]
        )
        title.append(NSAttributedString(
            string: record.command.replacingOccurrences(of: " \\\n  ", with: " "),
            attributes: [.font: NSFont.menuFont(ofSize: 0)]
        ))
        item.attributedTitle = title
        return item
    }

    private func autoApprovalMenuItem(_ record: AutoApprovalRecord) -> NSMenuItem {
        let item = NSMenuItem(
            title: autoApprovalTitle(record, formatter: autoApprovalTimeFormatter),
            action: #selector(openAutoApproval),
            keyEquivalent: ""
        )
        item.target = self
        item.representedObject = record.accessRequestID.uuidString
        return item
    }
}

extension AppDelegate: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) {
        guard !isStartingUp, !isUpdating else { return }
        refreshAutoApprovalMenuItems()
        refreshDoctorStatus()
    }
}

private func updateMenuVisibility(
    _ items: [NSMenuItem],
    startingUp: Bool,
    visibleDuringStartup: [NSMenuItem]
) {
    for item in items {
        item.isHidden = startingUp && !visibleDuringStartup.contains { $0 === item }
    }
}

private func makeStatusMenuItem(title: String) -> NSMenuItem {
    let item = NSMenuItem.sectionHeader(title: title)
    setStatusMenuItemTitle(title, on: item)
    return item
}

private func makeUpdatingMenu() -> NSMenu {
    let menu = NSMenu()
    menu.addItem(makeStatusMenuItem(title: "Updating…"))
    menu.addItem(.separator())
    let quitItem = NSMenuItem(title: "Quit", action: nil, keyEquivalent: "q")
    quitItem.isEnabled = false
    menu.addItem(quitItem)
    return menu
}

@MainActor
private func configureUpdatingAlert(_ alert: NSAlert) {
    alert.messageText = "Updating…"
    alert.informativeText = "Automic Vault will relaunch when the update is complete."
    alert.buttons.forEach { $0.isHidden = true }
    let progress = NSProgressIndicator(frame: NSRect(x: 0, y: 0, width: 24, height: 24))
    progress.style = .spinning
    progress.isIndeterminate = true
    progress.setAccessibilityLabel("Updating Automic Vault")
    progress.startAnimation(nil)
    alert.accessoryView = progress
    alert.layout()
}

private func setStatusMenuItemTitle(_ title: String, on item: NSMenuItem) {
    item.title = title
    item.attributedTitle = NSAttributedString(
        string: title,
        attributes: [
            .font: NSFont.menuFont(ofSize: 0),
            .foregroundColor: NSColor.disabledControlTextColor,
        ]
    )
}

private func setVersionBadge(_ version: String?, on item: NSMenuItem) {
    item.badge = version.flatMap { $0.isEmpty ? nil : NSMenuItemBadge(string: "v\($0)") }
}

private struct AutoApprovalRecord {
    let accessRequestID: UUID
    let date: Date
    let launcher: String
    let launcherIconPath: String
    let tool: String
    let command: String
    let keys: [String]
    let wasCanceled: Bool
    let wasDenied: Bool
}

private struct AutoApprovalGroup {
    var records: [AutoApprovalRecord]
    var firstDate: Date
    var lastDate: Date

    var count: Int { records.count }
    var record: AutoApprovalRecord { records[0] }

    init(_ record: AutoApprovalRecord) {
        records = [record]
        firstDate = record.date
        lastDate = record.date
    }
}

private func autoApprovalText(_ record: AutoApprovalRecord) -> String {
    let action = record.wasCanceled ? "canceled its request to use" : record.wasDenied ? "was denied use of" : "used"
    return "\(record.launcher) \(action) \(record.tool)"
}

private func groupedAutoApprovals(_ records: [AutoApprovalRecord]) -> [AutoApprovalGroup] {
    records.reduce(into: []) { groups, record in
        if let index = groups.indices.last,
           groups[index].record.launcher == record.launcher,
           groups[index].record.tool == record.tool,
           groups[index].record.wasCanceled == record.wasCanceled,
           groups[index].record.wasDenied == record.wasDenied
        {
            groups[index].records.append(record)
            groups[index].firstDate = min(groups[index].firstDate, record.date)
            groups[index].lastDate = max(groups[index].lastDate, record.date)
        } else {
            groups.append(AutoApprovalGroup(record))
        }
    }
}

private func autoApprovalTitle(_ record: AutoApprovalRecord, formatter: DateFormatter) -> String {
    "\(formatter.string(from: record.date)) – \(autoApprovalText(record))"
}

private func autoApprovalTitle(_ group: AutoApprovalGroup, formatter: DateFormatter) -> String {
    let firstTime = formatter.string(from: group.firstDate)
    guard group.count > 1 else { return autoApprovalTitle(group.record, formatter: formatter) }
    let lastTime = formatter.string(from: group.lastDate)
    let time = firstTime == lastTime ? firstTime : "\(firstTime)\u{2013}\(lastTime)"
    return "\(time) \(autoApprovalText(group.record)) \u{00D7}\(group.count)"
}

private func autoApprovalSubmenuCapacity(visibleHeight: CGFloat) -> Int {
    guard visibleHeight > 0 else { return 0 }
    return max(0, Int((visibleHeight - 16) / 22))
}

private func autoApprovalRecord(
    accessRequestID: UUID,
    request: ApprovalRequest,
    script: ScriptApproval?,
    launcher: LauncherIdentity
) -> AutoApprovalRecord {
    let requester = approvalPromptRequester(launcher: launcher, fallback: launcher.path)
    return AutoApprovalRecord(
        accessRequestID: accessRequestID,
        date: Date(),
        launcher: requester.name,
        launcherIconPath: requester.iconPath,
        tool: autoApprovalToolName(request, scriptPath: script?.path),
        command: autoApprovalCommand(request, scriptPath: script?.path),
        keys: request.keys,
        wasCanceled: false,
        wasDenied: false
    )
}

private func autoApprovalRecord(_ record: AccessRequestRecord) -> AutoApprovalRecord? {
    let wasCanceled = record.decision == "Canceled"
    let wasDenied = record.decision == "Denied"
    guard wasCanceled || wasDenied || (record.decision == "Approved" && record.approvalSourceLabel == "Policy") else { return nil }
    return AutoApprovalRecord(
        accessRequestID: record.id,
        date: record.date,
        launcher: record.launcher ?? "Unknown app",
        launcherIconPath: "",
        tool: record.tool,
        command: record.command,
        keys: record.keys,
        wasCanceled: wasCanceled,
        wasDenied: wasDenied
    )
}

private func shouldShowAutomaticAccessToast(_ record: AccessRequestRecord) -> Bool {
    record.decision == "Denied" && record.approvalSourceLabel == "Policy"
}

private func automaticApprovalFeedback(rawValue: String? = UserDefaults.standard.string(
    forKey: automaticApprovalFeedbackDefaultsKey
)) -> AutomaticApprovalFeedback {
    rawValue.flatMap(AutomaticApprovalFeedback.init(rawValue:)) ?? .notification
}

private func accessRequestRecord(
    id: UUID = UUID(),
    request: ApprovalRequest,
    callerPath: String,
    decision: String,
    approvalSource: String,
    reason: String,
    launcher: LauncherIdentity?
) -> AccessRequestRecord {
    AccessRequestRecord(
        id: id,
        date: Date(),
        tool: autoApprovalToolName(request),
        command: autoApprovalCommand(request),
        decision: decision,
        approvalSource: approvalSource,
        reason: reason,
        launcher: launcher.map { approvalPromptRequester(launcher: $0, fallback: $0.path).name },
        callerPath: callerPath,
        target: request.target,
        cwd: request.cwd,
        keys: request.keys.sorted(),
        detail: request.detail
    )
}

private func shortAppName(_ identifier: String) -> String {
    let name = identifier.split(separator: ".").last.map(String.init) ?? identifier
    return name.prefix(1).uppercased() + name.dropFirst()
}

private func autoApprovalToolName(_ request: ApprovalRequest, scriptPath: String? = nil) -> String {
    if let tool = request.tool {
        return tool
    }
    if let scriptPath {
        return URL(fileURLWithPath: scriptPath).lastPathComponent
    }
    if let scriptPath = resolvedShebangScriptPath(request) {
        return URL(fileURLWithPath: scriptPath).lastPathComponent
    }
    return URL(fileURLWithPath: request.target).lastPathComponent
}

private func autoApprovalCommand(_ request: ApprovalRequest, scriptPath: String? = nil) -> String {
    let scriptPath = scriptPath ?? resolvedShebangScriptPath(request)
    var args = request.args
    if let scriptPath,
       let scriptIndex = args.firstIndex(where: { standardizedPath($0, cwd: request.cwd) == scriptPath })
    {
        args.removeFirst(scriptIndex + 1)
    }
    return prettyShellCommand(target: autoApprovalToolName(request, scriptPath: scriptPath), args: args)
}

private func approvalCommandPath(_ request: ApprovalRequest) -> String {
    resolvedShebangScriptPath(request) ?? request.target
}

private func resolvedShebangScriptPath(_ request: ApprovalRequest) -> String? {
    guard let script = request.shebangScript else { return nil }
    let url = script.hasPrefix("/")
        ? URL(fileURLWithPath: script)
        : URL(fileURLWithPath: request.cwd).appendingPathComponent(script)
    return url.standardizedFileURL.path
}

private enum ScanResult {
    case clean(Int)
    case findings([DetectorFinding], Int, ScanAlertLevel)
    case failed
}

private func boundedScanDelay(
    now: TimeInterval,
    burstStartedAt: inout TimeInterval?,
    debounceDelay: TimeInterval,
    maximumDelay: TimeInterval
) -> TimeInterval {
    let startedAt = burstStartedAt ?? now
    burstStartedAt = startedAt
    return min(debounceDelay, max(0, startedAt + maximumDelay - now))
}

private func doctorStatusTitle(count: Int) -> String? {
    guard count > 0 else { return nil }
    return "\(spelledOut(count)) Doctor \(count == 1 ? "Report" : "Reports")"
}

private func vulnerabilityStatusTitle(count: Int) -> String {
    "\(spelledOut(count)) \(count == 1 ? "Vulnerability" : "Vulnerabilities") Detected"
}

private func spelledOut(_ count: Int) -> String {
    NumberFormatter.localizedString(from: NSNumber(value: count), number: .spellOut).capitalized
}

private enum ScanAlertLevel {
    case medium
    case high

    var color: NSColor {
        switch self {
        case .medium: .systemOrange
        case .high: .systemRed
        }
    }
}

private func scanResult() -> ScanResult {
    let executableURL = avExecutableURL()
    let process = Process()
    process.executableURL = executableURL
    process.arguments = ["scan", "--json"]

    let output = Pipe()
    process.standardOutput = output
    process.standardError = Pipe()

    do {
        try process.run()
    } catch {
        return .failed
    }

    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0,
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let findingObjects = object["findings"] as? [[String: Any]],
          let findings = try? detectorFindings(from: data)
    else {
        return .failed
    }
    let detectorCount = Set(findings.map(\.source)).count
    return findings.isEmpty
        ? .clean(loadDetectorMetadata(avExecutableURL: executableURL).count)
        : .findings(findings, detectorCount, scanAlertLevel(findingObjects))
}

private func scanAlertLevel(_ findings: [[String: Any]]) -> ScanAlertLevel {
    findings.allSatisfy {
        matchesMediumSeverity($0["severity"] as? String)
    } ? .medium : .high
}

private func matchesMediumSeverity(_ severity: String?) -> Bool {
    switch severity?.lowercased() {
    case "medium", "mid": true
    default: false
    }
}

private func avExecutableURL() -> URL {
    if let bundled = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("av"),
       FileManager.default.isExecutableFile(atPath: bundled.path)
    {
        return bundled
    }
    return URL(fileURLWithPath: "/usr/local/bin/av")
}

private struct ApprovalRequest {
    let op: String
    let keys: [String]
    let target: String
    let args: [String]
    let cwd: String
    let replaceExistingEnv: Bool
    let allowMissingKeys: Bool
    let envConflicts: [String]
    let shebangScript: String?
    let scriptData: Data?
    let tool: String?
    let title: String?
    let detail: String?
}

enum SecretMutation {
    case save(account: String, value: String, accessibility: StoredSecretAccessibility)
    case saveIfAbsentOrEqual(account: String, value: String)
    case delete(account: String)
    case rename(account: String, newAccount: String)
    case setAccessibility(account: String, accessibility: StoredSecretAccessibility)

    fileprivate func approvalRequest(callerPath: String) -> ApprovalRequest {
        let properties: (op: String, keys: [String], args: [String], title: String, detail: String)
        switch self {
        case .save(let account, _, _):
            properties = (
                "save", [account], ["save", account], "Store \(account)?",
                "This will create or replace a secret in Automic Vault."
            )
        case .saveIfAbsentOrEqual(let account, _):
            properties = (
                "save-if-absent", [account], ["save-if-absent", account], "Store \(account)?",
                "This will create the secret only if no differing value already exists."
            )
        case .delete(let account):
            properties = (
                "delete", [account], ["delete", account], "Delete \(account)?",
                "This will remove the secret from Automic Vault."
            )
        case .rename(let account, let newAccount):
            properties = (
                "rename", [account, newAccount], ["rename", account, newAccount],
                "Rename \(account)?", "This will rename the secret to \(newAccount)."
            )
        case .setAccessibility(let account, let accessibility):
            let protection = accessibility.isAvailableWhileLocked ? "after-first-unlock" : "when-unlocked"
            properties = (
                "set-accessibility", [account], ["set-accessibility", account, protection],
                "Change protection for \(account)?",
                accessibility.isAvailableWhileLocked
                    ? "This will make the secret available after the first unlock following a restart."
                    : "This will restrict the secret to use while your Mac is unlocked."
            )
        }
        return ApprovalRequest(
            op: properties.op,
            keys: properties.keys,
            target: callerPath,
            args: properties.args,
            cwd: "",
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: URL(fileURLWithPath: callerPath).lastPathComponent,
            title: properties.title,
            detail: properties.detail
        )
    }

    fileprivate func perform() -> OSStatus {
        switch self {
        case .save(let account, let value, let accessibility):
            saveStoredSecret(account: account, value: value, accessibility: accessibility)
        case .saveIfAbsentOrEqual(let account, let value):
            saveStoredSecretIfAbsentOrEqual(account: account, value: value)
        case .delete(let account):
            deleteStoredSecretRevokingDirectAccess(account: account)
        case .rename(let account, let newAccount):
            renameStoredSecretRevokingDirectAccess(account: account, to: newAccount)
        case .setAccessibility(let account, let accessibility):
            setStoredSecretAccessibility(account: account, accessibility: accessibility)
        }
    }
}

private struct TransientApprovalKey: Hashable {
    let pid: Int32
    let startUsec: UInt64
    let callerPath: String
    let signingIdentifier: String
    let signingTeamIdentifier: String
    let op: String
    let keys: [String]
    let target: String
    let args: [String]
    let cwd: String
    let replaceExistingEnv: Bool
    let allowMissingKeys: Bool
    let envConflicts: [String]
    let shebangScript: String?
    let tool: String?
}

private enum ApprovalDecision: Equatable {
    case canceled
    case denied
    case approved
    case alwaysApproved
}

private func canceledAccessRequestRecord(
    request: ApprovalRequest,
    callerPath: String,
    launcher: LauncherIdentity?
) -> AccessRequestRecord {
    accessRequestRecord(
        request: request,
        callerPath: callerPath,
        decision: "Canceled",
        approvalSource: "Manual",
        reason: "Gate client exited",
        launcher: launcher
    )
}

@MainActor
private func performApprovedSecretMutation(
    _ mutation: SecretMutation,
    callerPath: String,
    pid: pid_t,
    signing: SigningInfo,
    launcher: LauncherIdentity?,
    launcherFallbackPath: String,
    canRequestHumanApproval: () -> Bool,
    onAccessRequest: (AccessRequestRecord) -> Bool,
    cancellation: ApprovalCancellation? = nil,
    decision: ((ApprovalRequest) -> ApprovalDecision)? = nil,
    perform: ((SecretMutation) -> OSStatus)? = nil
) -> (status: OSStatus?, error: String?) {
    let request = mutation.approvalRequest(callerPath: callerPath)
    if cancellation?.isCanceled == true {
        _ = onAccessRequest(canceledAccessRequestRecord(
            request: request, callerPath: callerPath, launcher: launcher
        ))
        return (nil, "secret mutation canceled")
    }
    guard canRequestHumanApproval() else {
        _ = onAccessRequest(accessRequestRecord(
            request: request,
            callerPath: callerPath,
            decision: "Denied",
            approvalSource: "Auto",
            reason: "User session is inactive",
            launcher: launcher
        ))
        return (nil, "secret mutation denied while user session is inactive")
    }

    let approval = decision?(request) ?? showApprovalAlert(
        request: request,
        callerPath: callerPath,
        pid: pid,
        signing: signing,
        scriptApproval: nil,
        launcher: launcher,
        launcherFallbackPath: launcherFallbackPath,
        automaticApprovalExplanation: nil,
        cancellation: cancellation
    )
    guard approval == .approved else {
        let canceled = approval == .canceled
        _ = onAccessRequest(accessRequestRecord(
            request: request,
            callerPath: callerPath,
            decision: canceled ? "Canceled" : "Denied",
            approvalSource: "Manual",
            reason: canceled ? "Gate client exited" : "Denied in prompt",
            launcher: launcher
        ))
        return (nil, canceled ? "secret mutation canceled" : "secret mutation denied")
    }
    guard onAccessRequest(accessRequestRecord(
        request: request,
        callerPath: callerPath,
        decision: "Approved",
        approvalSource: "Manual",
        reason: "Approved in prompt",
        launcher: launcher
    )) else {
        return (nil, "approval audit log is unavailable")
    }
    return (perform?(mutation) ?? mutation.perform(), nil)
}

@MainActor
func performInAppSecretMutation(
    _ mutation: SecretMutation
) -> (status: OSStatus?, error: String?) {
    (mutation.perform(), nil)
}

private let humanApprovalRequiredEvent = "human-approval-required"

private func approvalEvent(
    for cachedDecision: ApprovalDecision?,
    humanApprovalAvailable: Bool = true
) -> String? {
    humanApprovalAvailable && cachedDecision == nil ? humanApprovalRequiredEvent : nil
}

private final class ApprovalCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var canceled = false
    private var observer: (@MainActor @Sendable () -> Void)?

    var isCanceled: Bool {
        lock.withLock { canceled }
    }

    func cancel() {
        let observer: (@MainActor @Sendable () -> Void)? = lock.withLock {
            guard !canceled else { return nil }
            canceled = true
            defer { self.observer = nil }
            return self.observer
        }
        if let observer {
            RunLoop.main.perform(inModes: [.modalPanel, .default]) {
                MainActor.assumeIsolated { observer() }
            }
        }
    }

    func observe(_ observer: @escaping @MainActor @Sendable () -> Void) -> Bool {
        lock.withLock {
            guard !canceled else { return false }
            self.observer = observer
            return true
        }
    }

    func stopObserving() {
        lock.withLock { observer = nil }
    }
}

private func isApprovalCancellationEvent(_ event: xpc_object_t) -> Bool {
    xpc_equal(event, XPC_ERROR_CONNECTION_INTERRUPTED)
        || xpc_equal(event, XPC_ERROR_CONNECTION_INVALID)
}

private func missingRequiredSecret(
    for request: ApprovalRequest,
    exists: (String) -> Bool = { storedSecretExists(account: $0) }
) -> String? {
    guard !request.allowMissingKeys else { return nil }
    let conflicts = Set(request.envConflicts)
    return request.keys.first {
        (request.replaceExistingEnv || !conflicts.contains($0)) && !exists($0)
    }
}

private struct TransientApprovalCache {
    private enum Key: Hashable {
        case approval(TransientApprovalKey)
        case denial(pid: Int32, startUsec: UInt64)
    }

    private var expirations: [Key: Date] = [:]

    mutating func decision(for key: TransientApprovalKey, now: Date = Date()) -> ApprovalDecision? {
        prune(now: now)
        if expirations[.denial(pid: key.pid, startUsec: key.startUsec)] != nil {
            return .denied
        }
        return expirations[.approval(key)] == nil ? nil : .approved
    }

    mutating func remember(_ decision: ApprovalDecision, for key: TransientApprovalKey, now: Date = Date()) {
        prune(now: now)
        let cacheKey: Key
        switch decision {
        case .canceled: return
        case .denied: cacheKey = .denial(pid: key.pid, startUsec: key.startUsec)
        case .approved, .alwaysApproved: cacheKey = .approval(key)
        }
        expirations[cacheKey] = now.addingTimeInterval(transientApprovalTTL)
    }

    private mutating func prune(now: Date) {
        expirations = expirations.filter { $0.value > now }
    }
}

private enum RetainedAuthorizationGate: Hashable {
    case blessing(path: String, checksum: String)
    case directSecret
    case secretGate(String)
}

private struct RetainedProcessExecution: Hashable {
    let pid: Int32
    let pidVersion: Int32
    let startUsec: UInt64
    let effectiveUserID: UInt32
    let auditSessionID: UInt32
    let codeIdentity: Data
}

private struct RetainedProcessChainNode {
    let pid: Int32
    let path: String
    let execution: RetainedProcessExecution?
}

private struct RetainedProcessProvenanceMatch {
    let launcher: LauncherIdentity
    let processPath: String
    let execution: RetainedProcessExecution
}

private struct RetainedProcessProvenanceStore {
    private var records: [RetainedAuthorizationGate: [RetainedProcessExecution: LauncherIdentity]] = [:]

    mutating func remember(
        _ executions: [RetainedProcessExecution],
        at gate: RetainedAuthorizationGate,
        launcher: LauncherIdentity,
        isLive: (RetainedProcessExecution) -> Bool = retainedProcessExecutionIsLive
    ) {
        prune(isLive: isLive)
        guard !executions.isEmpty else { return }
        for execution in executions where isLive(execution) {
            records[gate, default: [:]][execution] = launcher
        }
    }

    mutating func match(
        at gate: RetainedAuthorizationGate,
        in chains: [[RetainedProcessChainNode]],
        isLive: (RetainedProcessExecution) -> Bool = retainedProcessExecutionIsLive
    ) -> RetainedProcessProvenanceMatch? {
        prune(isLive: isLive)
        guard let gateRecords = records[gate] else { return nil }
        for node in chains.joined() {
            guard let execution = node.execution,
                  let launcher = gateRecords[execution]
            else { continue }
            return RetainedProcessProvenanceMatch(
                launcher: launcher,
                processPath: node.path,
                execution: execution
            )
        }
        return nil
    }

    private mutating func prune(isLive: (RetainedProcessExecution) -> Bool) {
        records = records.compactMapValues { gateRecords in
            let live = gateRecords.filter { isLive($0.key) }
            return live.isEmpty ? nil : live
        }
    }
}

private struct SigningInfo {
    let identifier: String
    let teamIdentifier: String
}

private struct MutationCaller {
    let pid: pid_t
    let identity: AVProcessIdentity
    let path: String
    let signing: SigningInfo
}

private struct LauncherIdentity {
    let pid: pid_t
    let path: String
    let identifier: String
    let teamIdentifier: String
    let designatedRequirement: String
    let runtimeProtection: LauncherRuntimeProtection
    let isStandalone: Bool

    init(
        pid: pid_t,
        path: String,
        identifier: String,
        teamIdentifier: String,
        designatedRequirement: String,
        runtimeProtection: LauncherRuntimeProtection,
        isStandalone: Bool = false
    ) {
        self.pid = pid
        self.path = path
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.designatedRequirement = designatedRequirement
        self.runtimeProtection = runtimeProtection
        self.isStandalone = isStandalone
    }
}

private struct ScriptApproval {
    let path: String
    let checksum: String
}

private func blessedScriptMatches(
    _ script: BlessedScript,
    request: ApprovalRequest,
    approval: ScriptApproval,
    launcher: LauncherIdentity?
) -> Bool {
    request.op == "inject"
        && request.scriptData != nil
        && script.matchesExecution(
            path: approval.path,
            checksum: approval.checksum,
            keys: request.keys,
            target: request.target,
            replaceExistingEnv: request.replaceExistingEnv,
            allowMissingKeys: request.allowMissingKeys,
            launcherRequirement: launcher?.designatedRequirement
        )
}

private func lostBlessingExplanation(
    for approval: ScriptApproval?,
    blessedScripts: [BlessedScript]? = nil
) -> String? {
    guard let approval else { return nil }
    guard let script = (blessedScripts ?? loadBlessedScripts()).first(where: { $0.path == approval.path }),
          script.checksum != approval.checksum
    else { return nil }
    return "Blessing lost because the script contents changed."
}

private func blessedScriptCanAutoApprove(
    _ script: BlessedScript,
    request: ApprovalRequest,
    signing: SigningInfo,
    metadata: [HardenerMetadata]
) -> Bool {
    guard let gate = matchingSecretGateDefinition(
        request: request,
        signing: signing,
        hardeners: metadata
    ),
    let protection = script.capabilities[gate.id]?.normalized(forGateID: gate.id)
    else { return false }
    return secretGateProtectionAllows(
        protection,
        classification: classifySecretGateRequest(gateID: gate.id, request: request)
    )
}

private struct BlessedExecutionKey: Hashable {
    let pid: Int32
    let startUsec: UInt64
}

private struct AWSRegistrationCandidate {
    let chain: AWSProfileChain
    let args: [String]
    let target: String
    let interpreter: String
    let useLongLivedCredentials: Bool
}

private struct AWSRegistration {
    let chain: AWSProfileChain
    let args: [String]
    let target: String
    let interpreter: String
    let useLongLivedCredentials: Bool
    var credentials: AWSCredentials?
}

private struct ApprovedPayload {
    let secrets: [String: String]
    let value: String?
}

private let awsHelperProtocolVersion = 1

private final class ApprovalServer: @unchecked Sendable {
    private let serviceName: String
    private let teamIdentifier: String
    private let hardeners: [HardenerMetadata]?
    private let onAutoApproval: @MainActor (AutoApprovalRecord) -> Void
    private let onAccessRequest: @Sendable (AccessRequestRecord) -> Bool
    private let onBlessRequest: @MainActor (
        BlessedScriptReviewRequest,
        @escaping (String?) -> Void
    ) -> Void
    private let canRequestHumanApproval: @MainActor () -> Bool
    private var listener: xpc_connection_t?
    // ponytail: helper-lifetime caches; persistent policy remains the cross-restart trust boundary.
    private var transientApprovals = TransientApprovalCache()
    private let retainedProcessProvenanceLock = NSLock()
    private var retainedProcessProvenance = RetainedProcessProvenanceStore()
    private let blessedExecutionsLock = NSLock()
    private var blessedExecutions: [BlessedExecutionKey: BlessedScript] = [:]
    private let awsRegistrationsLock = NSLock()
    private var awsRegistrations: [BlessedExecutionKey: AWSRegistration] = [:]

    init(
        serviceName: String,
        hardeners: [HardenerMetadata]? = nil,
        onAutoApproval: @escaping @MainActor (AutoApprovalRecord) -> Void = { _ in },
        onAccessRequest: @escaping @Sendable (AccessRequestRecord) -> Bool = { appendAccessRequestRecord($0) },
        onBlessRequest: @escaping @MainActor (
            BlessedScriptReviewRequest,
            @escaping (String?) -> Void
        ) -> Void = { _, completion in completion("script blessing is unavailable") },
        canRequestHumanApproval: @escaping @MainActor () -> Bool = { true }
    ) throws {
        guard let teamIdentifier = selfTeamIdentifier() else {
            throw AppError("missing menu bar signing team identifier")
        }
        self.serviceName = serviceName
        self.teamIdentifier = teamIdentifier
        self.hardeners = hardeners
        self.onAutoApproval = onAutoApproval
        self.onAccessRequest = onAccessRequest
        self.onBlessRequest = onBlessRequest
        self.canRequestHumanApproval = canRequestHumanApproval
    }

    func start() throws {
        listener = serviceName.withCString {
            xpc_connection_create_mach_service(
                $0,
                nil,
                UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
            )
        }
        guard let listener else { throw AppError("approval XPC listener failed") }

        let requirement = """
        anchor apple generic and certificate leaf[subject.OU] = \(teamIdentifier) and \
        (identifier "com.automicvault.av" or identifier "com.automicvault.av-brew-stub" or \
        identifier "gh" or identifier "com.github.cli" or identifier "stripe" or \
        identifier "supabase" or identifier "supabase-go" or identifier "com.supabase.cli")
        """
        let status = requirement.withCString {
            xpc_connection_set_peer_code_signing_requirement(listener, $0)
        }
        guard status == 0 else {
            throw AppError("approval XPC signing requirement failed")
        }

        xpc_connection_set_event_handler(listener) { [weak self] event in
            self?.accept(event)
        }
        xpc_connection_activate(listener)
    }

    func stop() {
        if let listener {
            xpc_connection_cancel(listener)
            self.listener = nil
        }
    }

    private func retainedProvenanceMatch(
        at gate: RetainedAuthorizationGate,
        in chains: [[RetainedProcessChainNode]]
    ) -> RetainedProcessProvenanceMatch? {
        retainedProcessProvenanceLock.withLock {
            retainedProcessProvenance.match(at: gate, in: chains)
        }
    }

    private func rememberRetainedProvenance(
        at gate: RetainedAuthorizationGate,
        launcher: LauncherIdentity,
        chains: [[RetainedProcessChainNode]],
        retainedMatch: RetainedProcessProvenanceMatch? = nil
    ) {
        let executions = retainedMatch.map {
            retainedExecutions(leadingTo: $0.execution, in: chains)
        } ?? retainedExecutions(leadingTo: launcher.pid, in: chains)
        retainedProcessProvenanceLock.withLock {
            retainedProcessProvenance.remember(executions, at: gate, launcher: launcher)
        }
    }

    private func accept(_ event: xpc_object_t) {
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
        let peer = event
        let cancellation = ApprovalCancellation()
        xpc_connection_set_event_handler(peer) { [weak self] message in
            self?.handle(message, on: peer, cancellation: cancellation)
        }
        xpc_connection_activate(peer)
    }

    private func handle(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation
    ) {
        if isApprovalCancellationEvent(message) {
            cancellation.cancel()
            return
        }
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else { return }

        let pid = xpc_connection_get_pid(peer)
        var identity = AVProcessIdentity()
        guard av_process_identity(pid, &identity) else {
            reply(peer, to: message, ok: false, error: "Gate Client identity is unavailable")
            return
        }

        let callerPath = pathString(identity)
        let signing = signingInfo(path: callerPath)

        guard let opPointer = xpc_dictionary_get_string(message, "op") else {
            reply(peer, to: message, ok: false, error: "invalid XPC request")
            return
        }
        let op = String(cString: opPointer)

        guard isAllowedCaller(path: callerPath, signing: signing) else {
            reply(peer, to: message, ok: false, error: "Gate Client is not trusted")
            return
        }
        let mutationCaller = MutationCaller(
            pid: pid,
            identity: identity,
            path: callerPath,
            signing: signing
        )

        switch op {
        case "aws-helper-version" where isTrustedAvCaller(path: callerPath, signing: signing):
            reply(peer, to: message, ok: true, error: nil, value: String(awsHelperProtocolVersion))
        case "inject", "keys", "authorize":
            handleInject(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case "aws-credentials" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleAWSCredentials(message, on: peer, pid: pid, identity: identity)
        case "list" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleList(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case "save" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "save-if-absent" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleSave(
                message,
                on: peer,
                cancellation: cancellation,
                caller: mutationCaller,
                ifAbsentOrEqual: true
            )
        case "load" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleLoad(message, on: peer)
        case "bless" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleBless(message, on: peer, identity: identity)
        case "delete" where isTrustedAvCaller(path: callerPath, signing: signing):
            handleDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "save" where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "gh-save" where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "delete" where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "gh-delete" where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "stripe-save" where isTrustedStripeCaller(path: callerPath, signing: signing):
            handleStripeSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case "stripe-delete" where isTrustedStripeCaller(path: callerPath, signing: signing):
            handleStripeDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        default:
            reply(peer, to: message, ok: false, error: "invalid XPC operation")
        }
    }

    private func handleList(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        pid: pid_t,
        identity: AVProcessIdentity,
        callerPath: String,
        signing: SigningInfo
    ) {
        guard let cwdPointer = xpc_dictionary_get_string(message, "cwd") else {
            reply(peer, to: message, ok: false, error: "invalid list request")
            return
        }
        var launchers = launcherIdentities(for: identity)
        let ancestorFallbackPath = launcherFallbackPath(for: identity)
        if launchers.isEmpty, let caller = launcherIdentity(pid: pid, identity: identity) {
            launchers.append(caller)
        }
        let allowedApps = loadSecretNameAccessApps()
        let allowedLauncher = launchers.first {
            candidate in allowedApps.contains { $0.requirement == candidate.designatedRequirement }
        }
        let launcher = executionOrigin(
            among: launchers,
            callerPID: pid,
            ancestorFallbackPath: ancestorFallbackPath
        )
        let request = ApprovalRequest(
            op: "list",
            keys: [],
            target: callerPath,
            args: ["list"],
            cwd: String(cString: cwdPointer),
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "av",
            title: "List saved secret names?",
            detail: "Secret values will remain hidden. The requesting app will receive every saved secret name."
        )
        if allowedLauncher != nil
        {
            discloseSecretNames(
                request: request,
                callerPath: callerPath,
                launcher: launcher,
                approvalSource: "Auto",
                reason: "Always allowed in Settings",
                peer: peer,
                message: message
            )
            return
        }
        DispatchQueue.main.async {
            if cancellation.isCanceled {
                _ = self.onAccessRequest(canceledAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: launcher
                ))
                return
            }
            guard self.canRequestHumanApproval() else {
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Denied",
                    approvalSource: "Auto",
                    reason: "User session is inactive",
                    launcher: launcher
                ))
                self.reply(peer, to: message, ok: false, error: "list denied while user session is inactive")
                return
            }
            let decision = showApprovalAlert(
                request: request,
                callerPath: callerPath,
                pid: pid,
                signing: signing,
                scriptApproval: nil,
                launcher: launcher,
                launcherFallbackPath: ancestorFallbackPath ?? callerPath,
                automaticApprovalExplanation: nil,
                allowsPersistentApproval: launcher.map { !$0.isStandalone } ?? false,
                cancellation: cancellation
            )
            if decision == .canceled {
                _ = self.onAccessRequest(canceledAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: launcher
                ))
                return
            }
            guard decision != .denied else {
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Denied",
                    approvalSource: "Manual",
                    reason: "Denied in prompt",
                    launcher: launcher
                ))
                self.reply(peer, to: message, ok: false, error: "list denied")
                return
            }
            if decision == .alwaysApproved, let launcher {
                let status = allowSecretNameAccess(BlessedScriptLauncher(
                    bundleIdentifier: launcher.identifier,
                    requirement: launcher.designatedRequirement
                ))
                guard status == errSecSuccess else {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Failed",
                        approvalSource: "Manual",
                        reason: "Could not save persistent access: \(status)",
                        launcher: launcher
                    ))
                    self.reply(peer, to: message, ok: false, error: "failed to save list access: \(status)")
                    return
                }
            }
            self.discloseSecretNames(
                request: request,
                callerPath: callerPath,
                launcher: launcher,
                approvalSource: "Manual",
                reason: decision == .alwaysApproved ? "Always allowed in prompt" : "Allowed once in prompt",
                peer: peer,
                message: message
            )
        }
    }

    private func discloseSecretNames(
        request: ApprovalRequest,
        callerPath: String,
        launcher: LauncherIdentity?,
        approvalSource: String,
        reason: String,
        peer: xpc_connection_t,
        message: xpc_object_t
    ) {
        let names = loadStoredSecrets().map(\.account)
        guard onAccessRequest(accessRequestRecord(
            request: request,
            callerPath: callerPath,
            decision: "Approved",
            approvalSource: approvalSource,
            reason: reason,
            launcher: launcher
        )) else {
            reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
            return
        }
        reply(peer, to: message, ok: true, error: nil, names: names)
    }

    private func handleInject(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        pid: pid_t,
        identity: AVProcessIdentity,
        callerPath: String,
        signing: SigningInfo
    ) {
        guard let parsedRequest = approvalRequest(from: message) else {
            reply(peer, to: message, ok: false, error: "invalid approval request")
            return
        }
        let request = approvalRequestWithCredentialContext(parsedRequest)
        let awsRegistration: AWSRegistrationCandidate?
        do {
            awsRegistration = try awsRegistrationCandidate(from: message, request: request)
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
            return
        }
        let scriptApproval = scriptApproval(for: request)
        let processChains = retainedProcessChains(for: identity)
        let keepsDetachedProcessAccess = UserDefaults.standard.bool(
            forKey: keepLauncherAccessForDetachedProcessesDefaultsKey
        )
        var launchers = launcherIdentities(for: identity)
        let ancestorFallbackPath = launcherFallbackPath(for: identity)
        let launcherFallbackPath = ancestorFallbackPath ?? callerPath
        if launchers.isEmpty, let launcher = launcherIdentity(pid: pid, identity: identity) {
            launchers.append(launcher)
        }
        let launcher = executionOrigin(
            among: launchers,
            callerPID: pid,
            ancestorFallbackPath: ancestorFallbackPath
        )
        let metadata = hardeners ?? loadHardenerMetadata(avExecutableURL: avExecutableURL())
        let activeBlessing = activeBlessedScript(pid: pid, identity: identity)
        if let script = activeBlessing {
            if handleBlessedCapability(
                script,
                request: request,
                signing: signing,
                metadata: metadata,
                launcher: launcher,
                callerPath: callerPath,
                awsRegistration: awsRegistration,
                pid: pid,
                identity: identity,
                peer: peer,
                message: message
            ) {
                return
            }
        }
        let blessingGate = scriptApproval.map {
            RetainedAuthorizationGate.blessing(path: $0.path, checksum: $0.checksum)
        }
        let retainedBlessingProvenance = blessingGate.flatMap {
            retainedProvenanceMatch(at: $0, in: processChains)
        }
        let currentBlessingMatch = scriptApproval.flatMap {
            matchingBlessedScript(request: request, approval: $0, launchers: launchers)
        }
        let retainedBlessingMatch = scriptApproval.flatMap { approval in
            retainedBlessingProvenance.flatMap {
                matchingBlessedScript(
                    request: request,
                    approval: approval,
                    launchers: [$0.launcher]
                )
            }
        }
        let effectiveBlessingMatch = currentBlessingMatch
            ?? (keepsDetachedProcessAccess ? retainedBlessingMatch : nil)
        if let scriptApproval,
           let blessingGate,
           let (script, matchedLauncher) = effectiveBlessingMatch
        {
            do {
                let payload = try approvedPayload(
                    for: request, awsRegistration: awsRegistration, pid: pid, identity: identity
                )
                let accessRequestID = UUID()
                let record = accessRequestRecord(
                    id: accessRequestID,
                    request: request,
                    callerPath: callerPath,
                    decision: "Approved",
                    approvalSource: "Auto",
                    reason: "Blessed script \(script.path)",
                    launcher: matchedLauncher
                )
                guard onAccessRequest(record) else {
                    reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                    return
                }
                registerBlessedExecution(script, pid: pid, identity: identity)
                rememberRetainedProvenance(
                    at: blessingGate,
                    launcher: matchedLauncher,
                    chains: processChains,
                    retainedMatch: currentBlessingMatch == nil ? retainedBlessingProvenance : nil
                )
                Task { @MainActor in
                    self.onAutoApproval(autoApprovalRecord(
                        accessRequestID: accessRequestID,
                        request: request,
                        script: scriptApproval,
                        launcher: matchedLauncher
                    ))
                }
                reply(peer, to: message, ok: true, error: nil, secrets: payload.secrets, value: payload.value)
            } catch {
                _ = onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Failed",
                    approvalSource: "Auto",
                    reason: error.localizedDescription,
                    launcher: matchedLauncher
                ))
                reply(peer, to: message, ok: false, error: error.localizedDescription)
            }
            return
        }
        if let key = missingRequiredSecret(for: request) {
            reply(peer, to: message, ok: false, error: "failed to load secret \(key): \(errSecItemNotFound)")
            return
        }
        let configuredGate = matchingSecretGate(
            request: request,
            signing: signing,
            hardeners: metadata
        )
        let authorizationGate = configuredGate.map {
            RetainedAuthorizationGate.secretGate($0.id)
        } ?? .directSecret
        let retainedGateProvenance = retainedProvenanceMatch(
            at: authorizationGate,
            in: processChains
        )
        var policyLaunchers = launchers
        if keepsDetachedProcessAccess,
           let retainedLauncher = retainedGateProvenance?.launcher,
           !policyLaunchers.contains(where: {
               $0.designatedRequirement == retainedLauncher.designatedRequirement
           })
        {
            policyLaunchers.append(retainedLauncher)
        }
        let policyLauncher = executionOrigin(
            among: policyLaunchers,
            callerPID: pid,
            ancestorFallbackPath: ancestorFallbackPath
        ) ?? launcher
        let directAccessRules = loadDirectAccessRules()
        let directAccessLauncher = matchingDirectAccessLauncher(
            request: request,
            configuredGate: configuredGate,
            trustedAVGateClient: isTrustedAvCaller(path: callerPath, signing: signing),
            launchers: policyLaunchers,
            rules: directAccessRules
        )
        let resolvedPolicy = configuredGate.flatMap {
            resolveSecretGatePolicy(gate: $0, launchers: policyLaunchers)
        }
        let classification = configuredGate.map {
            classifySecretGateRequest(gateID: $0.id, request: request)
        }
        let retainedProcessExplanation: String?
        if !keepsDetachedProcessAccess,
           retainedBlessingMatch != nil,
           let retainedBlessingProvenance
        {
            retainedProcessExplanation = retainedProcessApprovalExplanation(
                match: retainedBlessingProvenance,
                gateName: "this Blessing"
            )
        } else if !keepsDetachedProcessAccess,
                  activeBlessing == nil,
                  let retainedGateProvenance,
                  retainedProvenanceWouldAuthorize(
                      request: request,
                      configuredGate: configuredGate,
                      classification: classification,
                      launcher: retainedGateProvenance.launcher,
                      directAccessRules: directAccessRules,
                      trustedAVGateClient: isTrustedAvCaller(path: callerPath, signing: signing)
                  )
        {
            retainedProcessExplanation = retainedProcessApprovalExplanation(
                match: retainedGateProvenance,
                gateName: configuredGate.map { "the \($0.id) gate" } ?? "the Direct Secret Gate"
            )
        } else {
            retainedProcessExplanation = nil
        }
        let automaticApprovalExplanation: String?
        if let configuredGate,
           let resolvedPolicy,
           let classification,
           !secretGateProtectionAllows(resolvedPolicy.protection, classification: classification),
           let explanation = secretGateAutomaticApprovalExplanation(
               gateID: configuredGate.id,
               request: request
           )
        {
            automaticApprovalExplanation = explanation
        } else if resolvedPolicy == nil,
           classification == .readOnly,
           let failure = launcherAppVerificationFailure(for: identity)
        {
            automaticApprovalExplanation = failure.explanation
        } else {
            automaticApprovalExplanation = nil
        }
        if activeBlessing == nil, let directAccessLauncher {
            do {
                let payload = try approvedPayload(
                    for: request, awsRegistration: awsRegistration, pid: pid, identity: identity
                )
                let accessRequestID = UUID()
                let record = accessRequestRecord(
                    id: accessRequestID,
                    request: request,
                    callerPath: callerPath,
                    decision: "Approved",
                    approvalSource: "Auto",
                    reason: "Direct Access from \(shortAppName(directAccessLauncher.identifier))",
                    launcher: directAccessLauncher
                )
                guard onAccessRequest(record) else {
                    reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                    return
                }
                rememberRetainedProvenance(
                    at: authorizationGate,
                    launcher: directAccessLauncher,
                    chains: processChains,
                    retainedMatch: launchers.contains(where: {
                        $0.designatedRequirement == directAccessLauncher.designatedRequirement
                    }) ? nil : retainedGateProvenance
                )
                Task { @MainActor in
                    self.onAutoApproval(autoApprovalRecord(
                        accessRequestID: accessRequestID,
                        request: request,
                        script: scriptApproval,
                        launcher: directAccessLauncher
                    ))
                }
                reply(
                    peer,
                    to: message,
                    ok: true,
                    error: nil,
                    secrets: payload.secrets,
                    value: payload.value
                )
            } catch {
                _ = onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Failed",
                    approvalSource: "Auto",
                    reason: error.localizedDescription,
                    launcher: directAccessLauncher
                ))
                reply(peer, to: message, ok: false, error: error.localizedDescription)
            }
            return
        }
        if activeBlessing == nil,
           let configuredGate,
           let resolvedPolicy,
           let classification,
           secretGateProtectionAllows(
               resolvedPolicy.protection,
               classification: classification
           )
        {
            let authorizingLauncher = resolvedPolicy.launcher ?? policyLauncher
            do {
                let payload = try approvedPayload(
                    for: request, awsRegistration: awsRegistration, pid: pid, identity: identity
                )
                let reason = "\(configuredGate.protectionTitle(resolvedPolicy.protection)) from \(resolvedPolicy.source)"
                let accessRequestID = UUID()
                let record = accessRequestRecord(
                    id: accessRequestID,
                    request: request,
                    callerPath: callerPath,
                    decision: "Approved",
                    approvalSource: "Auto",
                    reason: reason,
                    launcher: authorizingLauncher
                )
                guard onAccessRequest(record) else {
                    reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                    return
                }
                if let authorizingLauncher {
                    rememberRetainedProvenance(
                        at: authorizationGate,
                        launcher: authorizingLauncher,
                        chains: processChains,
                        retainedMatch: launchers.contains(where: {
                            $0.designatedRequirement == authorizingLauncher.designatedRequirement
                        }) ? nil : retainedGateProvenance
                    )
                    Task { @MainActor in
                        self.onAutoApproval(autoApprovalRecord(
                            accessRequestID: accessRequestID,
                            request: request,
                            script: scriptApproval,
                            launcher: authorizingLauncher
                        ))
                    }
                }
                reply(peer, to: message, ok: true, error: nil, secrets: payload.secrets, value: payload.value)
            } catch {
                _ = onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Failed",
                    approvalSource: "Auto",
                    reason: error.localizedDescription,
                    launcher: authorizingLauncher
                ))
                reply(peer, to: message, ok: false, error: error.localizedDescription)
            }
            return
        }
        let promptLauncher = policyLauncher
        let transientApproval = TransientApprovalKey(
            pid: pid,
            startUsec: identity.start_usec,
            callerPath: callerPath,
            signingIdentifier: signing.identifier,
            signingTeamIdentifier: signing.teamIdentifier,
            op: request.op,
            keys: request.keys.sorted(),
            target: request.target,
            args: request.args,
            cwd: request.cwd,
            replaceExistingEnv: request.replaceExistingEnv,
            allowMissingKeys: request.allowMissingKeys,
            envConflicts: request.envConflicts.sorted(),
            shebangScript: request.shebangScript,
            tool: request.tool
        )
        let promptBlessing: BlessedScriptPromptContext?
        if let activeBlessing {
            promptBlessing = BlessedScriptPromptContext(
                script: activeBlessing,
                explanation: "This request exceeds the stored authority. Approval applies only to this request."
            )
        } else if let scriptApproval,
                  let script = matchingBlessedScriptExecution(
                      request: request,
                      approval: scriptApproval
                  )
        {
            promptBlessing = BlessedScriptPromptContext(
                script: script,
                explanation: script.launchers.isEmpty
                    ? "Approval activates this stored authority for one execution."
                    : "The current launcher isn’t endorsed. Approval permits this request once; the blessed capabilities remain inactive."
            )
        } else {
            promptBlessing = nil
        }
        let requiresFreshApproval = awsRequestMayUseLongLivedCredentials(request)
        RunLoop.main.perform(inModes: [.modalPanel, .default]) {
            MainActor.assumeIsolated {
                guard !cancellation.isCanceled,
                      let event = approvalEvent(
                          for: requiresFreshApproval
                              ? nil
                              : self.transientApprovals.decision(for: transientApproval),
                          humanApprovalAvailable: self.canRequestHumanApproval()
                      )
                else { return }
                self.sendEvent(event, to: peer)
            }
        }
        DispatchQueue.main.async {
            if cancellation.isCanceled {
                _ = self.onAccessRequest(canceledAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: promptLauncher
                ))
                return
            }
            let cachedDecision = requiresFreshApproval
                ? nil
                : self.transientApprovals.decision(for: transientApproval)
            if let decision = cachedDecision {
                if decision == .denied {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Denied",
                        approvalSource: "Auto",
                        reason: "Reused recent denial",
                        launcher: promptLauncher
                    ))
                    self.reply(peer, to: message, ok: false, error: "\(request.op) denied")
                    return
                }
                do {
                    let payload = try self.approvedPayload(
                        for: request, awsRegistration: awsRegistration, pid: pid, identity: identity
                    )
                    let record = accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Approved",
                        approvalSource: "Auto",
                        reason: "Reused recent approval",
                        launcher: promptLauncher
                    )
                    guard self.onAccessRequest(record) else {
                        self.reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                        return
                    }
                    self.reply(peer, to: message, ok: true, error: nil, secrets: payload.secrets, value: payload.value)
                } catch {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Failed",
                        approvalSource: "Auto",
                        reason: error.localizedDescription,
                        launcher: promptLauncher
                    ))
                    self.reply(peer, to: message, ok: false, error: error.localizedDescription)
                }
                return
            }

            guard self.canRequestHumanApproval() else {
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Denied",
                    approvalSource: "Auto",
                    reason: "Human approval unavailable",
                    launcher: promptLauncher
                ))
                self.reply(
                    peer,
                    to: message,
                    ok: false,
                    error: "human approval unavailable"
                )
                return
            }

            let decision = showApprovalAlert(
                request: request,
                callerPath: callerPath,
                pid: pid,
                signing: signing,
                scriptApproval: scriptApproval,
                blessing: promptBlessing,
                launcher: promptLauncher,
                launcherFallbackPath: launcherFallbackPath,
                automaticApprovalExplanation: lostBlessingExplanation(for: scriptApproval)
                    ?? retainedProcessExplanation
                    ?? automaticApprovalExplanation,
                cancellation: cancellation
            )
            if decision == .canceled {
                _ = self.onAccessRequest(canceledAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: promptLauncher
                ))
                return
            }
            guard decision != .denied else {
                if !requiresFreshApproval {
                    self.transientApprovals.remember(.denied, for: transientApproval)
                }
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Denied",
                    approvalSource: "Manual",
                    reason: "Denied in prompt",
                    launcher: promptLauncher
                ))
                self.reply(
                    peer,
                    to: message,
                    ok: false,
                    error: "\(request.op) denied",
                    humanApprovalDecision: "denied"
                )
                return
            }
            do {
                let payload = try self.approvedPayload(
                    for: request, awsRegistration: awsRegistration, pid: pid, identity: identity
                )
                let record = accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Approved",
                    approvalSource: "Manual",
                    reason: "Approved in prompt",
                    launcher: promptLauncher
                )
                guard self.onAccessRequest(record) else {
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "approval audit log is unavailable",
                        humanApprovalDecision: "approved"
                    )
                    return
                }
                if let scriptApproval,
                   let script = self.matchingBlessedScript(
                       request: request,
                       approval: scriptApproval,
                       launcher: nil
                   )
                {
                    self.registerBlessedExecution(script, pid: pid, identity: identity)
                }
                if !requiresFreshApproval {
                    self.transientApprovals.remember(.approved, for: transientApproval)
                }
                self.reply(
                    peer,
                    to: message,
                    ok: true,
                    error: nil,
                    secrets: payload.secrets,
                    value: payload.value,
                    humanApprovalDecision: "approved"
                )
            } catch {
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Failed",
                    approvalSource: "Manual",
                    reason: error.localizedDescription,
                    launcher: promptLauncher
                ))
                self.reply(
                    peer,
                    to: message,
                    ok: false,
                    error: error.localizedDescription,
                    humanApprovalDecision: "approved"
                )
            }
        }
    }

    private func matchingBlessedScript(
        request: ApprovalRequest,
        approval: ScriptApproval,
        launchers: [LauncherIdentity]
    ) -> (BlessedScript, LauncherIdentity)? {
        let scripts = loadBlessedScripts()
        for launcher in launchers {
            if let script = scripts.first(where: {
                blessedScriptMatches($0, request: request, approval: approval, launcher: launcher)
            }) {
                return (script, launcher)
            }
        }
        return nil
    }

    private func matchingBlessedScript(
        request: ApprovalRequest,
        approval: ScriptApproval,
        launcher: LauncherIdentity?
    ) -> BlessedScript? {
        loadBlessedScripts().first {
            blessedScriptMatches($0, request: request, approval: approval, launcher: launcher)
        }
    }

    private func matchingBlessedScriptExecution(
        request: ApprovalRequest,
        approval: ScriptApproval
    ) -> BlessedScript? {
        guard request.op == "inject", request.scriptData != nil else { return nil }
        return loadBlessedScripts().first {
            $0.matchesExecution(
                path: approval.path,
                checksum: approval.checksum,
                keys: request.keys,
                target: request.target,
                replaceExistingEnv: request.replaceExistingEnv,
                allowMissingKeys: request.allowMissingKeys
            )
        }
    }

    private func registerBlessedExecution(
        _ script: BlessedScript,
        pid: pid_t,
        identity: AVProcessIdentity
    ) {
        blessedExecutionsLock.lock()
        blessedExecutions[BlessedExecutionKey(pid: pid, startUsec: identity.start_usec)] = script
        blessedExecutionsLock.unlock()
    }

    private func activeBlessedScript(pid: pid_t, identity: AVProcessIdentity) -> BlessedScript? {
        let currentBlessings = loadBlessedScripts()
        blessedExecutionsLock.lock()
        blessedExecutions = blessedExecutions.filter { key, script in
            var current = AVProcessIdentity()
            return currentBlessings.contains(script)
                && av_process_identity(key.pid, &current)
                && current.start_usec == key.startUsec
        }
        let executions = blessedExecutions
        blessedExecutionsLock.unlock()

        var currentPID = pid
        var currentIdentity = identity
        for _ in 0..<64 {
            if let script = executions[BlessedExecutionKey(
                pid: currentPID,
                startUsec: currentIdentity.start_usec
            )] {
                return script
            }
            guard currentIdentity.ppid > 1 else { return nil }
            currentPID = currentIdentity.ppid
            guard av_process_identity(currentPID, &currentIdentity) else { return nil }
        }
        return nil
    }

    private func handleBlessedCapability(
        _ script: BlessedScript,
        request: ApprovalRequest,
        signing: SigningInfo,
        metadata: [HardenerMetadata],
        launcher: LauncherIdentity?,
        callerPath: String,
        awsRegistration: AWSRegistrationCandidate?,
        pid: pid_t,
        identity: AVProcessIdentity,
        peer: xpc_connection_t,
        message: xpc_object_t
    ) -> Bool {
        guard blessedScriptCanAutoApprove(
            script,
            request: request,
            signing: signing,
            metadata: metadata
        ) else { return false }

        do {
            let payload = try approvedPayload(
                for: request, awsRegistration: awsRegistration, pid: pid, identity: identity
            )
            let accessRequestID = UUID()
            guard onAccessRequest(accessRequestRecord(
                id: accessRequestID,
                request: request,
                callerPath: callerPath,
                decision: "Approved",
                approvalSource: "Auto",
                reason: "Blessed script \(script.path)",
                launcher: launcher
            )) else {
                reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                return true
            }
            if let launcher {
                Task { @MainActor in
                    self.onAutoApproval(autoApprovalRecord(
                        accessRequestID: accessRequestID,
                        request: request,
                        script: ScriptApproval(path: script.path, checksum: script.checksum),
                        launcher: launcher
                    ))
                }
            }
            reply(peer, to: message, ok: true, error: nil, secrets: payload.secrets, value: payload.value)
        } catch {
            _ = onAccessRequest(accessRequestRecord(
                request: request,
                callerPath: callerPath,
                decision: "Failed",
                approvalSource: "Auto",
                reason: error.localizedDescription,
                launcher: launcher
            ))
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
        return true
    }

    private func handleSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller,
        ifAbsentOrEqual: Bool = false
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              let valuePointer = xpc_dictionary_get_string(message, "value")
        else {
            reply(peer, to: message, ok: false, error: "invalid save request")
            return
        }
        let key = String(cString: keyPointer)
        guard validSecretKeyName(key) else {
            reply(peer, to: message, ok: false, error: "invalid secret name: \(key)")
            return
        }
        let value = String(cString: valuePointer)
        let mutation: SecretMutation = ifAbsentOrEqual
            ? .saveIfAbsentOrEqual(account: key, value: value)
            : .save(account: key, value: value, accessibility: .whenUnlocked)
        handleMutation(
            mutation,
            on: peer,
            message: message,
            cancellation: cancellation,
            caller: caller
        )
    }

    private func handleLoad(_ message: xpc_object_t, on peer: xpc_connection_t) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key") else {
            reply(peer, to: message, ok: false, error: "invalid load request")
            return
        }
        let key = String(cString: keyPointer)
        guard validSecretKeyName(key) else {
            reply(peer, to: message, ok: false, error: "invalid secret name: \(key)")
            return
        }
        guard let value = loadStoredSecret(account: key) else {
            reply(peer, to: message, ok: false, error: "failed to load secret \(key): \(errSecItemNotFound)")
            return
        }
        reply(peer, to: message, ok: true, error: nil, value: value)
    }

    private func handleBless(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        identity: AVProcessIdentity
    ) {
        guard let pathPointer = xpc_dictionary_get_string(message, "path") else {
            reply(peer, to: message, ok: false, error: "invalid bless request")
            return
        }
        let path = String(cString: pathPointer)
        guard path.hasPrefix("/"),
              URL(fileURLWithPath: path).standardizedFileURL.path == path,
              URL(fileURLWithPath: path).resolvingSymlinksInPath().path == path
        else {
            reply(peer, to: message, ok: false, error: "script path must be canonical")
            return
        }
        guard let data = try? readBlessedScript(path: path),
              let declaration = try? blessedScriptDeclaration(data: data)
        else {
            reply(peer, to: message, ok: false, error: "script is not a valid blessable file")
            return
        }
        let metadata = hardeners ?? loadHardenerMetadata(avExecutableURL: avExecutableURL())
        for (id, protection) in declaration.manifest.capabilities {
            guard let descriptor = metadata.lazy.compactMap(\.secretGate).first(where: { $0.id == id }) else {
                reply(peer, to: message, ok: false, error: "unknown script capability: \(id)")
                return
            }
            let gate = SecretGate(
                id: descriptor.id,
                keyPatterns: descriptor.keyPatterns,
                routes: descriptor.routes,
                defaultProtection: .noAccess,
                appPolicies: []
            )
            guard gate.availableProtections.contains(gate.normalizedProtection(protection)) else {
                reply(peer, to: message, ok: false, error: "unsupported access level for \(id)")
                return
            }
        }
        if loadBlessedScripts().contains(where: {
            $0.matchesBlessing(path: path, checksum: declaration.checksum)
        }) {
            reply(peer, to: message, ok: true, error: nil, value: "already blessed")
            return
        }
        let launcher = xpc_dictionary_get_bool(message, "endorse_caller")
            ? launcherIdentities(for: identity).first { !$0.isStandalone }
            : nil
        let request = BlessedScriptReviewRequest(
            path: path,
            declaration: declaration,
            launcher: launcher.map {
                BlessedScriptLauncher(
                    bundleIdentifier: $0.identifier,
                    requirement: $0.designatedRequirement
                )
            }
        )
        DispatchQueue.main.async {
            guard self.canRequestHumanApproval() else {
                self.reply(peer, to: message, ok: false, error: "user approval is unavailable")
                return
            }
            self.onBlessRequest(request) { error in
                self.reply(peer, to: message, ok: error == nil, error: error)
            }
        }
    }

    private func handleGhSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              isGhTokenKey(String(cString: keyPointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid GitHub token key")
            return
        }
        handleSave(message, on: peer, cancellation: cancellation, caller: caller)
    }

    private func handleGhDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              isGhTokenKey(String(cString: keyPointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid GitHub token key")
            return
        }
        handleDelete(message, on: peer, cancellation: cancellation, caller: caller)
    }

    private func handleStripeSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              isStripeCredentialKey(String(cString: keyPointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid Stripe credential key")
            return
        }
        handleSave(message, on: peer, cancellation: cancellation, caller: caller)
    }

    private func handleStripeDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              isStripeCredentialKey(String(cString: keyPointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid Stripe credential key")
            return
        }
        handleDelete(message, on: peer, cancellation: cancellation, caller: caller)
    }

    private func handleDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key") else {
            reply(peer, to: message, ok: false, error: "invalid delete request")
            return
        }
        let key = String(cString: keyPointer)
        guard validSecretKeyName(key) else {
            reply(peer, to: message, ok: false, error: "invalid secret name: \(key)")
            return
        }
        handleMutation(
            .delete(account: key),
            on: peer,
            message: message,
            cancellation: cancellation,
            caller: caller
        )
    }

    private func handleMutation(
        _ mutation: SecretMutation,
        on peer: xpc_connection_t,
        message: xpc_object_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        let launcher = launcherIdentities(for: caller.identity).first
        let launcherFallbackPath = launcherFallbackPath(for: caller.identity) ?? caller.path
        DispatchQueue.main.async {
            let result = performApprovedSecretMutation(
                mutation,
                callerPath: caller.path,
                pid: caller.pid,
                signing: caller.signing,
                launcher: launcher,
                launcherFallbackPath: launcherFallbackPath,
                canRequestHumanApproval: self.canRequestHumanApproval,
                onAccessRequest: self.onAccessRequest,
                cancellation: cancellation
            )
            guard let status = result.status else {
                self.reply(peer, to: message, ok: false, error: result.error)
                return
            }
            switch mutation {
            case .save(let account, _, _), .saveIfAbsentOrEqual(let account, _):
                if status == errSecSuccess {
                    self.reply(peer, to: message, ok: true, error: nil)
                } else {
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "failed to store secret \(account): \(status)"
                    )
                }
            case .delete(let account):
                if status == errSecSuccess || status == errSecItemNotFound {
                    self.reply(peer, to: message, ok: true, error: nil)
                } else {
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "failed to delete secret \(account): \(status)"
                    )
                }
            case .rename, .setAccessibility:
                self.reply(peer, to: message, ok: false, error: "invalid XPC mutation")
            }
        }
    }

    private func approvedSecrets(for request: ApprovalRequest) throws -> [String: String] {
        let conflicts = Set(request.envConflicts)
        var secrets: [String: String] = [:]
        for key in request.keys where request.replaceExistingEnv || !conflicts.contains(key) {
            guard let value = loadStoredSecret(account: key) else {
                if request.allowMissingKeys { continue }
                throw AppError("failed to load secret \(key): \(errSecItemNotFound)")
            }
            secrets[key] = value
        }
        return secrets
    }

    private func awsRegistrationCandidate(
        from message: xpc_object_t,
        request: ApprovalRequest
    ) throws -> AWSRegistrationCandidate? {
        guard request.tool == "aws" else { return nil }
        guard let profilePointer = xpc_dictionary_get_string(message, "aws_profile"),
              let config = xpcData(message, key: "aws_config"),
              let configText = String(data: config, encoding: .utf8)
        else { throw AWSCredentialError.invalidConfig("registration is incomplete") }
        let chain = try AWSProfileChain.parse(
            configText,
            selectedProfile: String(cString: profilePointer)
        )
        let firstLine = try String(contentsOfFile: request.target, encoding: .utf8)
            .split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)[0]
        let interpreter = try awsInterpreter(fromShebang: String(firstLine))
        return AWSRegistrationCandidate(
            chain: chain,
            args: request.args,
            target: request.target,
            interpreter: interpreter,
            useLongLivedCredentials: awsRequestMayUseLongLivedCredentials(request)
                && chain.selected.roleARN == nil
                && chain.selected.mfaSerial == nil
        )
    }

    private func approvedPayload(
        for request: ApprovalRequest,
        awsRegistration: AWSRegistrationCandidate?,
        pid: pid_t,
        identity: AVProcessIdentity
    ) throws -> ApprovedPayload {
        let secrets = try approvedSecrets(for: request)
        guard let awsRegistration else { return ApprovedPayload(secrets: secrets, value: nil) }
        let key = BlessedExecutionKey(pid: pid, startUsec: identity.start_usec)
        awsRegistrationsLock.lock()
        awsRegistrations = awsRegistrations.filter { key, _ in
            var current = AVProcessIdentity()
            return av_process_identity(key.pid, &current) && current.start_usec == key.startUsec
        }
        awsRegistrations[key] = AWSRegistration(
            chain: awsRegistration.chain,
            args: awsRegistration.args,
            target: awsRegistration.target,
            interpreter: awsRegistration.interpreter,
            useLongLivedCredentials: awsRegistration.useLongLivedCredentials,
            credentials: nil
        )
        awsRegistrationsLock.unlock()
        let section = awsRegistration.chain.selected.name == "default"
            ? "default"
            : "profile \(awsRegistration.chain.selected.name)"
        let config = """
        [\(section)]
        credential_process = /usr/local/bin/av aws-credentials
        region = \(awsRegistration.chain.region)

        """
        return ApprovedPayload(secrets: [:], value: config)
    }

    private func handleAWSCredentials(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        pid: pid_t,
        identity: AVProcessIdentity
    ) {
        let parentPID = identity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity) else {
            reply(peer, to: message, ok: false, error: "AWS credential helper has no live parent")
            return
        }
        let key = BlessedExecutionKey(pid: parentPID, startUsec: parentIdentity.start_usec)
        awsRegistrationsLock.lock()
        awsRegistrations = awsRegistrations.filter { key, _ in
            var current = AVProcessIdentity()
            return av_process_identity(key.pid, &current) && current.start_usec == key.startUsec
        }
        let registration = awsRegistrations[key]
        awsRegistrationsLock.unlock()
        guard let registration else {
            reply(peer, to: message, ok: false, error: "AWS credential helper is not a direct child of a registered AWS process")
            return
        }
        let parentPath = pathString(parentIdentity)
        guard let arguments = processArguments(parentPID),
              awsRuntimeMatches(
                  interpreter: registration.interpreter,
                  processPath: parentPath,
                  processArguments: arguments,
                  target: registration.target,
                  approvedArguments: registration.args
              )
        else {
            reply(peer, to: message, ok: false, error: "registered AWS process runtime does not match its approved executable and arguments")
            return
        }
        if let credentials = registration.credentials,
           credentials.expiration.map({ $0.timeIntervalSinceNow > 5 * 60 }) ?? true
        {
            do {
                reply(peer, to: message, ok: true, error: nil, value: String(decoding: try credentials.credentialProcessJSON(), as: UTF8.self))
            } catch {
                reply(peer, to: message, ok: false, error: error.localizedDescription)
            }
            return
        }

        Task { @MainActor in
            do {
                let credentials = try await self.resolveAWSCredentials(
                    registration,
                    parentPID: parentPID
                )
                var liveIdentity = AVProcessIdentity()
                guard av_process_identity(parentPID, &liveIdentity),
                      liveIdentity.start_usec == key.startUsec
                else { throw AppError("registered AWS process exited before credentials were ready") }
                self.awsRegistrationsLock.withLock {
                    self.awsRegistrations[key]?.credentials = credentials
                }
                self.reply(
                    peer,
                    to: message,
                    ok: true,
                    error: nil,
                    value: String(decoding: try credentials.credentialProcessJSON(), as: UTF8.self)
                )
            } catch {
                self.reply(peer, to: message, ok: false, error: error.localizedDescription)
            }
        }
    }

    @MainActor
    private func resolveAWSCredentials(
        _ registration: AWSRegistration,
        parentPID: pid_t
    ) async throws -> AWSCredentials {
        guard let accessKey = loadStoredSecret(account: "AWS_ACCESS_KEY_ID"),
              let secretKey = loadStoredSecret(account: "AWS_SECRET_ACCESS_KEY")
        else { throw AppError("AWS access keys are missing from Automic Vault") }
        var credentials = AWSCredentials(accessKeyID: accessKey, secretAccessKey: secretKey)
        if registration.useLongLivedCredentials { return credentials }

        let profiles = registration.chain.profiles
        let base = profiles[0]
        if let serial = base.mfaSerial {
            credentials = try await requestSTSCredentials(
                region: registration.chain.region,
                parameters: [
                    "Action": "GetSessionToken",
                    "Version": "2011-06-15",
                    "DurationSeconds": "3600",
                    "SerialNumber": serial,
                    "TokenCode": try requestMFACode(serial: serial),
                ],
                credentials: credentials
            )
        } else if profiles.count == 1 {
            credentials = try await requestSTSCredentials(
                region: registration.chain.region,
                parameters: [
                    "Action": "GetSessionToken",
                    "Version": "2011-06-15",
                    "DurationSeconds": "3600",
                ],
                credentials: credentials
            )
        }
        for profile in profiles.dropFirst() {
            guard let roleARN = profile.roleARN else {
                throw AWSCredentialError.unsupportedProfile("\(profile.name) does not define role_arn")
            }
            var parameters = [
                "Action": "AssumeRole",
                "Version": "2011-06-15",
                "DurationSeconds": "3600",
                "RoleArn": roleARN,
                "RoleSessionName": "automic-vault-\(parentPID)",
            ]
            if let serial = profile.mfaSerial {
                parameters["SerialNumber"] = serial
                parameters["TokenCode"] = try requestMFACode(serial: serial)
            }
            credentials = try await requestSTSCredentials(
                region: registration.chain.region,
                parameters: parameters,
                credentials: credentials
            )
        }
        return credentials
    }

    @MainActor
    private func requestMFACode(serial: String) throws -> String {
        guard canRequestHumanApproval() else { throw AppError("AWS MFA unavailable while the user session is inactive") }
        let alert = NSAlert()
        alert.messageText = "AWS MFA required"
        alert.informativeText = "Enter the current code for \(serial). Automic Vault does not run mfa_process commands."
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.placeholderString = "123456"
        field.setAccessibilityLabel("AWS MFA code")
        alert.accessoryView = field
        guard alert.runModal() == .alertFirstButtonReturn else { throw AppError("AWS MFA canceled") }
        let code = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code.count >= 6, code.count <= 8, code.allSatisfy(\.isNumber) else {
            throw AppError("AWS MFA code must contain 6 to 8 digits")
        }
        return code
    }

    private func requestSTSCredentials(
        region: String,
        parameters: [String: String],
        credentials: AWSCredentials
    ) async throws -> AWSCredentials {
        let signed = try awsSTSRequest(
            region: region,
            parameters: parameters,
            credentials: credentials
        )
        var request = URLRequest(url: signed.url)
        request.httpMethod = "POST"
        request.httpBody = signed.body
        request.timeoutInterval = 30
        for (name, value) in signed.headers { request.setValue(value, forHTTPHeaderField: name) }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = false
        let (data, response) = try await URLSession(configuration: configuration).data(for: request)
        guard data.count <= 1024 * 1024 else {
            throw AWSCredentialError.invalidResponse("STS response exceeds 1 MiB")
        }
        guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode) else {
            do {
                _ = try parseAWSTSCredentials(data)
            } catch {
                throw error
            }
            throw AWSCredentialError.invalidResponse("STS returned HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        return try parseAWSTSCredentials(data)
    }

    private func processArguments(_ pid: pid_t) -> [String]? {
        var buffer = [CChar](repeating: 0, count: 64 * 1024)
        guard av_process_arguments(pid, &buffer, buffer.count) else { return nil }
        let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
        let text = String(decoding: buffer[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    }


    private func approvalRequest(from message: xpc_object_t) -> ApprovalRequest? {
        guard let opPointer = xpc_dictionary_get_string(message, "op"),
              let targetPointer = xpc_dictionary_get_string(message, "target"),
              let cwdPointer = xpc_dictionary_get_string(message, "cwd"),
              let keys = stringArray(message, "keys"),
              let args = stringArray(message, "args"),
              let envConflicts = stringArray(message, "env_conflicts")
        else {
            return nil
        }
        let op = String(cString: opPointer)
        guard op == "inject" || op == "keys" || op == "authorize" else { return nil }
        let scriptData: Data?
        if xpc_dictionary_get_value(message, "script_data") != nil {
            guard let data = xpcData(message, key: "script_data") else { return nil }
            scriptData = data
        } else {
            scriptData = nil
        }

        return ApprovalRequest(
            op: op,
            keys: keys,
            target: String(cString: targetPointer),
            args: args,
            cwd: String(cString: cwdPointer),
            replaceExistingEnv: xpc_dictionary_get_bool(message, "replace_existing_env"),
            allowMissingKeys: xpc_dictionary_get_bool(message, "allow_missing_keys"),
            envConflicts: envConflicts,
            shebangScript: xpc_dictionary_get_string(message, "shebang_script").map(String.init(cString:)),
            scriptData: scriptData,
            tool: xpc_dictionary_get_string(message, "tool").map(String.init(cString:)),
            title: xpc_dictionary_get_string(message, "title").map(String.init(cString:)),
            detail: xpc_dictionary_get_string(message, "detail").map(String.init(cString:))
        )
    }

    private func stringArray(_ message: xpc_object_t, _ key: String) -> [String]? {
        guard let value = xpc_dictionary_get_value(message, key),
              xpc_get_type(value) == XPC_TYPE_ARRAY
        else {
            return nil
        }
        var strings: [String] = []
        for index in 0..<xpc_array_get_count(value) {
            guard let pointer = xpc_array_get_string(value, index) else { return nil }
            strings.append(String(cString: pointer))
        }
        return strings
    }

    private func xpcData(_ message: xpc_object_t, key: String) -> Data? {
        var length = 0
        guard let bytes = xpc_dictionary_get_data(message, key, &length),
              length <= blessedScriptMaximumBytes
        else { return nil }
        return Data(bytes: bytes, count: length)
    }

    private func reply(
        _ peer: xpc_connection_t,
        to message: xpc_object_t,
        ok: Bool,
        error: String?,
        secrets: [String: String]? = nil,
        value: String? = nil,
        names: [String]? = nil,
        humanApprovalDecision: String? = nil
    ) {
        let response = xpc_dictionary_create_reply(message) ?? xpc_dictionary_create_empty()
        xpc_dictionary_set_bool(response, "ok", ok)
        if let error {
            error.withCString {
                xpc_dictionary_set_string(response, "error", $0)
            }
        }
        if let secrets {
            let values = xpc_dictionary_create_empty()
            for (key, value) in secrets {
                key.withCString { keyPointer in
                    value.withCString { valuePointer in
                        xpc_dictionary_set_string(values, keyPointer, valuePointer)
                    }
                }
            }
            xpc_dictionary_set_value(response, "secrets", values)
        }
        if let value {
            value.withCString { xpc_dictionary_set_string(response, "value", $0) }
        }
        if let names {
            let array = xpc_array_create_empty()
            for name in names {
                name.withCString { xpc_array_set_string(array, XPC_ARRAY_APPEND, $0) }
            }
            xpc_dictionary_set_value(response, "names", array)
        }
        if let humanApprovalDecision {
            humanApprovalDecision.withCString {
                xpc_dictionary_set_string(response, "human_approval_decision", $0)
            }
        }
        xpc_connection_send_message(peer, response)
    }

    private func sendEvent(_ event: String, to peer: xpc_connection_t) {
        let message = xpc_dictionary_create_empty()
        event.withCString { xpc_dictionary_set_string(message, "event", $0) }
        xpc_connection_send_message(peer, message)
    }
}

private func matchingDirectAccessLauncher(
    request: ApprovalRequest,
    configuredGate: SecretGate?,
    trustedAVGateClient: Bool,
    launchers: [LauncherIdentity],
    rules: [DirectAccessRule]
) -> LauncherIdentity? {
    guard request.op == "inject", configuredGate == nil, trustedAVGateClient else { return nil }
    return launchers.first {
        directAccessAllows(
            secretNames: request.keys,
            launcherRequirement: $0.designatedRequirement,
            runtimeProtection: $0.runtimeProtection,
            rules: rules
        )
    }
}

private func retainedProvenanceWouldAuthorize(
    request: ApprovalRequest,
    configuredGate: SecretGate?,
    classification: SecretGateRequestClassification?,
    launcher: LauncherIdentity,
    directAccessRules: [DirectAccessRule],
    trustedAVGateClient: Bool
) -> Bool {
    if let configuredGate, let classification {
        guard let policy = resolveSecretGatePolicy(
            gate: configuredGate,
            launchers: [launcher]
        ) else { return false }
        return secretGateProtectionAllows(
            policy.protection,
            classification: classification
        )
    }
    return matchingDirectAccessLauncher(
        request: request,
        configuredGate: nil,
        trustedAVGateClient: trustedAVGateClient,
        launchers: [launcher],
        rules: directAccessRules
    ) != nil
}

private func retainedProcessApprovalExplanation(
    match: RetainedProcessProvenanceMatch,
    gateName: String
) -> String {
    let name = URL(fileURLWithPath: match.processPath).lastPathComponent
    let process = name.isEmpty ? "detached" : name
    let launcher = shortAppName(match.launcher.identifier)
    return "Automic Vault previously verified this running \(process) process under \(launcher), but that parent chain is no longer available. Keep Launcher Access for Detached Processes is off; enabling it would have automically authorized this request under the current \(gateName) policy."
}

private func isAllowedCaller(path: String, signing: SigningInfo) -> Bool {
    if isTrustedAvCaller(path: path, signing: signing) {
        return true
    }
    if isTrustedGhCaller(path: path, signing: signing) {
        return true
    }
    if isTrustedStripeCaller(path: path, signing: signing) {
        return true
    }
    if isTrustedBrewStubCaller(path: path, signing: signing) {
        return true
    }
    let name = URL(fileURLWithPath: path).lastPathComponent
    return (name == "supabase" || name == "supabase-go")
        && (signing.identifier == "supabase"
            || signing.identifier == "supabase-go"
            || signing.identifier == "com.supabase.cli")
}

private func isTrustedAvCaller(path: String, signing: SigningInfo) -> Bool {
    URL(fileURLWithPath: path).lastPathComponent == "av"
        && signing.identifier == "com.automicvault.av"
}

private func isTrustedGhCaller(path: String, signing: SigningInfo) -> Bool {
    URL(fileURLWithPath: path).lastPathComponent == "gh"
        && (signing.identifier == "gh" || signing.identifier == "com.github.cli")
}

private func isTrustedStripeCaller(path: String, signing: SigningInfo) -> Bool {
    URL(fileURLWithPath: path).lastPathComponent == "stripe"
        && signing.identifier == "stripe"
}

private func isTrustedBrewStubCaller(path: String, signing: SigningInfo) -> Bool {
    let name = URL(fileURLWithPath: path).lastPathComponent
    return (name == "brew" || name == "av-brew-stub")
        && signing.identifier == "com.automicvault.av-brew-stub"
}

private struct ResolvedSecretGatePolicy {
    let protection: SecretGateProtection
    let source: String
    let launcher: LauncherIdentity?
}

private func matchingSecretGate(
    request: ApprovalRequest,
    signing: SigningInfo,
    hardeners: [HardenerMetadata],
    service: String = secretGatePoliciesKeychainService
) -> SecretGate? {
    loadSecretGates(hardeners: hardeners, service: service).first {
        secretGateMatches($0, request: request, signing: signing)
    }
}

private func matchingSecretGateDefinition(
    request: ApprovalRequest,
    signing: SigningInfo,
    hardeners: [HardenerMetadata]
) -> SecretGate? {
    hardeners.lazy.compactMap(\.secretGate).map {
        SecretGate(
            id: $0.id,
            keyPatterns: $0.keyPatterns,
            routes: $0.routes,
            defaultProtection: .noAccess,
            appPolicies: []
        )
    }.first {
        secretGateMatches($0, request: request, signing: signing)
    }
}

private func secretGateMatches(
    _ gate: SecretGate,
    request: ApprovalRequest,
    signing: SigningInfo
) -> Bool {
    gate.routes.contains { route in
        route.operation == request.op
            && route.callerIdentifiers.contains(signing.identifier)
            && normalizedExecutablePath(route.targetPath) == normalizedExecutablePath(request.target)
            && route.scriptPath.map { standardizedPath($0, cwd: request.cwd) }
                == resolvedShebangScriptPath(request)
            && routeKeysMatch(route.keyPatterns, request.keys)
            && route.replaceExistingEnv == request.replaceExistingEnv
            && route.allowMissingKeys == request.allowMissingKeys
    }
}

private func routeKeysMatch(_ patterns: [String], _ keys: [String]) -> Bool {
    if patterns.isEmpty { return keys.isEmpty }
    guard !keys.isEmpty else { return false }
    if patterns.allSatisfy({ !$0.hasSuffix("*") }) {
        return patterns.sorted() == keys.sorted()
    }
    return keys.allSatisfy { key in
        patterns.contains { pattern in
            pattern.hasSuffix("*")
                ? key.hasPrefix(String(pattern.dropLast()))
                : key == pattern
        }
    }
}

private func resolveSecretGatePolicy(
    gate: SecretGate,
    launchers: [LauncherIdentity]
) -> ResolvedSecretGatePolicy? {
    for launcher in launchers {
        if let policy = gate.appPolicies.first(where: { $0.requirement == launcher.designatedRequirement }) {
            return ResolvedSecretGatePolicy(
                protection: !policy.runtimeRequirement.allows(launcher.runtimeProtection)
                    ? .noAccess
                    : policy.protection,
                source: shortAppName(launcher.identifier),
                launcher: launcher
            )
        }
    }
    guard let firstLauncher = launchers.first(where: { !$0.isStandalone }) else { return nil }
    return ResolvedSecretGatePolicy(
        protection: gate.defaultProtection,
        source: gate.defaultPolicyLabel,
        launcher: firstLauncher
    )
}

private func secretGateProtectionAllows(
    _ protection: SecretGateProtection,
    classification: SecretGateRequestClassification
) -> Bool {
    protection.allows(classification)
}

private func classifySecretGateRequest(
    gateID: String,
    request: ApprovalRequest
) -> SecretGateRequestClassification {
    switch gateID {
    case "gh":
        return ghRequestClassification(request.args)
    case "aws":
        if awsRequestMayUseLongLivedCredentials(request) { return .secretDump }
        return awsRequestIsReadOnly(awsCommandWords(request)) ? .readOnly : .mutating
    case "brew":
        return brewRequestClassification(request.args)
    default:
        return genericSecretGateRequestClassification(
            gateID: gateID,
            arguments: secretGateCommandWords(request)
        )
    }
}

private func secretGateCommandWords(_ request: ApprovalRequest) -> [String] {
    guard let scriptPath = resolvedShebangScriptPath(request) else { return request.args }
    guard let scriptIndex = request.args.firstIndex(where: {
        standardizedPath($0, cwd: request.cwd) == scriptPath
    }) else { return [] }
    return Array(request.args.dropFirst(scriptIndex + 1))
}

private func awsRequestMayUseLongLivedCredentials(_ request: ApprovalRequest) -> Bool {
    let words = awsCommandWords(awsCommandWords(request)).map { $0.lowercased() }
    guard words.count >= 2, words[1] != "help" else { return false }
    if words[0] == "iam" { return true }
    return words[0] == "sts"
        && words[1] != "assume-role"
        && words[1] != "get-caller-identity"
}

private func approvalRequestWithCredentialContext(_ request: ApprovalRequest) -> ApprovalRequest {
    guard awsRequestMayUseLongLivedCredentials(request) else { return request }
    return ApprovalRequest(
        op: request.op,
        keys: request.keys,
        target: request.target,
        args: request.args,
        cwd: request.cwd,
        replaceExistingEnv: request.replaceExistingEnv,
        allowMissingKeys: request.allowMissingKeys,
        envConflicts: request.envConflicts,
        shebangScript: request.shebangScript,
        scriptData: request.scriptData,
        tool: request.tool,
        title: "Use long-lived AWS credentials?",
        detail: "AWS does not allow non-MFA GetSessionToken credentials to call this operation. Unless the selected profile uses MFA or assumes a role, Automic Vault will provide your original AWS access keys directly to AWS CLI; they retain every IAM permission assigned to those keys."
    )
}

private func brewRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    if brewRequestIsReadOnly(args) { return .readOnly }
    if let command = args.first?.lowercased(), ["update", "up"].contains(command) { return .update }
    return .mutating
}

private func brewRequestIsReadOnly(_ args: [String]) -> Bool {
    guard let command = args.first?.lowercased() else { return true }
    if brewReadOnlyQueryOptions.contains(command) { return true }
    if command.hasPrefix("-") { return false }
    if command == "services" {
        guard args.count >= 2 else { return false }
        return ["list", "info"].contains(args[1].lowercased())
    }
    if command == "bundle" {
        guard args.count >= 2 else { return false }
        return ["check", "env", "list"].contains(args[1].lowercased())
    }
    return brewReadOnlyCommands.contains(command)
}

private let brewReadOnlyQueryOptions = Set([
    "--cache", "--caskroom", "--cellar", "--env", "--prefix", "--repository", "--taps",
    "--version", "-v"
])

private let brewReadOnlyCommands = Set([
    "casks", "cat", "command", "commands", "config", "deps", "desc", "doctor", "formula",
    "formulae", "help", "info", "leaves", "linkage", "list", "livecheck", "log", "ls",
    "missing", "options", "outdated", "readall", "search", "shellenv", "source", "tab",
    "tap-info", "unbottled", "uses", "vulns", "which-formula"
])

private func ghRequestIsSecretDump(_ args: [String]) -> Bool {
    let words = ghCommandWords(args).map { $0.lowercased() }
    guard words.count >= 2, words[0] == "auth" else { return false }
    return words[1] == "token"
        || (words[1] == "status" && words.dropFirst(2).contains("--show-token"))
}

private func awsRequestIsReadOnly(_ args: [String]) -> Bool {
    if args == ["--version"] { return true }
    let words = awsCommandWords(args).map { $0.lowercased() }
    guard let service = words.first else { return false }
    if service == "help" { return true }
    guard words.count >= 2 else { return false }
    let operation = words[1]
    if operation == "help" { return true }
    return awsCommandIsReadOnly(service: service, operation: operation)
}

private func awsCommandWords(_ request: ApprovalRequest) -> [String] {
    if request.tool == "aws" { return request.args }
    guard let scriptPath = resolvedShebangScriptPath(request),
          let scriptIndex = request.args.firstIndex(where: {
              standardizedPath($0, cwd: request.cwd) == scriptPath
          })
    else {
        return []
    }
    return Array(request.args.dropFirst(scriptIndex + 1))
}

private func awsCommandWords(_ args: [String]) -> [String] {
    var index = 0
    while index < args.count {
        let arg = args[index]
        if arg == "--" {
            return []
        }
        if awsGlobalOptionsWithValue.contains(arg) {
            index += 2
            continue
        }
        if awsGlobalOptionsWithValue.contains(where: { arg.hasPrefix("\($0)=") }) || awsGlobalFlags.contains(arg) {
            index += 1
            continue
        }
        if arg.hasPrefix("-") {
            return []
        }
        return Array(args[index...])
    }
    return []
}

private let awsGlobalOptionsWithValue = Set([
    "--ca-bundle",
    "--cli-binary-format",
    "--cli-input-json",
    "--cli-input-yaml",
    "--color",
    "--endpoint-url",
    "--max-items",
    "--output",
    "--page-size",
    "--profile",
    "--query",
    "--region",
    "--starting-token"
])

private let awsGlobalFlags = Set([
    "--debug",
    "--no-cli-auto-prompt",
    "--no-cli-pager",
    "--no-paginate",
    "--no-sign-request",
    "--no-verify-ssl",
    "--only-show-errors",
    "--version"
])

private func standardizedPath(_ path: String, cwd: String) -> String {
    let url = path.hasPrefix("/")
        ? URL(fileURLWithPath: path)
        : URL(fileURLWithPath: cwd).appendingPathComponent(path)
    return url.standardizedFileURL.path
}

private func ghRequestIsReadOnly(_ args: [String]) -> Bool {
    let words = ghCommandWords(args)
    guard let firstWord = words.first else { return false }
    let command = ghCanonicalCommand(firstWord.lowercased())
    if words.contains("--show-token") { return false }
    if command == "api" {
        return ghApiRequestClassification(Array(words.dropFirst())) == .readOnly
    }
    if ["alias", "extension", "config", "skill"].contains(command) { return false }
    if ["status", "browse", "search"].contains(command) { return true }
    guard words.count >= 2 else { return false }
    let subcommand = words[1].lowercased()
    switch command {
    case "auth":
        return subcommand == "status"
    case "repo":
        return subcommand == "view" || ghSubcommandIsList(subcommand)
    case "issue":
        return ["view", "status"].contains(subcommand) || ghSubcommandIsList(subcommand)
    case "pr":
        return ["view", "status", "checks", "diff"].contains(subcommand) || ghSubcommandIsList(subcommand)
    case "run":
        return subcommand == "view" || ghSubcommandIsList(subcommand)
    case "workflow":
        return subcommand == "view" || ghSubcommandIsList(subcommand)
    case "release":
        return subcommand == "view" || ghSubcommandIsList(subcommand)
    case "gist":
        return subcommand == "view" || ghSubcommandIsList(subcommand)
    case "cache", "secret", "variable", "ruleset", "org", "label", "gpg-key", "ssh-key":
        return ghSubcommandIsList(subcommand) || (command == "ruleset" && subcommand == "view")
    case "attestation":
        return ["verify", "trusted-root"].contains(subcommand)
    case "agent-task":
        return ["view", "list"].contains(subcommand)
    default:
        return false
    }
}

private func ghRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    if ghRequestIsSecretDump(args) { return .secretDump }
    if ghRequestIsReadOnly(args) { return .readOnly }
    if ghRequestIsLocalWrite(args) { return .localWrite }
    return .mutating
}

private func ghRequestIsLocalWrite(_ args: [String]) -> Bool {
    let words = ghCommandWords(args)
    guard words.count >= 2 else { return false }
    let command = ghCanonicalCommand(words[0].lowercased())
    let subcommand = words[1].lowercased()
    switch command {
    case "repo":
        return subcommand == "clone"
    case "pr":
        return subcommand == "checkout"
    case "gist":
        return subcommand == "clone"
    case "run", "release", "attestation":
        return subcommand == "download"
    default:
        return false
    }
}

private func ghCanonicalCommand(_ command: String) -> String {
    switch command {
    case "agent-tasks", "agent", "agents":
        return "agent-task"
    case "at":
        return "attestation"
    case "rs":
        return "ruleset"
    default:
        return command
    }
}

private func ghSubcommandIsList(_ subcommand: String) -> Bool {
    subcommand == "list" || subcommand == "ls"
}

private enum GhApiRequestClassification {
    case readOnly
    case indirectGraphQLInput
    case other
}

private func ghApiRequestClassification(_ args: [String]) -> GhApiRequestClassification {
    var index = 0
    var endpoints: [String] = []
    var method: String?
    var hasFields = false
    var graphQLArguments = GhGraphQLArguments()
    while index < args.count {
        let arg = args[index]
        switch arg {
        case "--":
            return .other
        case "-X", "--method":
            guard index + 1 < args.count else { return .other }
            method = args[index + 1].uppercased()
            index += 2
        case "-f", "--raw-field", "-F", "--field":
            guard index + 1 < args.count else { return .other }
            hasFields = true
            graphQLArguments.add(field: args[index + 1], readsFile: arg == "-F" || arg == "--field")
            index += 2
        case "--input":
            return .other
        case "-H", "--header", "-p", "--preview", "--cache", "-q", "--jq", "-t", "--template", "--hostname":
            guard index + 1 < args.count else { return .other }
            index += 2
        case "-i", "--include", "--paginate", "--slurp", "--silent", "--verbose":
            index += 1
        default:
            if let value = arg.value(afterOption: "--method=") {
                method = value.uppercased()
            } else if let field = arg.value(afterOption: "--field=") {
                hasFields = true
                graphQLArguments.add(field: field, readsFile: true)
            } else if let field = arg.value(afterOption: "--raw-field=") {
                hasFields = true
                graphQLArguments.add(field: field, readsFile: false)
            } else if arg.hasPrefix("--input=") {
                return .other
            } else if arg.hasPrefix("--header=")
                || arg.hasPrefix("--preview=")
                || arg.hasPrefix("--cache=")
                || arg.hasPrefix("--jq=")
                || arg.hasPrefix("--template=")
                || arg.hasPrefix("--hostname=") {
                // read-only option with inline value
            } else if arg.hasPrefix("-X"), arg.count > 2 {
                method = String(arg.dropFirst(2)).uppercased()
            } else if arg.hasPrefix("-f"), arg.count > 2 {
                hasFields = true
                graphQLArguments.add(field: String(arg.dropFirst(2)), readsFile: false)
            } else if arg.hasPrefix("-F"), arg.count > 2 {
                hasFields = true
                graphQLArguments.add(field: String(arg.dropFirst(2)), readsFile: true)
            } else if arg.hasPrefix("-") {
                return .other
            } else {
                endpoints.append(arg)
            }
            index += 1
        }
    }
    guard endpoints.count == 1 else { return .other }
    if endpoints[0] == "graphql" {
        if graphQLArguments.usesIndirectFieldInput { return .indirectGraphQLInput }
        return graphQLArguments.isReadOnly ? .readOnly : .other
    }
    return (method ?? (hasFields ? "POST" : "GET")) == "GET" ? .readOnly : .other
}

private func secretGateAutomaticApprovalExplanation(
    gateID: String,
    request: ApprovalRequest
) -> String? {
    guard gateID == "gh" else { return nil }
    return ghGraphQLIndirectInputExplanation(request.args)
}

private func ghGraphQLIndirectInputExplanation(_ args: [String]) -> String? {
    let words = ghCommandWords(args)
    guard words.first?.lowercased() == "api",
          ghApiRequestClassification(Array(words.dropFirst())) == .indirectGraphQLInput
    else {
        return nil
    }
    return "Automic Vault could not verify this GraphQL request as read-only because gh will read a field value from standard input or a file. That content is not present in the authorization request, so automic authorization fails closed. Pass field values inline, for example with -f query=…, to make them verifiable."
}

private struct GhGraphQLArguments {
    private var queries: [String] = []
    private var operationNames: [String] = []
    private var hasIndirectFieldInput = false

    var usesIndirectFieldInput: Bool { hasIndirectFieldInput }

    mutating func add(field: String, readsFile: Bool) {
        let parts = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return }

        let name = String(parts[0])
        let value = String(parts[1])
        if readsFile, value.hasPrefix("@") {
            hasIndirectFieldInput = true
            return
        }
        guard name == "query" || name == "operationName" else { return }
        if name == "query" {
            queries.append(value)
        } else {
            operationNames.append(value)
        }
    }

    var isReadOnly: Bool {
        guard !hasIndirectFieldInput,
              queries.count == 1,
              operationNames.count <= 1,
              let query = queries.first
        else {
            return false
        }
        return graphQLRequestIsReadOnly(query: query, operationName: operationNames.first)
    }
}

private func ghCommandWords(_ args: [String]) -> [String] {
    var index = 0
    while index < args.count {
        let arg = args[index]
        if arg == "--" {
            return []
        }
        if ["-R", "--repo", "--hostname"].contains(arg) {
            index += 2
            continue
        }
        if arg.hasPrefix("--repo=") || arg.hasPrefix("--hostname=") {
            index += 1
            continue
        }
        if arg.hasPrefix("-") {
            return []
        }
        return Array(args[index...])
    }
    return []
}

private extension String {
    func value(afterOption prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}

private func validSecretKeyName(_ key: String) -> Bool {
    guard let first = key.unicodeScalars.first,
          first == "_" || first.isASCIIAlpha
    else {
        return false
    }
    return key.unicodeScalars.dropFirst().allSatisfy {
        $0 == "_" || $0.isASCIIAlpha || $0.isASCIIDigit
    }
}

private func isGhTokenKey(_ key: String) -> Bool {
    key.hasPrefix("GH_TOKEN_") && validSecretKeyName(key)
}

private func isStripeCredentialKey(_ key: String) -> Bool {
    key.hasPrefix("STRIPE_CLI_") && validSecretKeyName(key)
}

private extension UnicodeScalar {
    var isASCIIAlpha: Bool {
        (65...90).contains(value) || (97...122).contains(value)
    }

    var isASCIIDigit: Bool {
        (48...57).contains(value)
    }
}

private struct AppError: LocalizedError {
    let errorDescription: String?

    init(_ description: String) {
        errorDescription = description
    }
}

private func handOffToLaunchAgentIfNeeded() throws -> Bool {
    guard shouldHandOffToLaunchAgent(),
          let launchAgent = bundledLaunchAgentURL(),
          let executableURL = Bundle.main.executableURL
    else {
        return false
    }

    let installed = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/LaunchAgents/\(approvalLaunchAgentName).plist")
    try FileManager.default.createDirectory(
        at: installed.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let template = try Data(contentsOf: launchAgent)
    let configured = try configuredLaunchAgent(template: template, executableURL: executableURL)
    let configurationChanged = !launchAgentConfigurationsMatch(
        try? Data(contentsOf: installed),
        configured
    )

    let domain = "gui/\(getuid())"
    let service = "\(domain)/\(approvalLaunchAgentName)"
    if !configurationChanged {
        do {
            try runLaunchctl(["kickstart", "-k", service])
            return true
        } catch {
            // The matching plist may exist while its job is not loaded.
        }
    }
    try configured.write(to: installed, options: .atomic)
    try? runLaunchctl(["bootout", service])
    do {
        try runLaunchctl(["bootstrap", domain, installed.path])
    } catch {
        usleep(200_000)
        try runLaunchctl(["bootstrap", domain, installed.path])
    }
    try runLaunchctl(["enable", service])
    try runLaunchctl(["kickstart", "-k", service])
    return true
}

private func launchAgentConfigurationsMatch(_ lhsData: Data?, _ rhsData: Data) -> Bool {
    guard let lhsData,
          let lhs = try? PropertyListSerialization.propertyList(from: lhsData, format: nil)
            as? NSDictionary,
          let rhs = try? PropertyListSerialization.propertyList(from: rhsData, format: nil)
            as? NSDictionary
    else {
        return false
    }
    return lhs == rhs
}

private func configuredLaunchAgent(template: Data, executableURL: URL) throws -> Data {
    guard var plist = try PropertyListSerialization.propertyList(from: template, format: nil) as? [String: Any]
    else {
        throw AppError("The bundled launch agent is invalid.")
    }
    plist["ProgramArguments"] = [executableURL.path]
    return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
}

private func shouldHandOffToLaunchAgent(
    environment: [String: String] = ProcessInfo.processInfo.environment,
    launchAgentURL: URL? = bundledLaunchAgentURL()
) -> Bool {
    !isLaunchAgentInstance(environment: environment) && launchAgentURL != nil
}

private func bundledLaunchAgentURL() -> URL? {
    let url = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Library/LaunchAgents/\(approvalLaunchAgentName).plist")
    return FileManager.default.fileExists(atPath: url.path) ? url : nil
}

private func isLaunchAgentInstance(
    environment: [String: String] = ProcessInfo.processInfo.environment
) -> Bool {
    environment["XPC_SERVICE_NAME"] == approvalLaunchAgentName
}

private func shouldOpenMainWindow(
    arguments: [String] = CommandLine.arguments,
    pending: Bool,
    environment: [String: String] = ProcessInfo.processInfo.environment
) -> Bool {
    pending || arguments.contains(openMainWindowArgument) || !isLaunchAgentInstance(environment: environment)
}

private func requestedSecretGateID(arguments: [String]) -> String? {
    guard let flag = arguments.firstIndex(of: "--secret-gate"),
          arguments.indices.contains(flag + 1)
    else { return nil }
    let id = arguments[flag + 1]
    return validSecretGateID(id) ? id : nil
}

private func secretGateID(from url: URL) -> String? {
    guard url.scheme == "automic-vault",
          url.host == "secret-gate",
          url.pathComponents.count == 2
    else { return nil }
    let id = url.lastPathComponent
    return validSecretGateID(id) ? id : nil
}

private func validSecretGateID(_ id: String) -> Bool {
    !id.isEmpty && id.utf8.allSatisfy {
        switch $0 {
        case 45, 46, 48...57, 65...90, 95, 97...122: true
        default: false
        }
    }
}

private func runLaunchctl(_ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    process.arguments = arguments
    let pipe = Pipe()
    process.standardError = pipe
    process.standardOutput = pipe
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        throw AppError("launchctl \(arguments.joined(separator: " ")) failed: \(output ?? "exit \(process.terminationStatus)")")
    }
}

private func pathString(_ identity: AVProcessIdentity) -> String {
    var copy = identity
    return withUnsafePointer(to: &copy.path) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 4096) {
            String(cString: $0)
        }
    }
}

private func signingInfo(path: String) -> SigningInfo {
    var staticCode: SecStaticCode?
    let url = URL(fileURLWithPath: path) as CFURL
    guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
          let staticCode,
          let info = copySigningInformation(staticCode)
    else {
        return SigningInfo(identifier: "unknown", teamIdentifier: "unknown")
    }

    return SigningInfo(
        identifier: info[kSecCodeInfoIdentifier] as? String ?? "unknown",
        teamIdentifier: info[kSecCodeInfoTeamIdentifier] as? String ?? "unknown"
    )
}

private func selfTeamIdentifier() -> String? {
    var code: SecCode?
    var staticCode: SecStaticCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess,
          let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
          let staticCode,
          let info = copySigningInformation(staticCode)
    else {
        return nil
    }
    return info[kSecCodeInfoTeamIdentifier] as? String
}

private func copySigningInformation(_ code: SecStaticCode) -> [CFString: Any]? {
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(
        code,
        SecCSFlags(rawValue: kSecCSSigningInformation),
        &info
    ) == errSecSuccess else {
        return nil
    }
    return info as? [CFString: Any]
}

private func launcherIdentities(for identity: AVProcessIdentity) -> [LauncherIdentity] {
    for pid in launcherAncestorStartPIDs(identity) {
        let launchers = launcherIdentities(startingAt: pid)
        if !launchers.isEmpty { return launchers }
    }
    return []
}

private func launcherAncestorStartPIDs(_ identity: AVProcessIdentity) -> [pid_t] {
    var seen = Set<pid_t>()
    return [identity.ppid, identity.sid].filter { $0 > 1 && seen.insert($0).inserted }
}

private func retainedProcessChains(for identity: AVProcessIdentity) -> [[RetainedProcessChainNode]] {
    launcherAncestorStartPIDs(identity).map { startPID in
        var nodes: [RetainedProcessChainNode] = []
        var pid = startPID
        var seen = Set<pid_t>()
        for _ in 0..<32 {
            guard pid > 1, seen.insert(pid).inserted else { break }
            var current = AVProcessIdentity()
            guard av_process_identity(pid, &current) else { break }
            nodes.append(RetainedProcessChainNode(
                pid: pid,
                path: pathString(current),
                execution: retainedProcessExecution(pid: pid, identity: current)
            ))
            pid = current.ppid
        }
        return nodes
    }
}

private func retainedProcessExecution(
    pid: pid_t,
    identity: AVProcessIdentity
) -> RetainedProcessExecution? {
    guard identity.pidversion > 0,
          identity.euid == geteuid(),
          let codeIdentity = liveCodeIdentity(pid: pid)
    else { return nil }

    var current = AVProcessIdentity()
    guard av_process_identity(pid, &current),
          current.pidversion == identity.pidversion,
          current.start_usec == identity.start_usec,
          current.euid == identity.euid,
          current.audit_session_id == identity.audit_session_id
    else { return nil }

    return RetainedProcessExecution(
        pid: pid,
        pidVersion: identity.pidversion,
        startUsec: identity.start_usec,
        effectiveUserID: identity.euid,
        auditSessionID: identity.audit_session_id,
        codeIdentity: codeIdentity
    )
}

private func retainedProcessExecutionIsLive(_ execution: RetainedProcessExecution) -> Bool {
    func matches(_ identity: AVProcessIdentity) -> Bool {
        identity.pidversion == execution.pidVersion
            && identity.start_usec == execution.startUsec
            && identity.euid == execution.effectiveUserID
            && identity.audit_session_id == execution.auditSessionID
    }
    var before = AVProcessIdentity()
    guard av_process_identity(execution.pid, &before),
          matches(before),
          liveCodeIdentity(pid: execution.pid) == execution.codeIdentity
    else { return false }
    var after = AVProcessIdentity()
    return av_process_identity(execution.pid, &after) && matches(after)
}

private func retainedExecutions(
    leadingTo launcherPID: pid_t,
    in chains: [[RetainedProcessChainNode]]
) -> [RetainedProcessExecution] {
    guard let chain = chains.first(where: { $0.contains(where: { $0.pid == launcherPID }) }),
          let launcherIndex = chain.firstIndex(where: { $0.pid == launcherPID })
    else { return [] }
    return chain[..<launcherIndex].compactMap(\.execution)
}

private func retainedExecutions(
    leadingTo retainedExecution: RetainedProcessExecution,
    in chains: [[RetainedProcessChainNode]]
) -> [RetainedProcessExecution] {
    guard let chain = chains.first(where: {
        $0.contains(where: { $0.execution == retainedExecution })
    }),
    let retainedIndex = chain.firstIndex(where: { $0.execution == retainedExecution })
    else { return [] }
    return chain[...retainedIndex].compactMap(\.execution)
}

private func executionOrigin(
    among launchers: [LauncherIdentity],
    callerPID: pid_t,
    ancestorFallbackPath: String?
) -> LauncherIdentity? {
    launchers.first { $0.pid != callerPID }
        ?? (ancestorFallbackPath == nil ? launchers.first : nil)
}

private func launcherFallbackPath(for identity: AVProcessIdentity) -> String? {
    launcherAncestorStartPIDs(identity)
        .compactMap(launcherAncestorPath(startingAt:))
        .max { $0.depth < $1.depth }?
        .path
}

private func approvalProcessChain(pid: pid_t) -> String? {
    var caller = AVProcessIdentity()
    guard av_process_identity(pid, &caller) else { return nil }
    var longest: [String] = []
    for startPID in launcherAncestorStartPIDs(caller) {
        var currentPID = startPID
        var seen = Set<pid_t>()
        var paths: [String] = []
        for _ in 0..<32 {
            guard currentPID > 1, seen.insert(currentPID).inserted else { break }
            var identity = AVProcessIdentity()
            guard av_process_identity(currentPID, &identity) else { break }
            let path = pathString(identity)
            if !path.isEmpty { paths.append(path) }
            currentPID = identity.ppid
        }
        if paths.count > longest.count { longest = paths }
    }
    let callerPath = pathString(caller)
    if !callerPath.isEmpty { longest.insert(callerPath, at: 0) }
    guard !longest.isEmpty else { return nil }
    return processChainLabel(paths: longest.reversed())
}

private func processChainLabel<S: Sequence>(paths: S) -> String where S.Element == String {
    paths.map { URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: " → ")
}

private func launcherAncestorPath(startingAt startPID: pid_t) -> (path: String, depth: Int)? {
    var pid = startPID
    var seen = Set<pid_t>()
    var result: (path: String, depth: Int)?
    for depth in 1...32 {
        guard pid > 1, seen.insert(pid).inserted else { return result }
        var identity = AVProcessIdentity()
        guard av_process_identity(pid, &identity) else { return result }
        let path = pathString(identity)
        if !path.isEmpty { result = (path, depth) }
        pid = identity.ppid
    }
    return result
}

private func launcherIdentities(startingAt startPID: pid_t) -> [LauncherIdentity] {
    var pid = startPID
    var seen = Set<pid_t>()
    var launchers: [LauncherIdentity] = []
    for _ in 0..<32 {
        guard pid > 1, seen.insert(pid).inserted else { return launchers }

        var identity = AVProcessIdentity()
        guard av_process_identity(pid, &identity) else { return launchers }
        launchers.append(contentsOf: launcherIdentities(pid: pid, identity: identity))
        pid = identity.ppid
    }
    return launchers
}

private func launcherIdentity(pid: pid_t, identity: AVProcessIdentity) -> LauncherIdentity? {
    launcherIdentities(pid: pid, identity: identity).first
}

private func launcherIdentities(pid: pid_t, identity: AVProcessIdentity) -> [LauncherIdentity] {
    let path = pathString(identity)
    if let signing = liveSigningInfo(pid: pid) {
        return launcherIdentities(pid: pid, path: path, signing: signing)
    }
    guard let signing = executableSigningInfo(path: path) else { return [] }
    // A path may now name a replacement binary, so it cannot prove the running process is standalone.
    return launcherIdentities(
        pid: pid,
        path: path,
        signing: signing,
        allowsStandaloneFallback: false
    )
}

private func launcherIdentity(
    pid: pid_t,
    path: String,
    signing: LiveSigningInfo,
    appSigning: (URL) -> StaticSigningInfo? = staticSigningInfo
) -> LauncherIdentity? {
    launcherIdentities(pid: pid, path: path, signing: signing, appSigning: appSigning).first
}

private func launcherIdentities(
    pid: pid_t,
    path: String,
    signing: LiveSigningInfo,
    appSigning: (URL) -> StaticSigningInfo? = staticSigningInfo,
    allowsStandaloneFallback: Bool = true
) -> [LauncherIdentity] {
    guard !signing.isAdHoc else { return [] }
    var seen = Set<String>()
    let appURLs = (
        appBundleURLs(containing: path)
        + appBundleURLs(containing: signing.mainExecutable)
        + [associatedAppBundleURL(path: path, signing: signing)].compactMap { $0 }
    ).filter { seen.insert($0.path).inserted }
    let apps: [LauncherIdentity] = appURLs.compactMap { appURL in
        guard let app = appSigning(appURL) else { return nil }
        return LauncherIdentity(
            pid: pid,
            path: path,
            identifier: app.identifier,
            teamIdentifier: app.teamIdentifier,
            designatedRequirement: app.designatedRequirement,
            runtimeProtection: signing.runtimeProtection
        )
    }
    if !apps.isEmpty { return apps }
    guard allowsStandaloneFallback,
          signing.isDeveloperID,
          signing.identifier != "unknown",
          signing.teamIdentifier != "unknown"
    else { return [] }
    return [LauncherIdentity(
        pid: pid,
        path: path,
        identifier: signing.identifier,
        teamIdentifier: signing.teamIdentifier,
        designatedRequirement: signing.designatedRequirement,
        runtimeProtection: signing.runtimeProtection,
        isStandalone: true
    )]
}

private struct LiveSigningInfo {
    let identifier: String
    let teamIdentifier: String
    let designatedRequirement: String
    let mainExecutable: String
    let isAdHoc: Bool
    let runtimeProtection: LauncherRuntimeProtection
    let isDeveloperID: Bool
}

private struct StaticSigningInfo {
    let identifier: String
    let teamIdentifier: String
    let designatedRequirement: String
}

private func runtimeProtection(_ dictionary: [CFString: Any]) -> LauncherRuntimeProtection {
    launcherRuntimeProtection(signingInformation: dictionary)
}

private struct LauncherAppVerificationFailure {
    let appName: String
    let resourcesUnreadable: Bool

    var explanation: String {
        if resourcesUnreadable {
            return "Automic authorization was unavailable because \(appName) contains signed app resources that Automic Vault cannot read, so its identity could not be securely verified. Approval is required to fail closed."
        }
        return "Automic authorization was unavailable because \(appName)’s code signature could not be securely verified. Approval is required to fail closed."
    }
}

private func liveSigningInfo(pid: pid_t) -> LiveSigningInfo? {
    var code: SecCode?
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
          let code
    else {
        return nil
    }
    guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }

    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
          let staticCode
    else {
        return nil
    }

    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any],
          let requirementValue = dictionary[kSecCodeInfoDesignatedRequirement]
    else {
        return nil
    }
    let requirement = requirementValue as! SecRequirement
    guard let requirementText = requirementString(requirement) else { return nil }

    let executable = (dictionary[kSecCodeInfoMainExecutable] as? URL)?.path ?? ""
    let signatureFlags = (dictionary[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
    return LiveSigningInfo(
        identifier: dictionary[kSecCodeInfoIdentifier] as? String ?? "unknown",
        teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier] as? String ?? "unknown",
        designatedRequirement: requirementText,
        mainExecutable: executable,
        isAdHoc: signatureFlags & secCodeSignatureAdHoc != 0,
        runtimeProtection: runtimeProtection(dictionary),
        isDeveloperID: satisfiesDeveloperIDRequirement {
            SecCodeCheckValidity(code, [], $0)
        }
    )
}

private func liveCodeIdentity(pid: pid_t) -> Data? {
    var code: SecCode?
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
          let code,
          SecCodeCheckValidity(code, [], nil) == errSecSuccess
    else { return nil }

    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
          let staticCode
    else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any]
    else { return nil }
    return dictionary[kSecCodeInfoUnique] as? Data
}

private func executableSigningInfo(path: String) -> LiveSigningInfo? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode,
          SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess
    else {
        return nil
    }

    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any],
          let requirementValue = dictionary[kSecCodeInfoDesignatedRequirement]
    else {
        return nil
    }
    let requirement = requirementValue as! SecRequirement
    guard let requirementText = requirementString(requirement) else { return nil }

    let executable = (dictionary[kSecCodeInfoMainExecutable] as? URL)?.path ?? path
    let signatureFlags = (dictionary[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
    return LiveSigningInfo(
        identifier: dictionary[kSecCodeInfoIdentifier] as? String ?? "unknown",
        teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier] as? String ?? "unknown",
        designatedRequirement: requirementText,
        mainExecutable: executable,
        isAdHoc: signatureFlags & secCodeSignatureAdHoc != 0,
        runtimeProtection: runtimeProtection(dictionary),
        isDeveloperID: satisfiesDeveloperIDRequirement {
            SecStaticCodeCheckValidity(staticCode, [], $0)
        }
    )
}

private func staticSigningInfo(url: URL) -> StaticSigningInfo? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode,
          SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess
    else {
        return nil
    }

    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any],
          let requirementValue = dictionary[kSecCodeInfoDesignatedRequirement],
          ((dictionary[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0) & secCodeSignatureAdHoc == 0
    else {
        return nil
    }
    let requirement = requirementValue as! SecRequirement
    guard let requirementText = requirementString(requirement) else { return nil }

    return StaticSigningInfo(
        identifier: dictionary[kSecCodeInfoIdentifier] as? String ?? "unknown",
        teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier] as? String ?? "unknown",
        designatedRequirement: requirementText
    )
}

private func launcherAppVerificationFailure(
    for identity: AVProcessIdentity
) -> LauncherAppVerificationFailure? {
    var checkedApps = Set<String>()
    for startPID in launcherAncestorStartPIDs(identity) {
        var pid = startPID
        var seenPIDs = Set<pid_t>()
        for _ in 0..<32 {
            guard pid > 1, seenPIDs.insert(pid).inserted else { break }
            var ancestor = AVProcessIdentity()
            guard av_process_identity(pid, &ancestor) else { break }
            let path = pathString(ancestor)
            if let signing = liveSigningInfo(pid: pid) ?? executableSigningInfo(path: path) {
                let appURLs = appBundleURLs(containing: path)
                    + appBundleURLs(containing: signing.mainExecutable)
                    + [associatedAppBundleURL(path: path, signing: signing)].compactMap { $0 }
                for appURL in appURLs where checkedApps.insert(appURL.path).inserted {
                    if let failure = appBundleVerificationFailure(appURL) { return failure }
                }
            }
            pid = ancestor.ppid
        }
    }
    return nil
}

private func appBundleVerificationFailure(_ url: URL) -> LauncherAppVerificationFailure? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode
    else {
        return nil
    }
    let status = SecStaticCodeCheckValidity(staticCode, [], nil)
    guard status != errSecSuccess else { return nil }
    let name = url.deletingPathExtension().lastPathComponent
    let executableOnly = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures | kSecCSDoNotValidateResources
    )
    let resourcesUnreadable = status == OSStatus(100_000 + EACCES)
        && SecStaticCodeCheckValidity(staticCode, executableOnly, nil) == errSecSuccess
    return LauncherAppVerificationFailure(
        appName: name,
        resourcesUnreadable: resourcesUnreadable
    )
}

// SecRequirement is immutable but is not annotated Sendable by Security.framework.
nonisolated(unsafe) private let developerIDRequirement: SecRequirement? = {
    var requirement: SecRequirement?
    let source = """
    anchor apple generic and \
    certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
    certificate leaf[field.1.2.840.113635.100.6.1.13] exists
    """
    guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess,
          let requirement
    else { return nil }
    return requirement
}()

func satisfiesDeveloperIDRequirement(
    _ validate: (SecRequirement) -> OSStatus
) -> Bool {
    guard let developerIDRequirement else { return false }
    return validate(developerIDRequirement) == errSecSuccess
}

private func requirementString(_ requirement: SecRequirement) -> String? {
    var text: CFString?
    guard SecRequirementCopyString(requirement, [], &text) == errSecSuccess,
          let text
    else {
        return nil
    }
    return text as String
}

private func isAppBundleExecutable(_ path: String) -> Bool {
    path.range(of: ".app/Contents/", options: [.caseInsensitive]) != nil
}

private func appBundleURL(containing path: String) -> URL? {
    appBundleURLs(containing: path).first
}

private func appBundleURLs(containing path: String) -> [URL] {
    var url = URL(fileURLWithPath: path)
    var apps: [URL] = []
    while url.path != "/" {
        if url.pathExtension.caseInsensitiveCompare("app") == .orderedSame {
            apps.append(url)
        }
        url.deleteLastPathComponent()
    }
    return apps
}

private func associatedAppBundleURL(path: String, signing: LiveSigningInfo) -> URL? {
    guard signing.identifier == "com.automicvault.vaultty.session-bridge",
          path.hasSuffix("/Library/Application Support/Vaultty/vaultty-session-bridge")
    else {
        return nil
    }
    return NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.automicvault.vaultty")
        ?? URL(fileURLWithPath: "/Applications/Vaultty.app")
}

private func scriptApproval(for request: ApprovalRequest) -> ScriptApproval? {
    guard let script = request.shebangScript else { return nil }
    let url = script.hasPrefix("/")
        ? URL(fileURLWithPath: script)
        : URL(fileURLWithPath: request.cwd).appendingPathComponent(script)
    let path = url.standardizedFileURL.resolvingSymlinksInPath().path
    guard let data = request.scriptData ?? (try? readBlessedScript(path: path)) else {
        return nil
    }
    let checksum = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return ScriptApproval(path: path, checksum: checksum)
}

private final class ApprovalPanel: NSPanel {
    private var allowsKey = false

    override var canBecomeKey: Bool { allowsKey }

    override func sendEvent(_ event: NSEvent) {
        if event.type == .leftMouseDown, !isKeyWindow {
            allowsKey = true
            makeKey()
        }
        super.sendEvent(event)
    }
}

@MainActor
private func fitApprovalPanel(_ panel: NSPanel, maximumHeight: CGFloat, animate: Bool) {
    guard let contentView = panel.contentView else { return }
    contentView.layoutSubtreeIfNeeded()
    var size = contentView.fittingSize
    size.height = min(size.height, maximumHeight)
    var frame = panel.frame
    let top = frame.maxY
    frame.size = size
    frame.origin.y = top - size.height
    if let visibleFrame = panel.screen?.visibleFrame ?? NSScreen.main?.visibleFrame {
        frame.origin.y = max(visibleFrame.minY, min(frame.origin.y, visibleFrame.maxY - size.height))
    }
    panel.setFrame(frame, display: true, animate: animate)
}

@MainActor
private func showApprovalAlert(
    request: ApprovalRequest,
    callerPath: String,
    pid: pid_t,
    signing: SigningInfo,
    scriptApproval: ScriptApproval?,
    blessing: BlessedScriptPromptContext? = nil,
    launcher: LauncherIdentity?,
    launcherFallbackPath: String,
    automaticApprovalExplanation: String?,
    allowsPersistentApproval: Bool = false,
    cancellation: ApprovalCancellation? = nil
) -> ApprovalDecision {
    guard cancellation?.isCanceled != true else { return .canceled }
    let receivedAt = Date()
    let requester = approvalPromptRequester(launcher: launcher, fallback: launcherFallbackPath)
    let content = ApprovalPromptContent(
        requesterName: requester.name,
        requesterIconPath: requester.iconPath,
        credentialConsumer: autoApprovalToolName(request),
        command: autoApprovalCommand(request),
        commandPath: approvalCommandPath(request),
        title: request.title,
        detail: request.detail,
        automaticApprovalExplanation: automaticApprovalExplanation,
        cwd: request.cwd,
        keys: request.keys.joined(separator: ", "),
        blessing: blessing,
        sections: approvalPromptSections(
            request: request,
            callerPath: callerPath,
            pid: pid,
            signing: signing,
            scriptApproval: scriptApproval,
            launcher: launcher,
            receivedAt: receivedAt
        )
    )
    var decision = ApprovalDecision.canceled
    let maximumHeight = NSScreen.main?.visibleFrame.height ?? 660
    let panel = ApprovalPanel(
        contentRect: NSRect(x: 0, y: 0, width: 560, height: 660),
        styleMask: [.borderless, .nonactivatingPanel],
        backing: .buffered,
        defer: false
    )
    panel.backgroundColor = .clear
    panel.isOpaque = false
    panel.hasShadow = true
    panel.isMovableByWindowBackground = true
    panel.isFloatingPanel = true
    panel.hidesOnDeactivate = false
    panel.level = .modalPanel
    panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
    panel.contentView = NSHostingView(
        rootView: ApprovalPromptView(
            content: content,
            maximumHeight: maximumHeight,
            allowsPersistentApproval: allowsPersistentApproval,
            decide: {
                decision = $0
                NSApp.stopModal()
            },
            contentSizeDidChange: { [weak panel] in
                Task { @MainActor in
                    await Task.yield()
                    if let panel {
                        fitApprovalPanel(panel, maximumHeight: maximumHeight, animate: true)
                    }
                }
            }
        )
    )
    guard cancellation?.observe({ [weak panel] in
        guard let panel, NSApp.modalWindow === panel else { return }
        NSApp.stopModal()
    }) != false else { return .canceled }
    defer { cancellation?.stopObserving() }
    fitApprovalPanel(panel, maximumHeight: maximumHeight, animate: false)
    panel.center()
    panel.orderFrontRegardless()
    NSApp.runModal(for: panel)
    panel.orderOut(nil)
    return cancellation?.isCanceled == true ? .canceled : decision
}

private func approvalPromptRequester(
    launcher: LauncherIdentity?,
    fallback: String
) -> (name: String, iconPath: String) {
    guard let launcher else {
        return (URL(fileURLWithPath: fallback).lastPathComponent, fallback)
    }
    if launcher.isStandalone {
        return ("\(launcher.path) — Team ID: \(launcher.teamIdentifier)", launcher.path)
    }
    if let appURL = appBundleURL(containing: launcher.path)
        ?? NSWorkspace.shared.urlForApplication(withBundleIdentifier: launcher.identifier)
    {
        let bundle = Bundle(url: appURL)
        let name = bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? appURL.deletingPathExtension().lastPathComponent
        return (name, appURL.path)
    }
    return (shortAppName(launcher.identifier), launcher.path)
}

private func prettyShellCommand(target: String, args: [String]) -> String {
    ([target] + args).map(shellQuote).enumerated().map { index, word in
        if args.isEmpty { return word }
        return index == 0 ? "\(word) \\" : "  \(word)" + (index == args.count ? "" : " \\")
    }.joined(separator: "\n")
}

private func shellQuote(_ word: String) -> String {
    guard !word.isEmpty,
          word.rangeOfCharacter(from: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: #"'"\\$`!&|;()<>{}[]*?"#))) == nil
    else {
        return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    return word
}

@MainActor
private func approvalPromptSections(
    request: ApprovalRequest,
    callerPath: String,
    pid: pid_t,
    signing: SigningInfo,
    scriptApproval: ScriptApproval?,
    launcher: LauncherIdentity?,
    receivedAt: Date
) -> [ApprovalPromptSection] {
    var sections = [
        ApprovalPromptSection("Request", "clock", [
            ApprovalPromptRow("Received", approvalPromptTimestamp(receivedAt)),
        ]),
        ApprovalPromptSection("Environment", "arrow.triangle.2.circlepath", [
            ApprovalPromptRow("Existing", request.envConflicts.isEmpty ? "(none)" : request.envConflicts.joined(separator: ", ")),
            ApprovalPromptRow("Replace existing", request.replaceExistingEnv ? "yes" : "no"),
            ApprovalPromptRow("Allow missing keys", request.allowMissingKeys ? "yes" : "no"),
        ]),
        ApprovalPromptSection("Gate Client Identity", "terminal", [
            ApprovalPromptRow("Gate Client", "\(callerPath) (pid \(pid))"),
            ApprovalPromptRow("Signed", "\(signing.identifier) / \(signing.teamIdentifier)"),
        ]),
    ]

    let chain = approvalProcessChain(pid: pid)
    let chainRows = chain.map { [ApprovalPromptRow("Process chain", $0)] } ?? []
    sections.append(ApprovalPromptSection("Execution Origin", "app.badge", launcher.map {
        [
            ApprovalPromptRow("App", "\($0.identifier) (pid \($0.pid))"),
            ApprovalPromptRow("Path", $0.path),
            ApprovalPromptRow("Signed", "\($0.identifier) / \($0.teamIdentifier)"),
        ] + chainRows
    } ?? [
        ApprovalPromptRow("Status", "unavailable; persistent auto-approve disabled"),
    ] + chainRows))

    if let scriptApproval {
        sections.append(ApprovalPromptSection("Script", "doc.text", [
            ApprovalPromptRow("Path", scriptApproval.path),
            ApprovalPromptRow("Checksum", scriptApproval.checksum),
        ]))
    } else if let script = request.shebangScript {
        sections.append(ApprovalPromptSection("Script", "doc.text", [
            ApprovalPromptRow("Path", script),
            ApprovalPromptRow("Checksum", "unavailable"),
        ]))
    }

    return sections
}

private func approvalPromptTimestamp(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.dateStyle = .medium
    formatter.timeStyle = .long
    return formatter.string(from: date)
}

private struct ApprovalPromptSection: Identifiable {
    let id: String
    let title: String
    let systemImage: String
    let rows: [ApprovalPromptRow]

    init(_ title: String, _ systemImage: String, _ rows: [ApprovalPromptRow]) {
        self.id = title
        self.title = title
        self.systemImage = systemImage
        self.rows = rows
    }
}

private struct ApprovalPromptRow: Identifiable {
    let id: String
    let label: String
    let value: String

    init(_ label: String, _ value: String) {
        self.id = label
        self.label = label
        self.value = value
    }
}

private struct BlessedScriptPromptContext {
    let script: BlessedScript
    let explanation: String
}

private struct ApprovalPromptContent {
    let requesterName: String
    let requesterIconPath: String
    let credentialConsumer: String
    let command: String
    let commandPath: String
    let title: String?
    let detail: String?
    let automaticApprovalExplanation: String?
    let cwd: String
    let keys: String
    let blessing: BlessedScriptPromptContext?
    let sections: [ApprovalPromptSection]
}

private struct ApprovalPromptView: View {
    let content: ApprovalPromptContent
    var maximumHeight: CGFloat? = nil
    var allowsPersistentApproval = false
    let decide: (ApprovalDecision) -> Void
    let contentSizeDidChange: () -> Void
    @State private var showsDetails = false

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 8) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: content.requesterIconPath))
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 72, height: 72)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .accessibilityLabel(content.requesterName)
                Text(content.requesterName)
                    .font(.title2.weight(.bold))
                Text("WANTS TO RUN")
                    .font(.caption.weight(.semibold))
                    .tracking(1.6)
                    .foregroundStyle(.secondary)
            }

            ApprovalPromptCommandView(content: content)
                .layoutPriority(-1)

            if let blessing = content.blessing {
                ApprovalPromptBlessingView(context: blessing)
            } else {
                Text("Credential consumer: \(content.credentialConsumer)")
                    .font(.callout.weight(.medium))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            VStack(alignment: .leading, spacing: 5) {
                if let title = content.title, !title.isEmpty {
                    Text(title)
                        .font(.headline)
                }
                if let detail = content.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if content.blessing == nil,
                   content.title?.isEmpty != false,
                   content.detail?.isEmpty != false
                {
                    Text("Review the request details before allowing access.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if let explanation = content.automaticApprovalExplanation {
                Label {
                    Text(explanation)
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundStyle(.orange)
                }
                .font(.callout)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
                .accessibilityElement(children: .combine)
            }

            DisclosureGroup(isExpanded: $showsDetails) {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(content.sections) { section in
                            ApprovalPromptSectionView(section: section)
                        }
                    }
                    .padding(.top, 8)
                }
                .frame(maxHeight: 170)
                .scrollIndicators(.visible)
            } label: {
                Label("Details", systemImage: "info.circle")
                    .font(.callout.weight(.medium))
            }
            .transaction { $0.animation = nil }
            .onChange(of: showsDetails) { _, _ in contentSizeDidChange() }

            HStack(spacing: 12) {
                Button("Deny", role: .cancel) { decide(.denied) }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
                    .keyboardShortcut(.cancelAction)
                Button("Approve Once") { decide(.approved) }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .tint(.blue)
                    .frame(maxWidth: .infinity)
                    .keyboardShortcut(.defaultAction)
                if allowsPersistentApproval {
                    Button("Always Allow") { decide(.alwaysApproved) }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .tint(.blue)
                        .frame(maxWidth: .infinity)
                }
            }

            Text(allowsPersistentApproval
                ? "Always Allow trusts this verified app until removed in Settings"
                : "Automic authorization can be configured for verified Launchers in the Automic Vault app.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(28)
        .frame(maxHeight: maximumHeight)
        .frame(width: 560)
        .fixedSize(horizontal: false, vertical: true)
        .background {
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .fill(.regularMaterial)
                // .overlay {
                //     RoundedRectangle(cornerRadius: 28, style: .continuous)
                //         .fill(.blue.opacity(0.18))
                // }
        }
        .overlay {
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .stroke(.white.opacity(0.18), lineWidth: 1)
        }
        .contentShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
    }
}

private struct ApprovalPromptBlessingView: View {
    let context: BlessedScriptPromptContext
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Label("Blessed script authority", systemImage: "checkmark.seal.fill")
                    .font(.headline)
                    .foregroundStyle(.green)
                Spacer(minLength: 0)
                Text(context.explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
                    .fixedSize(horizontal: false, vertical: true)
            }
            LabeledContent("Secrets (\(context.script.keys.count))") {
                Text(context.script.keys.isEmpty ? "(none)" : context.script.keys.joined(separator: ", "))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
            }
            LabeledContent("Capabilities (\(context.script.capabilities.count))") {
                Text(approvalPromptCapabilitySummary(context.script))
                    .multilineTextAlignment(.trailing)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.green.opacity(colorScheme == .light ? 0.14 : 0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(.green.opacity(0.25), lineWidth: 1)
        }
    }
}

private func approvalPromptCapabilitySummary(_ script: BlessedScript) -> String {
    let summary = script.capabilities.sorted(by: { $0.key < $1.key })
        .map { "\($0.key): \($0.value.title)" }
        .joined(separator: " • ")
    return summary.isEmpty ? "(none)" : summary
}

private struct ApprovalPromptCommandView: View {
    let content: ApprovalPromptContent

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ScrollView([.horizontal, .vertical]) {
                Text(approvalPromptCommandText(command: content.command, path: content.commandPath))
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: true, vertical: true)
            }
            .scrollIndicators(.visible)
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 14) {
                    ApprovalPromptInlineMeta(label: "cwd", value: content.cwd)
                    ApprovalPromptInlineMeta(label: "keys", value: content.keys)
                }
                VStack(alignment: .leading, spacing: 5) {
                    ApprovalPromptInlineMeta(label: "cwd", value: content.cwd)
                    ApprovalPromptInlineMeta(label: "keys", value: content.keys)
                }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.black.opacity(0.72), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(.white.opacity(0.12), lineWidth: 1)
        }
    }
}

private func approvalPromptCommandText(command: String, path: String) -> AttributedString {
    let lineBreak = command.firstIndex(of: "\n") ?? command.endIndex
    var text = AttributedString(String(command[..<lineBreak]))
    text.foregroundColor = .white
    var comment = AttributedString("    # \(path)")
    comment.foregroundColor = .white.opacity(0.55)
    text += comment
    if lineBreak != command.endIndex {
        var remainder = AttributedString(String(command[lineBreak...]))
        remainder.foregroundColor = .white
        text += remainder
    }
    return text
}

private struct ApprovalPromptInlineMeta: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 5) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.6))
            Text(value.isEmpty ? "(none)" : value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.white.opacity(0.82))
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }
}

private struct ApprovalPromptSectionView: View {
    let section: ApprovalPromptSection

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(section.title, systemImage: section.systemImage)
                .font(.headline)
                .symbolRenderingMode(.hierarchical)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(section.rows) { row in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(row.label)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(width: 124, alignment: .trailing)
                        Text(row.value)
                            .font(.system(.callout, design: .monospaced))
                            .foregroundStyle(.primary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            Color(nsColor: .controlBackgroundColor).opacity(0.72),
            in: RoundedRectangle(cornerRadius: 10, style: .continuous)
        )
    }
}

private func automaticAccessDecisionLabel(wasDenied: Bool) -> String {
    wasDenied ? "AUTO REJECTED" : "AUTO APPROVED"
}

private func automaticAccessDecisionSymbol(wasDenied: Bool) -> String {
    wasDenied ? "xmark.shield.fill" : "checkmark.shield.fill"
}

private struct AutomaticAccessToastView: View {
    let record: AutoApprovalRecord
    let dismiss: () -> Void

    var body: some View {
        Button(action: dismiss) {
            content
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Dismiss \(record.wasDenied ? "rejection" : "approval") notification for \(record.command)")
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: record.launcherIconPath))
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 42, height: 42)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .accessibilityLabel(record.launcher)
                VStack(alignment: .leading, spacing: 2) {
                    Text(record.launcher)
                        .font(.headline)
                    Text(automaticAccessDecisionLabel(wasDenied: record.wasDenied))
                        .font(.caption2.weight(.semibold))
                        .tracking(1.2)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                Image(systemName: automaticAccessDecisionSymbol(wasDenied: record.wasDenied))
                    .font(.title2)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(record.wasDenied ? .red : .green)
                    .accessibilityLabel(record.wasDenied ? "Rejected" : "Approved")
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(record.command)
                    .font(.system(.callout, design: .monospaced).weight(.medium))
                    .foregroundStyle(.white)
                    .fixedSize(horizontal: false, vertical: true)
                Text(record.keys.joined(separator: ", "))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.68))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.black.opacity(0.72), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .padding(16)
        .frame(width: 360)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(.white.opacity(0.18), lineWidth: 1)
        }
        .contentShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private func autoApprovalToastFrame(anchor: NSRect, visibleFrame: NSRect, size: NSSize) -> NSRect {
    let margin: CGFloat = 8
    let x = min(max(anchor.midX - size.width / 2, visibleFrame.minX + margin), visibleFrame.maxX - size.width - margin)
    let y = max(visibleFrame.minY + margin, min(anchor.minY - 4, visibleFrame.maxY) - size.height)
    return NSRect(origin: NSPoint(x: x, y: y), size: size)
}

@MainActor
private func showAutomaticAccessToast(
    _ record: AutoApprovalRecord,
    below button: NSStatusBarButton?
) {
    guard let button, let statusWindow = button.window else { return }
    let anchor = statusWindow.convertToScreen(button.convert(button.bounds, to: nil))
    let window = NSPanel(
        contentRect: .zero,
        styleMask: [.borderless, .nonactivatingPanel],
        backing: .buffered,
        defer: false
    )
    let hostingView = NSHostingView(rootView: AutomaticAccessToastView(record: record) { [weak window] in
        if let window {
            window.orderOut(nil)
            toastWindows.removeAll { $0 === window }
        }
    })
    let size = hostingView.fittingSize
    hostingView.frame.size = size
    let visibleFrame = statusWindow.screen?.visibleFrame ?? NSScreen.main?.visibleFrame
        ?? NSRect(x: 0, y: 0, width: 800, height: 600)
    let frame = autoApprovalToastFrame(anchor: anchor, visibleFrame: visibleFrame, size: size)
    window.setFrame(frame, display: false)
    window.level = .statusBar
    window.isOpaque = false
    window.backgroundColor = .clear
    window.hasShadow = true
    window.contentView = hostingView
    window.alphaValue = 0
    toastWindows.append(window)
    window.orderFront(nil)
    NSAnimationContext.runAnimationGroup { context in
        context.duration = 0.15
        window.animator().alphaValue = 1
    }

    DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
        NSAnimationContext.runAnimationGroup({ context in
            context.duration = 0.25
            window.animator().alphaValue = 0
        }, completionHandler: {
            Task { @MainActor in
                window.orderOut(nil)
                toastWindows.removeAll { $0 === window }
            }
        })
    }
}

@MainActor
private func runSecretMutationSelfCheck() -> Int32 {
    for mutation in [
        SecretMutation.save(account: "TEST_SECRET", value: "secret", accessibility: .whenUnlocked),
        SecretMutation.delete(account: "TEST_SECRET"),
    ] {
        var performed = false
        let result = performApprovedSecretMutation(
            mutation,
            callerPath: "/usr/local/bin/av",
            pid: 42,
            signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
            launcher: nil,
            launcherFallbackPath: "/Applications/Terminal.app",
            canRequestHumanApproval: { true },
            onAccessRequest: { _ in true },
            decision: { _ in .denied },
            perform: { _ in
                performed = true
                return errSecSuccess
            }
        )
        guard result.status == nil, !performed else { return 1 }
    }

    var cancellationRecord: AccessRequestRecord?
    var performedAfterCancellation = false
    let canceled = performApprovedSecretMutation(
        .delete(account: "TEST_SECRET"),
        callerPath: "/usr/local/bin/av",
        pid: 42,
        signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
        launcher: nil,
        launcherFallbackPath: "/Applications/Terminal.app",
        canRequestHumanApproval: { true },
        onAccessRequest: {
            cancellationRecord = $0
            return true
        },
        decision: { _ in .canceled },
        perform: { _ in
            performedAfterCancellation = true
            return errSecSuccess
        }
    )
    guard canceled.status == nil,
          canceled.error == "secret mutation canceled",
          cancellationRecord?.decision == "Canceled",
          cancellationRecord?.reason == "Gate client exited",
          !performedAfterCancellation
    else { return 1 }

    var performedWithoutAudit = false
    let unaudited = performApprovedSecretMutation(
        .delete(account: "TEST_SECRET"),
        callerPath: "/usr/local/bin/av",
        pid: 42,
        signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
        launcher: nil,
        launcherFallbackPath: "/Applications/Terminal.app",
        canRequestHumanApproval: { true },
        onAccessRequest: { _ in false },
        decision: { _ in .approved },
        perform: { _ in
            performedWithoutAudit = true
            return errSecSuccess
        }
    )
    return unaudited.status == nil && !performedWithoutAudit ? 0 : 1
}

@MainActor
private func runApprovalSelfCheck() -> Int32 {
    let cancellation = ApprovalCancellation()
    guard isApprovalCancellationEvent(XPC_ERROR_CONNECTION_INTERRUPTED),
          isApprovalCancellationEvent(XPC_ERROR_CONNECTION_INVALID),
          cancellation.observe({}),
          !cancellation.isCanceled
    else { return 1 }
    cancellation.cancel()
    guard cancellation.isCanceled, !cancellation.observe({}) else { return 1 }

    let requester = approvalPromptRequester(
        launcher: LauncherIdentity(
            pid: 41,
            path: "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond",
            identifier: "com.automicvault.vaultty",
            teamIdentifier: "TEAM",
            designatedRequirement: #"identifier "com.automicvault.vaultty" and anchor apple generic"#,
            runtimeProtection: .hardened
        ),
        fallback: "/opt/homebrew/bin/gh"
    )
    let unverifiedRequester = approvalPromptRequester(
        launcher: nil,
        fallback: "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond"
    )
    let cliRequester = approvalPromptRequester(
        launcher: LauncherIdentity(
            pid: 42,
            path: "/opt/homebrew/bin/gh",
            identifier: "gh",
            teamIdentifier: "TEAM",
            designatedRequirement: #"identifier "gh" and anchor apple generic"#,
            runtimeProtection: .hardened,
            isStandalone: true
        ),
        fallback: "/opt/homebrew/bin/gh"
    )
    let automaticApprovalExplanation = LauncherAppVerificationFailure(
        appName: "ChatGPT",
        resourcesUnreadable: true
    ).explanation
    let promptBlessing = BlessedScriptPromptContext(
        script: BlessedScript(
            path: "/tmp/publish.sh",
            checksum: "checksum",
            keys: ["PUBLISH_TOKEN"],
            target: "/bin/sh",
            replaceExistingEnv: false,
            allowMissingKeys: false,
            capabilities: ["gh": .readOnly, "stripe": .fullExceptSecretDumps],
            launchers: []
        ),
        explanation: "Approval activates this stored authority for one execution."
    )
    let collapsedHeight = NSHostingView(
        rootView: ApprovalPromptView(
            content: ApprovalPromptContent(
                requesterName: requester.name,
                requesterIconPath: requester.iconPath,
                credentialConsumer: "gh",
                command: "gh auth token",
                commandPath: "/opt/homebrew/bin/gh",
                title: "GitHub token requested",
                detail: "gh needs the GitHub token",
                automaticApprovalExplanation: automaticApprovalExplanation,
                cwd: "/tmp",
                keys: "GH_TOKEN_GITHUB_COM",
                blessing: promptBlessing,
                sections: []
            ),
            decide: { _ in },
            contentSizeDidChange: {}
        )
    ).fittingSize.height
    let constrainedHeight = NSHostingView(
        rootView: ApprovalPromptView(
            content: ApprovalPromptContent(
                requesterName: requester.name,
                requesterIconPath: requester.iconPath,
                credentialConsumer: "gh",
                command: Array(repeating: "  --long-option \\", count: 100).joined(separator: "\n"),
                commandPath: "/opt/homebrew/bin/gh",
                title: nil,
                detail: nil,
                automaticApprovalExplanation: nil,
                cwd: "/tmp",
                keys: "GH_TOKEN_GITHUB_COM",
                blessing: nil,
                sections: []
            ),
            maximumHeight: 500,
            decide: { _ in },
            contentSizeDidChange: {}
        )
    ).fittingSize.height
    let commandWithArguments = approvalPromptCommandText(
        command: prettyShellCommand(target: "gh", args: ["repo", "view"]),
        path: "/opt/homebrew/bin/gh"
    )
    let commandWithoutArguments = approvalPromptCommandText(
        command: prettyShellCommand(target: "gh", args: []),
        path: "/opt/homebrew/bin/gh"
    )
    guard prettyShellCommand(target: "/bin/echo", args: ["hello world", "it's-ok"]) == """
    /bin/echo \\
      'hello world' \\
      'it'\\''s-ok'
    """,
          prettyShellCommand(target: "/bin/echo", args: []) == "/bin/echo",
          String(commandWithArguments.characters) == """
          gh \\    # /opt/homebrew/bin/gh
            repo \\
            view
          """,
          String(commandWithoutArguments.characters) == "gh    # /opt/homebrew/bin/gh",
          promptBlessing.script.capabilities["gh"] == .readOnly,
          approvalPromptCapabilitySummary(promptBlessing.script)
            == "gh: Read Only • stripe: Write Access",
          requester.name == "Vaultty",
          requester.iconPath == "/Applications/Vaultty.app",
          unverifiedRequester.name == "vaultty-sessiond",
          unverifiedRequester.iconPath == "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond",
          cliRequester.name == "/opt/homebrew/bin/gh — Team ID: TEAM",
          cliRequester.iconPath == "/opt/homebrew/bin/gh",
          automaticApprovalExplanation.contains("ChatGPT contains signed app resources"),
          automaticApprovalExplanation.contains("Approval is required to fail closed"),
          collapsedHeight > 0,
          collapsedHeight < 660,
          constrainedHeight <= 500
    else {
        return 1
    }
    let vaulttySigning = LiveSigningInfo(
        identifier: "app.vaultty.Vaultty",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "app.vaultty.Vaultty" and anchor apple generic"#,
        mainExecutable: "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let vaulttyBridgeSigning = LiveSigningInfo(
        identifier: "com.automicvault.vaultty.session-bridge",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.automicvault.vaultty.session-bridge" and anchor apple generic"#,
        mainExecutable: "/Users/mxcl/Library/Application Support/Vaultty/vaultty-session-bridge",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let vaulttyAppSigning = StaticSigningInfo(
        identifier: "com.automicvault.vaultty",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.automicvault.vaultty" and anchor apple generic"#
    )
    let nestedMenuSigning = LiveSigningInfo(
        identifier: "dev.mxcl.pmm.menu",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "dev.mxcl.pmm.menu" and anchor apple generic"#,
        mainExecutable: "/Applications/Package Manager Manager.app/Contents/Library/LoginItems/Package Manager Manager Menu.app/Contents/MacOS/PMMMenuBar",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    var detachedCaller = AVProcessIdentity()
    detachedCaller.ppid = 1
    detachedCaller.sid = 43
    let pythonSigning = LiveSigningInfo(
        identifier: "org.python.python",
        teamIdentifier: "unknown",
        designatedRequirement: #"identifier "org.python.python" and anchor apple generic"#,
        mainExecutable: "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python",
        isAdHoc: true,
        runtimeProtection: .hardenedRuntimeMissing,
        isDeveloperID: false
    )
    let unbundledSigning = LiveSigningInfo(
        identifier: "com.automicvault.av",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.automicvault.av" and anchor apple generic"#,
        mainExecutable: "/usr/local/bin/av",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let parentlessVaulttyLauncher = launcherIdentity(
        pid: 43,
        path: "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond",
        signing: vaulttySigning,
        appSigning: { _ in vaulttyAppSigning }
    )
    let vaulttyBridgeLauncher = launcherIdentity(
        pid: 44,
        path: "/Users/mxcl/Library/Application Support/Vaultty/vaultty-session-bridge",
        signing: vaulttyBridgeSigning,
        appSigning: { _ in vaulttyAppSigning }
    )
    let nestedLaunchers = launcherIdentities(
        pid: 45,
        path: nestedMenuSigning.mainExecutable,
        signing: nestedMenuSigning,
        appSigning: { url in
            let identifier = url.lastPathComponent == "Package Manager Manager.app"
                ? "dev.mxcl.pmm"
                : "dev.mxcl.pmm.menu"
            return StaticSigningInfo(
                identifier: identifier,
                teamIdentifier: "TEAM",
                designatedRequirement: "identifier \"\(identifier)\" and anchor apple generic"
            )
        }
    )
    guard parentlessVaulttyLauncher?.designatedRequirement == vaulttyAppSigning.designatedRequirement,
          vaulttyBridgeLauncher?.designatedRequirement == vaulttyAppSigning.designatedRequirement,
          nestedLaunchers.map(\.identifier) == ["dev.mxcl.pmm.menu", "dev.mxcl.pmm"],
          launcherAncestorStartPIDs(detachedCaller) == [43],
          launcherIdentity(pid: 46, path: pythonSigning.mainExecutable, signing: pythonSigning) == nil,
          launcherIdentity(pid: 47, path: "/usr/local/bin/av", signing: unbundledSigning)?.isStandalone == true
    else {
        return 1
    }
    let ghSigning = SigningInfo(identifier: "gh", teamIdentifier: "TEAM")
    func ghRequest(
        op: String = "keys",
        keys: [String] = ["GH_TOKEN_GITHUB_COM"],
        args: [String] = ["repo", "view"]
    ) -> ApprovalRequest {
        ApprovalRequest(
            op: op,
            keys: keys,
            target: "/opt/homebrew/Cellar/gh-cli/2.94.0/bin/gh",
            args: args,
            cwd: "/tmp",
            replaceExistingEnv: true,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "gh",
            title: nil,
            detail: nil
        )
    }
    let readOnlyGh = ghRequest()
    let blockedRequirement = #"identifier "com.openai.codex" and anchor apple generic"#
    let policyGate = SecretGate(
        id: "gh",
        keyPatterns: ["GH_TOKEN_*"],
        routes: [],
        defaultProtection: .fullExceptSecretDumps,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: "com.openai.codex",
            requirement: blockedRequirement,
            protection: .noAccess
        )]
    )
    let blockedLauncher = LauncherIdentity(
        pid: 42,
        path: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
        identifier: "com.openai.codex",
        teamIdentifier: "TEAM",
        designatedRequirement: blockedRequirement,
        runtimeProtection: .hardened
    )
    let unhardenedLauncher = LauncherIdentity(
        pid: blockedLauncher.pid,
        path: blockedLauncher.path,
        identifier: blockedLauncher.identifier,
        teamIdentifier: blockedLauncher.teamIdentifier,
        designatedRequirement: blockedLauncher.designatedRequirement,
        runtimeProtection: .hardenedRuntimeMissing
    )
    let runtimeProtectedGate = SecretGate(
        id: "gh",
        keyPatterns: ["GH_TOKEN_*"],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: blockedLauncher.identifier,
            requirement: blockedRequirement,
            protection: .readOnly,
            requiresHardenedRuntime: true
        )]
    )
    let grandfatheredGate = SecretGate(
        id: "gh",
        keyPatterns: ["GH_TOKEN_*"],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: blockedLauncher.identifier,
            requirement: blockedRequirement,
            protection: .readOnly
        )]
    )
    let ghMetadata = HardenerMetadata(
        name: "gh",
        hardened: true,
        secretGate: SecretGateDescriptor(
            id: "gh",
            keyPatterns: ["GH_TOKEN_*"],
            routes: [SecretGateRoute(
                operation: "keys",
                scriptPath: nil,
                targetPath: "/opt/homebrew/opt/gh-cli/bin/gh",
                callerIdentifiers: ["gh", "com.github.cli"],
                keyPatterns: ["GH_TOKEN_*"],
                replaceExistingEnv: true,
                allowMissingKeys: false
            )]
        )
    )
    let stripeSigning = SigningInfo(identifier: "stripe", teamIdentifier: "TEAM")
    let stripeRequest = ApprovalRequest(
        op: "keys",
        keys: ["STRIPE_CLI_6163636F756E742E616363745F3132332E746573745F6D6F64655F6170695F6B6579".uppercased()],
        target: "/opt/homebrew/opt/stripe-cli/bin/stripe",
        args: ["customers", "list"],
        cwd: "/tmp",
        replaceExistingEnv: true,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: "stripe",
        title: "Stripe credential requested",
        detail: nil
    )
    let stripeMetadata = HardenerMetadata(
        name: "stripe",
        hardened: true,
        secretGate: SecretGateDescriptor(
            id: "stripe",
            keyPatterns: ["STRIPE_CLI_*"],
            routes: [SecretGateRoute(
                operation: "keys",
                scriptPath: nil,
                targetPath: "/opt/homebrew/opt/stripe-cli/bin/stripe",
                callerIdentifiers: ["stripe"],
                keyPatterns: ["STRIPE_CLI_*"],
                replaceExistingEnv: true,
                allowMissingKeys: false
            )]
        )
    )
    func flyRequest(_ arguments: [String]) -> ApprovalRequest {
        ApprovalRequest(
            op: "inject",
            keys: ["FLY_ACCESS_TOKEN"],
            target: "/bin/sh",
            args: ["/usr/local/bin/fly"] + arguments,
            cwd: "/tmp",
            replaceExistingEnv: false,
            allowMissingKeys: true,
            envConflicts: [],
            shebangScript: "/usr/local/bin/fly",
            scriptData: nil,
            tool: nil,
            title: nil,
            detail: nil
        )
    }
    let directRequest = ApprovalRequest(
        op: "inject",
        keys: ["HCLOUD_TOKEN"],
        target: "/bin/sh",
        args: ["-c", "hcloud server list"],
        cwd: "/tmp",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: nil,
        title: nil,
        detail: nil
    )
    let directRules = [DirectAccessRule(
        secretName: "HCLOUD_TOKEN",
        launcher: BlessedScriptLauncher(
            bundleIdentifier: blockedLauncher.identifier,
            requirement: blockedLauncher.designatedRequirement
        )
    )]
    guard resolveSecretGatePolicy(gate: policyGate, launchers: []) == nil,
          resolveSecretGatePolicy(gate: policyGate, launchers: [blockedLauncher])?.protection == .noAccess,
          resolveSecretGatePolicy(gate: runtimeProtectedGate, launchers: [blockedLauncher])?.protection == .readOnly,
          resolveSecretGatePolicy(gate: runtimeProtectedGate, launchers: [unhardenedLauncher])?.protection == .noAccess,
          resolveSecretGatePolicy(gate: grandfatheredGate, launchers: [unhardenedLauncher])?.protection == .readOnly,
          matchingSecretGate(request: readOnlyGh, signing: ghSigning, hardeners: [ghMetadata])?.id == "gh",
          matchingSecretGate(request: ghRequest(keys: ["OTHER_TOKEN"]), signing: ghSigning, hardeners: [ghMetadata]) == nil,
          matchingSecretGate(request: ghRequest(keys: []), signing: ghSigning, hardeners: [ghMetadata]) == nil,
          matchingSecretGate(request: ghRequest(op: "inject"), signing: ghSigning, hardeners: [ghMetadata]) == nil,
          matchingSecretGate(
              request: readOnlyGh,
              signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
              hardeners: [ghMetadata]
          ) == nil,
          classifySecretGateRequest(gateID: "gh", request: readOnlyGh) == .readOnly,
          classifySecretGateRequest(gateID: "gh", request: ghRequest(args: ["repo", "delete", "owner/name"])) == .mutating,
          classifySecretGateRequest(gateID: "gh", request: ghRequest(args: ["auth", "token"])) == .secretDump,
          classifySecretGateRequest(gateID: "gh", request: ghRequest(args: ["auth", "status", "--show-token"])) == .secretDump,
          isGhTokenKey("GH_TOKEN_GITHUB_COM_MXCL"),
          !isGhTokenKey("GITHUB_TOKEN"),
          !isGhTokenKey("GH_TOKEN_bad-key"),
          matchingSecretGate(request: stripeRequest, signing: stripeSigning, hardeners: [stripeMetadata])?.id == "stripe",
          matchingSecretGate(
              request: stripeRequest,
              signing: SigningInfo(identifier: "gh", teamIdentifier: "TEAM"),
              hardeners: [stripeMetadata]
          ) == nil,
          classifySecretGateRequest(gateID: "stripe", request: stripeRequest) == .readOnly,
          classifySecretGateRequest(gateID: "flyctl", request: flyRequest(["apps", "list"])) == .readOnly,
          classifySecretGateRequest(gateID: "flyctl", request: flyRequest(["deploy"])) == .mutating,
          classifySecretGateRequest(gateID: "flyctl", request: flyRequest(["auth", "token"])) == .secretDump,
          matchingDirectAccessLauncher(
              request: directRequest,
              configuredGate: nil,
              trustedAVGateClient: true,
              launchers: [blockedLauncher],
              rules: directRules
          )?.designatedRequirement == blockedLauncher.designatedRequirement,
          matchingDirectAccessLauncher(
              request: directRequest,
              configuredGate: policyGate,
              trustedAVGateClient: true,
              launchers: [blockedLauncher],
              rules: directRules
          ) == nil,
          matchingDirectAccessLauncher(
              request: directRequest,
              configuredGate: nil,
              trustedAVGateClient: false,
              launchers: [blockedLauncher],
              rules: directRules
          ) == nil,
          matchingDirectAccessLauncher(
              request: directRequest,
              configuredGate: nil,
              trustedAVGateClient: true,
              launchers: [unhardenedLauncher],
              rules: directRules
          ) == nil,
          isTrustedStripeCaller(
              path: "/opt/homebrew/opt/stripe-cli/bin/stripe",
              signing: stripeSigning
          ),
          !isTrustedStripeCaller(path: "/tmp/stripe", signing: ghSigning),
          isStripeCredentialKey("STRIPE_CLI_616263"),
          !isStripeCredentialKey("STRIPE_CLI_bad-key"),
          !isStripeCredentialKey("GH_TOKEN_GITHUB_COM")
    else {
        return 1
    }

    let avSigning = SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM")
    func awsRequest(
        keys: [String] = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        args: [String] = ["s3", "ls"],
        shebangScript: String? = nil,
        scriptData: Data? = nil,
        replaceExistingEnv: Bool = false,
        allowMissingKeys: Bool = false,
        envConflicts: [String] = []
    ) -> ApprovalRequest {
        ApprovalRequest(
            op: "inject",
            keys: keys,
            target: "/opt/homebrew/bin/aws",
            args: args,
            cwd: "/tmp",
            replaceExistingEnv: replaceExistingEnv,
            allowMissingKeys: allowMissingKeys,
            envConflicts: envConflicts,
            shebangScript: shebangScript,
            scriptData: scriptData,
            tool: "aws",
            title: nil,
            detail: nil
        )
    }
    let readOnlyAws = awsRequest()
    let longLivedAws = awsRequest(
        args: ["iam", "get-role", "--role-name", "example"]
    )
    let contextualLongLivedAws = approvalRequestWithCredentialContext(longLivedAws)
    let awsMetadata = HardenerMetadata(
        name: "aws",
        hardened: true,
        secretGate: SecretGateDescriptor(
            id: "aws",
            keyPatterns: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            routes: [SecretGateRoute(
                operation: "inject",
                scriptPath: nil,
                targetPath: "/opt/homebrew/bin/aws",
                callerIdentifiers: ["com.automicvault.av"],
                keyPatterns: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                replaceExistingEnv: false,
                allowMissingKeys: false
            )]
        )
    )
    let blessedRequest = awsRequest(shebangScript: "/tmp/script", scriptData: Data("script".utf8))
    let blessedScript = BlessedScript(
        path: "/tmp/script",
        checksum: "checksum",
        keys: blessedRequest.keys,
        target: blessedRequest.target,
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: ["aws": .readOnly],
        launchers: [BlessedScriptLauncher(
            bundleIdentifier: blockedLauncher.identifier,
            requirement: blockedLauncher.designatedRequirement
        )]
    )
    let unendorsedBlessedScript = BlessedScript(
        path: blessedScript.path,
        checksum: blessedScript.checksum,
        keys: blessedScript.keys,
        target: blessedScript.target,
        replaceExistingEnv: blessedScript.replaceExistingEnv,
        allowMissingKeys: blessedScript.allowMissingKeys,
        capabilities: blessedScript.capabilities,
        launchers: []
    )
    guard blessedScriptCanAutoApprove(
        blessedScript,
        request: readOnlyAws,
        signing: avSigning,
        metadata: [awsMetadata]
    ),
        !blessedScriptCanAutoApprove(
            blessedScript,
            request: awsRequest(args: ["s3", "rm", "s3://bucket/key"]),
            signing: avSigning,
            metadata: [awsMetadata]
        ),
        !blessedScriptCanAutoApprove(
            blessedScript,
            request: readOnlyGh,
            signing: ghSigning,
            metadata: [ghMetadata]
        ),
        matchingSecretGateDefinition(
            request: readOnlyAws,
            signing: avSigning,
            hardeners: [HardenerMetadata(
                name: awsMetadata.name,
                hardened: false,
                secretGate: awsMetadata.secretGate
            )]
        )?.id == "aws",
        blessedScriptMatches(
            blessedScript,
            request: blessedRequest,
            approval: ScriptApproval(path: "/tmp/script", checksum: "checksum"),
            launcher: blockedLauncher
        ),
        !blessedScriptMatches(
            blessedScript,
            request: awsRequest(shebangScript: "/tmp/script"),
            approval: ScriptApproval(path: "/tmp/script", checksum: "checksum"),
            launcher: blockedLauncher
        ),
        !blessedScriptMatches(
            unendorsedBlessedScript,
            request: blessedRequest,
            approval: ScriptApproval(path: "/tmp/script", checksum: "checksum"),
            launcher: blockedLauncher
        ),
        lostBlessingExplanation(
            for: ScriptApproval(path: "/tmp/script", checksum: "changed"),
            blessedScripts: [blessedScript]
        ) == "Blessing lost because the script contents changed.",
        lostBlessingExplanation(
            for: ScriptApproval(path: "/tmp/script", checksum: "checksum"),
            blessedScripts: [blessedScript]
        ) == nil
    else { return 1 }

    guard matchingSecretGate(request: readOnlyAws, signing: avSigning, hardeners: [awsMetadata])?.id == "aws",
          matchingSecretGate(request: longLivedAws, signing: avSigning, hardeners: [awsMetadata])?.id == "aws",
          missingRequiredSecret(for: readOnlyAws, exists: { $0 == "AWS_SECRET_ACCESS_KEY" }) == "AWS_ACCESS_KEY_ID",
          missingRequiredSecret(for: readOnlyAws, exists: { _ in true }) == nil,
          missingRequiredSecret(for: awsRequest(allowMissingKeys: true), exists: { _ in false }) == nil,
          missingRequiredSecret(
              for: awsRequest(keys: ["AWS_ACCESS_KEY_ID"], envConflicts: ["AWS_ACCESS_KEY_ID"]),
              exists: { _ in false }
          ) == nil,
          missingRequiredSecret(
              for: awsRequest(
                  keys: ["AWS_ACCESS_KEY_ID"],
                  replaceExistingEnv: true,
                  envConflicts: ["AWS_ACCESS_KEY_ID"]
              ),
              exists: { _ in false }
          ) == "AWS_ACCESS_KEY_ID",
          matchingSecretGate(request: awsRequest(keys: ["AWS_ACCESS_KEY_ID"]), signing: avSigning, hardeners: [awsMetadata]) == nil,
          matchingSecretGate(request: awsRequest(shebangScript: nil), signing: avSigning, hardeners: [awsMetadata]) == nil,
          matchingSecretGate(
              request: readOnlyAws,
              signing: SigningInfo(identifier: "aws", teamIdentifier: "TEAM"),
              hardeners: [awsMetadata]
          ) == nil,
          classifySecretGateRequest(gateID: "aws", request: readOnlyAws) == .readOnly,
          classifySecretGateRequest(gateID: "aws", request: longLivedAws) == .secretDump,
          classifySecretGateRequest(
              gateID: "aws",
              request: awsRequest(args: ["-f", "/usr/local/bin/aws", "--profile", "dev", "iam", "get-role"])
          ) == .secretDump,
          contextualLongLivedAws.title == "Use long-lived AWS credentials?",
          contextualLongLivedAws.detail?.contains("retain every IAM permission") == true,
          classifySecretGateRequest(
              gateID: "aws",
              request: awsRequest(args: ["-f", "/usr/local/bin/aws", "s3", "rm", "s3://bucket/key"])
          ) == .mutating,
          (SecretGateRequestClassification.allCases
              .filter { $0 != .unknown }
              .allSatisfy { secretGateProtectionAllows(.fullIncludingSecretDumps, classification: $0) }),
          !secretGateProtectionAllows(.fullIncludingSecretDumps, classification: .unknown),
          !secretGateProtectionAllows(.noAccess, classification: .readOnly),
          secretGateProtectionAllows(.readOnly, classification: .readOnly),
          !secretGateProtectionAllows(.readOnly, classification: .unknown),
          secretGateProtectionAllows(.readOnlyAndLocalWrites, classification: .readOnly),
          secretGateProtectionAllows(.readOnlyAndLocalWrites, classification: .localWrite),
          !secretGateProtectionAllows(.readOnlyAndLocalWrites, classification: .mutating),
          secretGateProtectionAllows(.readOnlyAndUpdates, classification: .readOnly),
          secretGateProtectionAllows(.readOnlyAndUpdates, classification: .update),
          !secretGateProtectionAllows(.readOnlyAndUpdates, classification: .mutating),
          !secretGateProtectionAllows(.fullExceptSecretDumps, classification: .secretDump),
          !secretGateProtectionAllows(.fullExceptSecretDumps, classification: .unknown)
    else { return 1 }

    let brewSigning = SigningInfo(identifier: "com.automicvault.av-brew-stub", teamIdentifier: "TEAM")
    let brewRequest = ApprovalRequest(
        op: "authorize",
        keys: [],
        target: "/opt/homebrew/bin/brew",
        args: ["info", "ack"],
        cwd: "/tmp",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: "brew",
        title: nil,
        detail: nil
    )
    let brewMetadata = HardenerMetadata(
        name: "brew",
        hardened: true,
        secretGate: SecretGateDescriptor(
            id: "brew",
            keyPatterns: [],
            routes: [SecretGateRoute(
                operation: "authorize",
                scriptPath: nil,
                targetPath: "/opt/homebrew/bin/brew",
                callerIdentifiers: ["com.automicvault.av-brew-stub"],
                keyPatterns: [],
                replaceExistingEnv: false,
                allowMissingKeys: false
            )]
        )
    )
    guard matchingSecretGate(request: brewRequest, signing: brewSigning, hardeners: [brewMetadata])?.id == "brew",
          matchingSecretGate(request: brewRequest, signing: avSigning, hardeners: [brewMetadata]) == nil,
          classifySecretGateRequest(gateID: "brew", request: brewRequest) == .readOnly,
          brewRequestClassification(["update"]) == .update,
          brewRequestClassification(["up"]) == .update,
          brewRequestClassification(["--debug", "update"]) == .mutating,
          isTrustedBrewStubCaller(path: "/usr/local/bin/brew", signing: brewSigning),
          !isTrustedBrewStubCaller(path: "/opt/homebrew/bin/brew", signing: avSigning)
    else { return 1 }

    return 0
}

private func runStandaloneLauncherSelfCheck() -> Int32 {
    let requirement = #"identifier "com.example.cli" and anchor apple generic"#
    let developerID = LiveSigningInfo(
        identifier: "com.example.cli",
        teamIdentifier: "TEAM",
        designatedRequirement: requirement,
        mainExecutable: "/usr/local/bin/example",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let rejected = LiveSigningInfo(
        identifier: "com.apple.zsh",
        teamIdentifier: "unknown",
        designatedRequirement: #"identifier "com.apple.zsh" and anchor apple"#,
        mainExecutable: "/bin/zsh",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: false
    )
    let adHoc = LiveSigningInfo(
        identifier: developerID.identifier,
        teamIdentifier: developerID.teamIdentifier,
        designatedRequirement: developerID.designatedRequirement,
        mainExecutable: "/usr/local/bin/ad-hoc-example",
        isAdHoc: true,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let bundledDeveloperID = LiveSigningInfo(
        identifier: "com.example.helper",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.example.helper" and anchor apple generic"#,
        mainExecutable: "/Applications/Example.app/Contents/Helpers/example",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let liveBundleFallback = launcherIdentities(
        pid: 44,
        path: bundledDeveloperID.mainExecutable,
        signing: bundledDeveloperID,
        appSigning: { _ in nil }
    ).first
    let pathOnlyBundleFallback = launcherIdentities(
        pid: 44,
        path: bundledDeveloperID.mainExecutable,
        signing: bundledDeveloperID,
        appSigning: { _ in nil },
        allowsStandaloneFallback: false
    ).first
    guard satisfiesDeveloperIDRequirement({ _ in errSecSuccess }),
          let launcher = launcherIdentity(
              pid: 42,
              path: developerID.mainExecutable,
              signing: developerID
          ),
          launcher.isStandalone,
          launcher.designatedRequirement == requirement,
          let liveBundleFallback,
          liveBundleFallback.isStandalone,
          liveBundleFallback.identifier == bundledDeveloperID.identifier,
          pathOnlyBundleFallback == nil,
          launcherIdentity(pid: 43, path: adHoc.mainExecutable, signing: adHoc) == nil,
          launcherIdentity(pid: 43, path: rejected.mainExecutable, signing: rejected) == nil,
          executionOrigin(
              among: [liveBundleFallback, launcher],
              callerPID: launcher.pid,
              ancestorFallbackPath: "/bin/zsh"
          )?.pid == liveBundleFallback.pid,
          executionOrigin(
              among: [launcher],
              callerPID: launcher.pid,
              ancestorFallbackPath: "/bin/zsh"
          ) == nil,
          executionOrigin(
              among: [launcher],
              callerPID: launcher.pid,
              ancestorFallbackPath: nil
          )?.pid == launcher.pid,
          processChainLabel(paths: [
              bundledDeveloperID.mainExecutable,
              "/bin/zsh",
              "/opt/homebrew/bin/gh",
          ]) == "example → zsh → gh"
    else { return 1 }
    let unhardenedLauncher = LauncherIdentity(
        pid: launcher.pid,
        path: launcher.path,
        identifier: launcher.identifier,
        teamIdentifier: launcher.teamIdentifier,
        designatedRequirement: launcher.designatedRequirement,
        runtimeProtection: .hardenedRuntimeMissing,
        isStandalone: true
    )
    let libraryValidationLauncher = LauncherIdentity(
        pid: launcher.pid,
        path: launcher.path,
        identifier: launcher.identifier,
        teamIdentifier: launcher.teamIdentifier,
        designatedRequirement: launcher.designatedRequirement,
        runtimeProtection: .hardenedWithLibraryValidationDisabled,
        isStandalone: true
    )
    let injectableLauncher = LauncherIdentity(
        pid: launcher.pid,
        path: launcher.path,
        identifier: launcher.identifier,
        teamIdentifier: launcher.teamIdentifier,
        designatedRequirement: launcher.designatedRequirement,
        runtimeProtection: .unsafeEntitlements([
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.disable-library-validation",
        ]),
        isStandalone: true
    )

    let unconfiguredGate = SecretGate(
        id: "test",
        keyPatterns: [],
        routes: [],
        defaultProtection: .fullIncludingSecretDumps,
        appPolicies: []
    )
    let configuredGate = SecretGate(
        id: "test",
        keyPatterns: [],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: developerID.identifier,
            requirement: requirement,
            protection: .readOnly,
            requiresHardenedRuntime: true
        )]
    )
    let libraryLoadingGate = SecretGate(
        id: "test",
        keyPatterns: [],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: developerID.identifier,
            requirement: requirement,
            protection: .readOnly,
            runtimeRequirement: .hardenedAllowingLibraryValidationDisabled
        )]
    )
    guard resolveSecretGatePolicy(gate: unconfiguredGate, launchers: [launcher]) == nil,
          resolveSecretGatePolicy(gate: configuredGate, launchers: [launcher])?.protection == .readOnly,
          resolveSecretGatePolicy(gate: configuredGate, launchers: [unhardenedLauncher])?.protection == .noAccess,
          resolveSecretGatePolicy(gate: configuredGate, launchers: [libraryValidationLauncher])?.protection == .noAccess,
          resolveSecretGatePolicy(gate: libraryLoadingGate, launchers: [launcher])?.protection == .readOnly,
          resolveSecretGatePolicy(gate: libraryLoadingGate, launchers: [libraryValidationLauncher])?.protection == .readOnly,
          resolveSecretGatePolicy(gate: libraryLoadingGate, launchers: [injectableLauncher])?.protection == .noAccess
    else { return 1 }
    return 0
}

private func runGhReadOnlySelfCheck() -> Int32 {
    let allowed = [
        ["auth", "status"],
        ["status"],
        ["browse"],
        ["search", "prs", "foo"],
        ["repo", "view"],
        ["repo", "list"],
        ["repo", "ls"],
        ["issue", "view", "1"],
        ["issue", "list"],
        ["issue", "status"],
        ["pr", "view"],
        ["pr", "list"],
        ["pr", "status"],
        ["pr", "checks"],
        ["pr", "diff"],
        ["run", "view"],
        ["run", "list"],
        ["workflow", "view"],
        ["workflow", "list"],
        ["release", "view"],
        ["release", "list"],
        ["gist", "view"],
        ["gist", "list"],
        ["cache", "list"],
        ["secret", "list"],
        ["variable", "list"],
        ["ruleset", "view"],
        ["ruleset", "list"],
        ["rs", "view"],
        ["rs", "list"],
        ["rs", "ls"],
        ["attestation", "verify"],
        ["attestation", "trusted-root"],
        ["at", "verify"],
        ["at", "trusted-root"],
        ["agent-task", "view"],
        ["agent-task", "list"],
        ["agent", "view"],
        ["agents", "list"],
        ["agent-tasks", "list"],
        ["org", "list"],
        ["label", "list"],
        ["gpg-key", "list"],
        ["ssh-key", "list"],
        ["-R", "owner/repo", "pr", "view"],
        ["--hostname=github.example.com", "repo", "view"],
        ["api", "repos/owner/repo"],
        ["api", "--method", "GET", "repos/owner/repo"],
        ["api", "-XGET", "-H", "Accept: application/vnd.github+json", "repos/owner/repo/releases/latest"],
        ["api", "--method=GET", "-f", "per_page=1", "search/issues"],
        ["api", "--paginate", "repos/owner/repo/actions/runs", "--jq", ".workflow_runs[].id"],
        ["api", "graphql", "-f", "query=query { viewer { login } }"],
        ["api", "graphql", "-fquery={ viewer { login } }"],
        [
            "api", "graphql",
            "-f", "query=query($owner: String!, $repo: String!, $number: Int!) { repository(owner: $owner, name: $repo) { pullRequest(number: $number) { body bodyHTML } } }",
            "-f", "owner=automic-vault",
            "-f", "repo=automic-vault",
            "-F", "number=49",
            "--hostname", "github.com",
        ],
        ["api", "graphql", "-f", "query=query Read { viewer { login } } mutation Write { addStar(input: {}) { clientMutationId } }", "-f", "operationName=Read"],
    ]
    guard allowed.allSatisfy(ghRequestIsReadOnly) else { return 1 }

    let localWrites = [
        ["repo", "clone", "owner/repo"],
        ["pr", "checkout", "123"],
        ["gist", "clone", "0123456789abcdef"],
        ["run", "download", "123456"],
        ["release", "download", "v1.0.0"],
        ["attestation", "download", "owner/repo"],
        ["at", "download", "owner/repo"],
        ["-R", "owner/repo", "repo", "clone"],
    ]
    guard localWrites.allSatisfy({ ghRequestClassification($0) == .localWrite }) else { return 1 }

    let denied = [
        ["api"],
        ["api", "--method", "POST", "repos/owner/repo/dispatches"],
        ["api", "-X", "DELETE", "repos/owner/repo"],
        ["api", "-f", "name=value", "repos/owner/repo"],
        ["api", "--input", "body.json", "repos/owner/repo"],
        ["api", "graphql"],
        ["api", "graphql", "-f", "query=mutation { addStar(input: {}) { clientMutationId } }"],
        ["api", "graphql", "-f", "query=subscription { viewer { login } }"],
        ["api", "graphql", "-f", "query=query Read { viewer { login } } mutation Write { addStar(input: {}) { clientMutationId } }"],
        ["api", "graphql", "-f", "query=query Read { viewer { login } } mutation Write { addStar(input: {}) { clientMutationId } }", "-f", "operationName=Write"],
        ["api", "graphql", "-F", "query=@query.graphql"],
        ["api", "graphql", "-f", "query={ viewer { login } }", "-F", "secret=@/etc/passwd"],
        ["api", "graphql", "-f", "query={ viewer { login } }", "-f", "query={ viewer { name } }"],
        ["api", "graphql", "--input", "body.json"],
        ["auth", "token"],
        ["auth", "status", "--show-token"],
        ["alias", "set", "x", "repo view"],
        ["extension", "install", "owner/gh-ext"],
        ["config", "set", "editor", "vim"],
        ["skill", "install", "foo"],
        ["repo", "delete", "owner/name"],
        ["issue", "create"],
        ["pr", "merge"],
        ["run", "rerun"],
        ["workflow", "enable"],
        ["release", "create"],
        ["unknown", "view"],
        ["--unknown", "repo", "view"],
    ]
    guard denied.allSatisfy({
        let classification = ghRequestClassification($0)
        return classification != .readOnly && classification != .localWrite
    }),
    ghGraphQLIndirectInputExplanation(
        ["api", "graphql", "-F", "query=@-"]
    )?.contains("automic authorization fails closed") == true,
    ghGraphQLIndirectInputExplanation(
        ["api", "graphql", "-f", "query={ viewer { login } }"]
    ) == nil
    else { return 1 }
    return 0
}

private func runAwsReadOnlySelfCheck() -> Int32 {
    let allowed = [
        ["--version"],
        ["s3", "ls"],
        ["--profile", "dev", "s3", "ls"],
        ["--region=us-east-1", "ec2", "describe-instances"],
        ["ec2", "describe-vpcs", "--filters", "Name=is-default,Values=true"],
        ["iam", "list-users"],
        ["s3api", "list-objects-v2"],
        ["s3api", "head-object"],
        ["sts", "get-caller-identity"],
        ["cloudfront", "get-distribution", "--id", "example"],
        ["dynamodb", "get-item", "--table-name", "example", "--key", "{}"],
        ["dynamodb", "query", "--table-name", "example"],
        ["help"],
    ]
    guard allowed.allSatisfy(awsRequestIsReadOnly) else { return 1 }

    let denied = [
        ["s3", "rm", "s3://bucket/key"],
        ["s3", "cp", "file", "s3://bucket/key"],
        ["ec2", "start-instances"],
        ["lambda", "invoke"],
        ["sts", "get-session-token"],
        ["ecr", "get-login-password"],
        ["secretsmanager", "get-secret-value"],
        ["ssm", "get-parameter", "--with-decryption"],
        ["configure", "get", "aws_secret_access_key"],
        ["cloudfront", "future-get-operation"],
        ["--unknown", "s3", "ls"],
        [],
    ]
    guard denied.allSatisfy({ !awsRequestIsReadOnly($0) }) else { return 1 }
    return 0
}

private func runBrewReadOnlySelfCheck() -> Int32 {
    let allowed = [
        [],
        ["--version"],
        ["--prefix", "ack"],
        ["--cellar"],
        ["--cache"],
        ["--repository"],
        ["--caskroom"],
        ["--taps"],
        ["--env"],
        ["-v"],
        ["casks"],
        ["cat", "ack"],
        ["command", "install"],
        ["commands"],
        ["config"],
        ["deps", "ack"],
        ["desc", "ack"],
        ["doctor"],
        ["formula", "ack"],
        ["formulae"],
        ["help", "install"],
        ["info", "ack"],
        ["leaves"],
        ["linkage", "ack"],
        ["list", "--versions"],
        ["ls"],
        ["livecheck", "ack"],
        ["log", "ack"],
        ["missing"],
        ["options", "ack"],
        ["outdated"],
        ["readall"],
        ["search", "ack"],
        ["shellenv"],
        ["source", "ack"],
        ["tab", "ack"],
        ["tap-info", "homebrew/core"],
        ["unbottled"],
        ["uses", "openssl@3"],
        ["vulns"],
        ["which-formula", "git"],
        ["services", "list"],
        ["services", "info", "postgresql"],
        ["bundle", "check"],
        ["bundle", "env"],
        ["bundle", "list"],
    ]
    guard allowed.allSatisfy(brewRequestIsReadOnly) else { return 1 }

    let denied = [
        ["install", "ack"],
        ["reinstall", "ack"],
        ["uninstall", "ack"],
        ["remove", "ack"],
        ["rm", "ack"],
        ["upgrade"],
        ["cleanup"],
        ["autoremove"],
        ["link", "ack"],
        ["unlink", "ack"],
        ["pin", "ack"],
        ["unpin", "ack"],
        ["tap", "owner/repo"],
        ["untap", "owner/repo"],
        ["services"],
        ["services", "start", "postgresql"],
        ["services", "restart", "postgresql"],
        ["services", "stop", "postgresql"],
        ["services", "kill", "postgresql"],
        ["services", "cleanup"],
        ["bundle"],
        ["bundle", "install"],
        ["bundle", "dump"],
        ["bundle", "add", "ack"],
        ["bundle", "remove", "ack"],
        ["bundle", "cleanup"],
        ["bundle", "edit"],
        ["bundle", "exec", "echo"],
        ["bundle", "sh"],
        ["sh"],
        ["exec", "echo"],
        ["fetch", "ack"],
        ["unknown", "view"],
        ["--debug", "info", "ack"],
        ["--"],
    ]
    guard denied.allSatisfy({ !brewRequestIsReadOnly($0) }) else { return 1 }
    return 0
}

private func runTransientApprovalSelfCheck() -> Int32 {
    func key(
        startUsec: UInt64 = 456,
        args: [String] = ["repo", "view"],
        keys: [String] = ["GH_TOKEN_GITHUB_COM"]
    ) -> TransientApprovalKey {
        TransientApprovalKey(
            pid: 123,
            startUsec: startUsec,
            callerPath: "/opt/homebrew/bin/gh",
            signingIdentifier: "gh",
            signingTeamIdentifier: "TEAM",
            op: "keys",
            keys: keys,
            target: "/opt/homebrew/Cellar/gh-cli/2.94.0/bin/gh",
            args: args,
            cwd: "/tmp",
            replaceExistingEnv: true,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            tool: "gh"
        )
    }
    let approval = key()
    let denial = key(
        args: ["auth", "token"],
        keys: ["GH_TOKEN_GITHUB_COM_MXCL"]
    )
    let fallbackAfterDenial = key(args: ["auth", "token"])
    var cache = TransientApprovalCache()
    cache.remember(.approved, for: approval, now: Date(timeIntervalSince1970: 100))
    guard cache.decision(for: approval, now: Date(timeIntervalSince1970: 200)) == .approved,
          cache.decision(for: fallbackAfterDenial, now: Date(timeIntervalSince1970: 200)) == nil,
          cache.decision(for: key(startUsec: 789), now: Date(timeIntervalSince1970: 200)) == nil
    else {
        return 1
    }
    cache.remember(.denied, for: denial, now: Date(timeIntervalSince1970: 200))
    guard cache.decision(for: denial, now: Date(timeIntervalSince1970: 300)) == .denied,
          cache.decision(for: fallbackAfterDenial, now: Date(timeIntervalSince1970: 300)) == .denied,
          cache.decision(for: key(startUsec: 789), now: Date(timeIntervalSince1970: 300)) == nil,
          cache.decision(for: fallbackAfterDenial, now: Date(timeIntervalSince1970: 501)) == nil
    else {
        return 1
    }
    return 0
}

private func runRetainedProcessProvenanceSelfCheck() -> Int32 {
    var currentIdentity = AVProcessIdentity()
    guard av_process_identity(getpid(), &currentIdentity),
          currentIdentity.pidversion > 0,
          currentIdentity.euid == geteuid(),
          let currentExecution = retainedProcessExecution(
              pid: getpid(),
              identity: currentIdentity
          ),
          retainedProcessExecutionIsLive(currentExecution)
    else { return 1 }

    let launcher = LauncherIdentity(
        pid: 300,
        path: "/Applications/Ghostty.app/Contents/MacOS/ghostty",
        identifier: "com.mitchellh.ghostty",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.mitchellh.ghostty" and anchor apple generic"#,
        runtimeProtection: .hardened
    )
    let herdr = RetainedProcessExecution(
        pid: 200,
        pidVersion: 9,
        startUsec: 123,
        effectiveUserID: 501,
        auditSessionID: 10,
        codeIdentity: Data([1, 2, 3])
    )
    let replacedHerdr = RetainedProcessExecution(
        pid: herdr.pid,
        pidVersion: herdr.pidVersion + 1,
        startUsec: herdr.startUsec,
        effectiveUserID: herdr.effectiveUserID,
        auditSessionID: herdr.auditSessionID,
        codeIdentity: herdr.codeIdentity
    )
    let chains = [[RetainedProcessChainNode(
        pid: herdr.pid,
        path: "/usr/local/bin/herdr",
        execution: herdr
    )]]
    let request = ApprovalRequest(
        op: "keys",
        keys: ["GH_TOKEN_GITHUB_COM"],
        target: "/opt/homebrew/bin/gh",
        args: ["repo", "view"],
        cwd: "/tmp",
        replaceExistingEnv: true,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: "gh",
        title: nil,
        detail: nil
    )
    let gate = SecretGate(
        id: "gh",
        keyPatterns: ["GH_TOKEN_*"],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: launcher.identifier,
            requirement: launcher.designatedRequirement,
            protection: .readOnly
        )]
    )
    var store = RetainedProcessProvenanceStore()
    store.remember(
        [herdr],
        at: .secretGate("gh"),
        launcher: launcher,
        isLive: { _ in true }
    )
    guard store.match(
        at: .secretGate("gh"),
        in: chains,
        isLive: { _ in true }
    )?.launcher.designatedRequirement == launcher.designatedRequirement,
    retainedProvenanceWouldAuthorize(
        request: request,
        configuredGate: gate,
        classification: .readOnly,
        launcher: launcher,
        directAccessRules: [],
        trustedAVGateClient: false
    ),
    !retainedProvenanceWouldAuthorize(
        request: request,
        configuredGate: gate,
        classification: .mutating,
        launcher: launcher,
        directAccessRules: [],
        trustedAVGateClient: false
    ),
    store.match(
        at: .directSecret,
        in: chains,
        isLive: { _ in true }
    ) == nil,
    store.match(
        at: .secretGate("gh"),
        in: [[RetainedProcessChainNode(
            pid: replacedHerdr.pid,
            path: "/usr/local/bin/herdr",
            execution: replacedHerdr
        )]],
        isLive: { _ in true }
    ) == nil,
    store.match(
        at: .secretGate("gh"),
        in: chains,
        isLive: { _ in false }
    ) == nil
    else { return 1 }
    return 0
}

private func runLaunchAgentHandoffSelfCheck() -> Int32 {
    let template = try! PropertyListSerialization.data(
        fromPropertyList: [
            "Label": approvalLaunchAgentName,
            "ProgramArguments": ["@AUTOMIC_VAULT_EXECUTABLE@"],
        ],
        format: .xml,
        options: 0
    )
    let executableURL = URL(fileURLWithPath: "/Users/example/My Apps/Automic Vault.app/Contents/MacOS/AutomicVaultMenubar")
    let configured = try! configuredLaunchAgent(template: template, executableURL: executableURL)
    let plist = try! PropertyListSerialization.propertyList(from: configured, format: nil) as! [String: Any]
    let binaryConfigured = try! PropertyListSerialization.data(
        fromPropertyList: plist,
        format: .binary,
        options: 0
    )
    guard !isLaunchAgentInstance(environment: [:]),
          isLaunchAgentInstance(environment: ["XPC_SERVICE_NAME": approvalLaunchAgentName]),
          shouldHandOffToLaunchAgent(environment: [:], launchAgentURL: URL(fileURLWithPath: "/tmp/agent.plist")),
          !shouldHandOffToLaunchAgent(environment: ["XPC_SERVICE_NAME": approvalLaunchAgentName], launchAgentURL: URL(fileURLWithPath: "/tmp/agent.plist")),
          !shouldHandOffToLaunchAgent(environment: [:], launchAgentURL: nil),
          shouldOpenMainWindow(
              arguments: ["AutomicVaultMenubar", openMainWindowArgument],
              pending: false,
              environment: ["XPC_SERVICE_NAME": approvalLaunchAgentName]
          ),
          shouldOpenMainWindow(
              arguments: ["AutomicVaultMenubar"],
              pending: true,
              environment: ["XPC_SERVICE_NAME": approvalLaunchAgentName]
          ),
          shouldOpenMainWindow(arguments: ["AutomicVaultMenubar"], pending: false, environment: [:]),
          !shouldOpenMainWindow(
              arguments: ["AutomicVaultMenubar"],
              pending: false,
              environment: ["XPC_SERVICE_NAME": approvalLaunchAgentName]
          ),
          requestedSecretGateID(arguments: ["AutomicVaultMenubar", "--secret-gate", "aws"]) == "aws",
          requestedSecretGateID(arguments: ["AutomicVaultMenubar", "--secret-gate", "../aws"]) == nil,
          secretGateID(from: URL(string: "automic-vault://secret-gate/aws")!) == "aws",
          secretGateID(from: URL(string: "automic-vault://secret-gate/aws/extra")!) == nil,
          launchAgentConfigurationsMatch(configured, binaryConfigured),
          !launchAgentConfigurationsMatch(nil, configured),
          plist["ProgramArguments"] as? [String] == [executableURL.path],
          String(decoding: configured, as: UTF8.self).contains("/Applications/") == false
    else {
        return 1
    }
    return 0
}

@MainActor
private func runMenuStatusSelfCheck() -> Int32 {
    let statusItem = makeStatusMenuItem(title: "Starting Automic Vault")
    let actionItem = NSMenuItem(title: "Open Automic Vault", action: nil, keyEquivalent: "")
    setVersionBadge("1.2.3", on: actionItem)
    let quitSeparator = NSMenuItem.separator()
    let quitItem = NSMenuItem(title: "Quit", action: nil, keyEquivalent: "q")
    let items = [statusItem, NSMenuItem.separator(), actionItem, quitSeparator, quitItem]
    updateMenuVisibility(
        items,
        startingUp: true,
        visibleDuringStartup: [statusItem, quitSeparator, quitItem]
    )
    let statusFont = statusItem.attributedTitle?.attribute(.font, at: 0, effectiveRange: nil) as? NSFont
    guard statusItem.isSectionHeader,
          statusFont == NSFont.menuFont(ofSize: 0),
          actionItem.title == "Open Automic Vault",
          actionItem.badge?.stringValue == "v1.2.3",
          !statusItem.isHidden,
          items[1].isHidden,
          actionItem.isHidden,
          !quitSeparator.isHidden,
          !quitItem.isHidden
    else { return 1 }
    updateMenuVisibility(items, startingUp: false, visibleDuringStartup: [])
    guard items.allSatisfy({ !$0.isHidden }) else { return 1 }

    let updatingItems = makeUpdatingMenu().items
    guard updatingItems.map(\.title) == ["Updating…", "", "Quit"],
          updatingItems[0].isSectionHeader,
          !updatingItems[2].isEnabled
    else { return 1 }

    let updatingAlert = NSAlert()
    updatingAlert.addButton(withTitle: "Install and Relaunch")
    configureUpdatingAlert(updatingAlert)
    guard updatingAlert.messageText == "Updating…",
          updatingAlert.buttons.allSatisfy(\.isHidden),
          let progress = updatingAlert.accessoryView as? NSProgressIndicator,
          progress.style == .spinning,
          progress.isIndeterminate
    else { return 1 }

    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "h:mm a"
    func menuRecord(
        _ time: TimeInterval,
        launcher: String = "ChatGPT",
        command: String = """
        gh \\
          repo \\
          view
        """
    ) -> AutoApprovalRecord {
        AutoApprovalRecord(
            accessRequestID: UUID(),
            date: Date(timeIntervalSince1970: time),
            launcher: launcher,
            launcherIconPath: "",
            tool: "gh",
            command: command,
            keys: ["GH_TOKEN"],
            wasCanceled: false,
            wasDenied: false
        )
    }
    let groupedMenuRecords = groupedAutoApprovals([
        menuRecord(19_800),
        menuRecord(18_900, command: "gh issue list"),
        menuRecord(18_000, launcher: "Codex"),
        menuRecord(17_100),
    ])
    let groupedMenuItem = AppDelegate().autoApprovalMenuItem(groupedMenuRecords[0])
    guard let groupedSubmenuTitle = groupedMenuItem.submenu?.items.first?.attributedTitle else {
        return 1
    }
    let groupedCommand = groupedMenuRecords[0].record.command.replacingOccurrences(of: " \\\n  ", with: " ")
    let groupedCommandStart = groupedSubmenuTitle.length - (groupedCommand as NSString).length
    let request = ApprovalRequest(
        op: "inject",
        keys: ["AWS_SECRET_ACCESS_KEY"],
        target: "/bin/zsh",
        args: ["/usr/local/bin/aws", "s3", "ls"],
        cwd: "/tmp",
        replaceExistingEnv: true,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: "/usr/local/bin/aws",
        scriptData: nil,
        tool: nil,
        title: nil,
        detail: nil
    )
    let envWrapperRequest = ApprovalRequest(
        op: "inject",
        keys: ["PULUMI_ACCESS_TOKEN"],
        target: "/bin/sh",
        args: ["/usr/local/bin/pulumi", "stack", "ls"],
        cwd: "/tmp",
        replaceExistingEnv: false,
        allowMissingKeys: true,
        envConflicts: [],
        shebangScript: "/usr/local/bin/pulumi",
        scriptData: nil,
        tool: nil,
        title: nil,
        detail: nil
    )
    let recordedApproval = AccessRequestRecord(
        date: Date(timeIntervalSince1970: 18_900),
        tool: "aws",
        command: "aws s3 ls",
        decision: "Approved",
        approvalSource: "Auto",
        reason: "Read Only from app policy",
        launcher: "Codex",
        callerPath: "/usr/local/bin/av",
        target: "/bin/zsh",
        cwd: "/tmp",
        keys: ["AWS_SECRET_ACCESS_KEY"],
        detail: nil
    )
    guard let restoredApproval = autoApprovalRecord(recordedApproval) else { return 1 }
    guard shortAppName("com.openai.codex") == "Codex",
          approvalEvent(for: nil) == humanApprovalRequiredEvent,
          approvalEvent(for: .approved) == nil,
          approvalEvent(for: .denied) == nil,
          approvalEvent(for: nil, humanApprovalAvailable: false) == nil,
          AutomaticApprovalFeedback.allCases == [.notification, .menuBarFlash, .none],
          automaticApprovalFeedback(rawValue: nil) == .notification,
          automaticApprovalFeedback(rawValue: "notification") == .notification,
          automaticApprovalFeedback(rawValue: "menuBarFlash") == .menuBarFlash,
          automaticApprovalFeedback(rawValue: "none") == .none,
          automaticApprovalFeedback(rawValue: "tampered") == .notification,
          AutomaticApprovalFlashSide.left.next == .right,
          AutomaticApprovalFlashSide.right.next == .left,
          autoApprovalToolName(request) == "aws",
          approvalCommandPath(request) == "/usr/local/bin/aws",
          approvalCommandPath(envWrapperRequest) == "/usr/local/bin/pulumi",
          autoApprovalCommand(envWrapperRequest) == """
          pulumi \\
            stack \\
            ls
          """,
          scanAlertLevel([["severity": "medium"]]) == .medium,
          scanAlertLevel([["severity": "medium"], ["severity": "high"]]) == .high,
          doctorStatusTitle(count: 0) == nil,
          doctorStatusTitle(count: 1) == "One Doctor Report",
          doctorStatusTitle(count: 2) == "Two Doctor Reports",
          vulnerabilityStatusTitle(count: 1) == "One Vulnerability Detected",
          vulnerabilityStatusTitle(count: 2) == "Two Vulnerabilities Detected",
          groupedMenuRecords.map(\.count) == [2, 1, 1],
          groupedMenuRecords[0].records[1].command == "gh issue list",
          groupedMenuItem.representedObject == nil,
          groupedMenuItem.submenu?.items.compactMap({ $0.representedObject as? String })
              == groupedMenuRecords[0].records.map({ $0.accessRequestID.uuidString }),
          groupedCommandStart > 0,
          groupedSubmenuTitle.string.hasSuffix(groupedCommand),
          !groupedSubmenuTitle.string.contains("\\"),
          !groupedSubmenuTitle.string.contains("\n"),
          !groupedSubmenuTitle.string.contains(groupedMenuRecords[0].record.launcher),
          groupedSubmenuTitle.attribute(.foregroundColor, at: 0, effectiveRange: nil) as? NSColor
              == .disabledControlTextColor,
          groupedSubmenuTitle.attribute(
              .foregroundColor,
              at: groupedCommandStart,
              effectiveRange: nil
          ) == nil,
          autoApprovalTitle(groupedMenuRecords[0], formatter: formatter)
              == "5:15 AM\u{2013}5:30 AM ChatGPT used gh \u{00D7}2",
          autoApprovalTitle(
              AutoApprovalRecord(
                  accessRequestID: UUID(),
                  date: Date(timeIntervalSince1970: 18_900),
                  launcher: "Codex",
                  launcherIconPath: "/Applications/Codex.app",
                  tool: "aws",
                  command: "aws s3 ls",
                  keys: ["AWS_SECRET_ACCESS_KEY"],
                  wasCanceled: false,
                  wasDenied: false
              ),
              formatter: formatter
          ) == "5:15 AM – Codex used aws",
          autoApprovalSubmenuCapacity(visibleHeight: 600) == 26,
          restoredApproval.accessRequestID == recordedApproval.id,
          restoredApproval.launcher == "Codex",
          restoredApproval.tool == "aws",
          restoredApproval.command == "aws s3 ls",
          restoredApproval.keys == ["AWS_SECRET_ACCESS_KEY"],
          let restoredDenial = autoApprovalRecord(AccessRequestRecord(
              id: recordedApproval.id,
              date: recordedApproval.date,
              tool: "gh",
              command: "gh auth token",
              decision: "Denied",
              approvalSource: "Manual",
              reason: "Denied in prompt",
              launcher: recordedApproval.launcher,
              callerPath: recordedApproval.callerPath,
              target: recordedApproval.target,
              cwd: recordedApproval.cwd,
              keys: recordedApproval.keys,
              detail: recordedApproval.detail
          )),
          let restoredCancellation = autoApprovalRecord(AccessRequestRecord(
              id: recordedApproval.id,
              date: recordedApproval.date,
              tool: "gh",
              command: "gh pr create",
              decision: "Canceled",
              approvalSource: "Manual",
              reason: "Gate client exited",
              launcher: recordedApproval.launcher,
              callerPath: recordedApproval.callerPath,
              target: recordedApproval.target,
              cwd: recordedApproval.cwd,
              keys: recordedApproval.keys,
              detail: recordedApproval.detail
          )),
          shouldShowAutomaticAccessToast(AccessRequestRecord(
              date: recordedApproval.date,
              tool: "gh",
              command: "gh auth status",
              decision: "Denied",
              approvalSource: "Auto",
              reason: "Unknown launcher",
              launcher: "vaulty-sessiond",
              callerPath: recordedApproval.callerPath,
              target: recordedApproval.target,
              cwd: recordedApproval.cwd,
              keys: recordedApproval.keys,
              detail: recordedApproval.detail
          )),
          !shouldShowAutomaticAccessToast(AccessRequestRecord(
              date: recordedApproval.date,
              tool: "gh",
              command: "gh auth token",
              decision: "Denied",
              approvalSource: "Manual",
              reason: "Denied in prompt",
              launcher: recordedApproval.launcher,
              callerPath: recordedApproval.callerPath,
              target: recordedApproval.target,
              cwd: recordedApproval.cwd,
              keys: recordedApproval.keys,
              detail: recordedApproval.detail
          )),
          restoredDenial.wasDenied,
          restoredCancellation.wasCanceled,
          autoApprovalTitle(restoredCancellation, formatter: formatter)
              == "5:15 AM – Codex canceled its request to use gh",
          automaticAccessDecisionLabel(wasDenied: restoredDenial.wasDenied) == "AUTO REJECTED",
          automaticAccessDecisionSymbol(wasDenied: restoredDenial.wasDenied) == "xmark.shield.fill",
          automaticAccessDecisionLabel(wasDenied: restoredApproval.wasDenied) == "AUTO APPROVED",
          automaticAccessDecisionSymbol(wasDenied: restoredApproval.wasDenied) == "checkmark.shield.fill",
          autoApprovalTitle(restoredDenial, formatter: formatter) == "5:15 AM – Codex was denied use of gh",
          autoApprovalCommand(request) == """
          aws \\
            s3 \\
            ls
          """,
          accessRequestRecord(
              request: request,
              callerPath: "/usr/local/bin/av",
              decision: "Approved",
              approvalSource: "Manual",
              reason: "Approved in prompt",
              launcher: nil
          ).command == """
          aws \\
            s3 \\
            ls
          """,
          autoApprovalToastFrame(
              anchor: NSRect(x: 760, y: 600, width: 24, height: 24),
              visibleFrame: NSRect(x: 0, y: 0, width: 800, height: 600),
              size: NSSize(width: 360, height: 120)
          ) == NSRect(x: 432, y: 476, width: 360, height: 120)
    else {
        return 1
    }
    return 0
}

private func runScanSchedulingSelfCheck() -> Int32 {
    var burstStartedAt: TimeInterval?
    guard boundedScanDelay(
        now: 10,
        burstStartedAt: &burstStartedAt,
        debounceDelay: 1,
        maximumDelay: 5
    ) == 1,
    boundedScanDelay(
        now: 14.5,
        burstStartedAt: &burstStartedAt,
        debounceDelay: 1,
        maximumDelay: 5
    ) == 0.5,
    boundedScanDelay(
        now: 15,
        burstStartedAt: &burstStartedAt,
        debounceDelay: 1,
        maximumDelay: 5
    ) == 0
    else {
        return 1
    }
    return 0
}

private final class UpdatePreflightURLProtocol: URLProtocol, @unchecked Sendable {
    private static let input = try? UpdatePreflightInput(arguments: CommandLine.arguments)
    private let lock = NSLock()
    private var stopped = false

    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else { return false }
        return input?.fixture(for: url) != nil
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url,
              let fixture = Self.input?.fixture(for: url),
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Type": fixture.data == nil
                        ? "application/octet-stream"
                        : "application/json",
                    "Content-Length": String(fixture.size),
                ]
              )
        else {
            client?.urlProtocol(self, didFailWithError: UpdatePreflightError.invalidDraft)
            return
        }

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        do {
            if let data = fixture.data {
                client?.urlProtocol(self, didLoad: data)
            } else if let file = fixture.file {
                let handle = try FileHandle(forReadingFrom: file)
                defer { try? handle.close() }
                while !lock.withLock({ stopped }) {
                    let data = try handle.read(upToCount: 1024 * 1024) ?? Data()
                    if data.isEmpty { break }
                    client?.urlProtocol(self, didLoad: data)
                }
            }
            if !lock.withLock({ stopped }) {
                client?.urlProtocolDidFinishLoading(self)
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {
        lock.withLock { stopped = true }
    }
}

@MainActor
private func runUpdatePreflight() async -> Int32 {
    do {
        let input = try UpdatePreflightInput(arguments: CommandLine.arguments)
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        if input.releasesData != nil {
            sessionConfiguration.protocolClasses = [UpdatePreflightURLProtocol.self]
                + (sessionConfiguration.protocolClasses ?? [])
        }
        let updater = makeUpdater(sessionConfiguration: sessionConfiguration)
        guard let update = try await updater.check(),
              update.version == input.expectedVersion
        else {
            throw UpdatePreflightError.invalidDraft
        }
        let prepared = try await update.prepareInstallation()
        await prepared.discard()
        print("Verified update to \(update.version) with AppUpdater.")
        return 0
    } catch {
        fputs("update preflight failed: \(error.localizedDescription)\n", stderr)
        return 1
    }
}

if CommandLine.arguments.contains("--self-check-approvals") {
    exit(MainActor.assumeIsolated { runApprovalSelfCheck() })
}

if CommandLine.arguments.contains("--self-check-standalone-launchers") {
    exit(runStandaloneLauncherSelfCheck())
}

if CommandLine.arguments.contains("--self-check-secret-mutations") {
    exit(MainActor.assumeIsolated { runSecretMutationSelfCheck() })
}

if CommandLine.arguments.contains("--self-check-gh-read-only") {
    exit(runGhReadOnlySelfCheck())
}

if CommandLine.arguments.contains("--self-check-aws-read-only") {
    exit(runAwsReadOnlySelfCheck())
}

if CommandLine.arguments.contains("--self-check-brew-read-only") {
    exit(runBrewReadOnlySelfCheck())
}

if CommandLine.arguments.contains("--self-check-transient-approvals") {
    exit(runTransientApprovalSelfCheck())
}

if CommandLine.arguments.contains("--self-check-retained-provenance") {
    exit(runRetainedProcessProvenanceSelfCheck())
}

if CommandLine.arguments.contains("--self-check-dashboard-search") {
    exit(MainActor.assumeIsolated { runDashboardSearchSelfCheck() })
}

if CommandLine.arguments.contains("--self-check-update-toolbar") {
    exit(MainActor.assumeIsolated { runUpdateToolbarSelfCheck() })
}

if CommandLine.arguments.contains("--self-check-launch-agent-handoff") {
    exit(runLaunchAgentHandoffSelfCheck())
}

if CommandLine.arguments.contains("--self-check-menu-status") {
    exit(MainActor.assumeIsolated { runMenuStatusSelfCheck() })
}

if CommandLine.arguments.contains("--self-check-scan-scheduling") {
    exit(runScanSchedulingSelfCheck())
}

if CommandLine.arguments.contains("--verify-update") {
    Task { @MainActor in
        exit(await runUpdatePreflight())
    }
    dispatchMain()
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
