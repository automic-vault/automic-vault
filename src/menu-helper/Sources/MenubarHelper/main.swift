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
private var temporaryAccessGrantStripFrame: NSRect?

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
    private var autoApprovalHeadingItem: NSMenuItem?
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
    private var pendingFullScan = false
    private var pendingScanDetectors = Set<String>()
    private var isScanRunning = false
    private var latestDetectorFindings: [DetectorFinding] = []
    private var detectorMetadata: [DetectorMetadata] = []
    private var eventStream: FSEventStreamRef?
    private var recursiveWatchDetectors: [String: Set<String>] = [:]
    private var fileWatchSources: [DispatchSourceFileSystemObject] = []
    private var missingFileWatchDetectors: [String: Set<String>] = [:]
    private var missingFilePoller: DispatchSourceTimer?
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
    private let temporaryAccessGrants = TemporaryAccessGrantController()
    private var temporaryAccessGrantSnapshots: [TemporaryAccessGrantSnapshot] = []
    private var temporaryAccessGrantMenuItems: [NSMenuItem] = []
    private var temporaryAccessGrantHeadingItem: NSMenuItem?
    private var temporaryAccessGrantSeparator: NSMenuItem?
    private var temporaryAccessGrantPanel: TemporaryAccessGrantPanel?
    private var temporaryAccessGrantTimer: Timer?
    private var baseStatusImage: NSImage?
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
        temporaryAccessGrants.cancelAll()
        refreshTemporaryAccessGrants()
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
        temporaryAccessGrants.cancelAll()
        refreshTemporaryAccessGrants()
        if NSApp.modalWindow is ApprovalPanel {
            NSApp.abortModal()
        }
    }

    @objc private func screensDidWake(_ notification: Notification) {
        areScreensAwake = true
    }

    private func installStatusMenu() {
        baseStatusImage = brandImage()
        statusItem.button?.image = baseStatusImage

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
        refreshTemporaryAccessGrants()
        refreshCLIInstallState()
        do {
            let approval = try ApprovalServer(
                serviceName: approvalServiceName,
                temporaryAccessGrants: temporaryAccessGrants
            ) { [weak self] event in
                self?.recordAutoApproval(event)
            } onAccessRequest: { [weak self] record in
                let recorded = appendAccessRequestRecord(record)
                if recorded {
                    Task { @MainActor in self?.didRecordAccessRequest(record) }
                }
                return recorded
            } onBlessRequest: { [weak self] request, completion in
                guard let self else {
                    completion(.failed("Automic Vault is unavailable"))
                    return
                }
                guard !self.isUpdating else {
                    completion(.failed("Automic Vault is updating"))
                    return
                }
                self.showMainWindow(secretGateID: nil)
                guard let controller = self.mainWindow?.contentViewController
                    as? AutomicVaultMainWindowController
                else {
                    completion(.failed("Automic Vault could not open the blessing review"))
                    return
                }
                controller.reviewBlessing(request, completion: completion)
            } onOpenWindow: { [weak self] in
                guard let self else { return }
                let secretGateID = self.consumePendingSecretGate()
                _ = self.consumePendingMainWindow()
                self.showMainWindow(secretGateID: secretGateID)
            } onTemporaryAccessGrantsChanged: { [weak self] in
                self?.refreshTemporaryAccessGrants()
            } canRequestHumanApproval: { [weak self] in
                self?.isUserSessionActive == true && self?.areScreensAwake == true
            }
            try approval.start()
            self.approval = approval
            scheduleScan(after: 0)
            scanQueue.async { [weak self] in
                let metadata = loadDetectorMetadata(avExecutableURL: avExecutableURL())
                Task { @MainActor in
                    self?.detectorMetadata = metadata
                    self?.startDetectorWatchers()
                }
            }
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
        temporaryAccessGrants.cancelAll()
        refreshTemporaryAccessGrants()
        temporaryAccessGrantTimer?.invalidate()
        temporaryAccessGrantTimer = nil
        if NSApp.modalWindow is ApprovalPanel {
            NSApp.abortModal()
        }
        automaticApprovalFlashWorkItem?.cancel()
        automaticApprovalFlashWorkItem = nil
        preFlashStatusImage = nil
        scanWorkItem?.cancel()
        scanWorkItem = nil
        scanBurstStartedAt = nil
        stopDetectorWatchers()
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
        temporaryAccessGrants.cancelAll()
        refreshTemporaryAccessGrants()
        if NSApp.modalWindow is ApprovalPanel {
            NSApp.abortModal()
        }
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

        let controller = AutomicVaultMainWindowController(
            checkForUpdates: { [weak self] in self?.checkForUpdates() },
            requestScan: { [weak self] in self?.scheduleScan(after: 0) }
        )
        controller.updateDetectorFindings(latestDetectorFindings)
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

    private func startDetectorWatchers() {
        stopDetectorWatchers()
        let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
        var exact = [String: Set<String>]()
        var recursive = [String: Set<String>]()
        for detector in detectorMetadata {
            for scope in detector.watchScopes {
                let path = URL(fileURLWithPath: scope.path).standardizedFileURL.path
                guard path != home else { continue }
                var isDirectory: ObjCBool = false
                let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
                if scope.recursive || (exists && isDirectory.boolValue) {
                    if exists {
                        recursive[path, default: []].insert(detector.name)
                    } else {
                        missingFileWatchDetectors[path, default: []].insert(detector.name)
                    }
                } else if exists {
                    exact[path, default: []].insert(detector.name)
                } else {
                    missingFileWatchDetectors[path, default: []].insert(detector.name)
                }
            }
        }
        for finding in latestDetectorFindings {
            for affected in finding.affected where affected.path.hasPrefix("/") {
                let path = URL(fileURLWithPath: affected.path).standardizedFileURL.path
                guard path != home else { continue }
                var isDirectory: ObjCBool = false
                if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
                   isDirectory.boolValue {
                    recursive[path, default: []].formUnion(finding.detectors)
                } else {
                    exact[path, default: []].formUnion(finding.detectors)
                }
            }
        }

        for (path, detectors) in exact {
            let descriptor = open(path, O_EVTONLY)
            guard descriptor >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: descriptor,
                eventMask: [.write, .delete, .rename, .attrib, .extend],
                queue: .main
            )
            source.setEventHandler { [weak self, source] in
                self?.scheduleScan(detectors: detectors, after: 1)
                if !source.data.intersection([.delete, .rename]).isEmpty {
                    self?.startDetectorWatchers()
                }
            }
            source.setCancelHandler { close(descriptor) }
            source.resume()
            fileWatchSources.append(source)
        }

        recursiveWatchDetectors = recursive
        startRecursiveWatcher(paths: Array(recursive.keys))
        startMissingFilePoller()
    }

    private func startRecursiveWatcher(paths: [String]) {
        guard !paths.isEmpty else { return }
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info else { return }
            let paths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] ?? []
            guard paths.count == count else { return }
            MainActor.assumeIsolated {
                Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
                    .handleRecursiveFileEvents(paths)
            }
        }
        guard let stream = FSEventStreamCreate(
            nil,
            callback,
            &context,
            paths as CFArray,
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

    private func handleRecursiveFileEvents(_ paths: [String]) {
        var detectors = Set<String>()
        for changedPath in paths {
            for (root, names) in recursiveWatchDetectors
            where changedPath == root || changedPath.hasPrefix(root + "/") {
                detectors.formUnion(names)
            }
        }
        if !detectors.isEmpty {
            scheduleScan(detectors: detectors, after: 1)
        }
    }

    private func startMissingFilePoller() {
        guard !missingFileWatchDetectors.isEmpty else { return }
        let poller = DispatchSource.makeTimerSource(queue: .main)
        poller.schedule(deadline: .now() + 30, repeating: 30)
        poller.setEventHandler { [weak self] in
            guard let self else { return }
            let created = self.missingFileWatchDetectors.filter {
                FileManager.default.fileExists(atPath: $0.key)
            }
            guard !created.isEmpty else { return }
            self.scheduleScan(
                detectors: created.values.reduce(into: Set<String>()) { $0.formUnion($1) },
                after: 0
            )
            self.startDetectorWatchers()
        }
        poller.resume()
        missingFilePoller = poller
    }

    private func stopDetectorWatchers() {
        fileWatchSources.forEach { $0.cancel() }
        fileWatchSources.removeAll()
        missingFilePoller?.cancel()
        missingFilePoller = nil
        missingFileWatchDetectors.removeAll()
        recursiveWatchDetectors.removeAll()
        if let eventStream {
            FSEventStreamStop(eventStream)
            FSEventStreamInvalidate(eventStream)
            FSEventStreamRelease(eventStream)
            self.eventStream = nil
        }
    }

    private func scheduleScan(detectors: Set<String>? = nil, after delay: TimeInterval) {
        if let detectors, !pendingFullScan {
            pendingScanDetectors.formUnion(scanDetectorGroup(detectors))
        } else if detectors == nil {
            pendingFullScan = true
            pendingScanDetectors.removeAll()
        }
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
            self?.runPendingScan()
        }
        scanWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + scheduledDelay, execute: workItem)
    }

    private func runPendingScan() {
        guard !isScanRunning, pendingFullScan || !pendingScanDetectors.isEmpty else { return }
        let detectors = pendingFullScan ? nil : pendingScanDetectors
        pendingFullScan = false
        pendingScanDetectors.removeAll()
        isScanRunning = true
        scanQueue.async { [weak self] in
            let result = scanResult(detectors: detectors)
            Task { @MainActor in
                self?.applyScanResult(result)
            }
        }
    }

    private func applyScanResult(_ result: ScanResult) {
        isScanRunning = false
        switch result {
        case .success(let findings, let detectors):
            if let detectors {
                latestDetectorFindings.removeAll {
                    !Set($0.detectors).isDisjoint(with: detectors)
                }
                latestDetectorFindings.append(contentsOf: findings)
            } else {
                latestDetectorFindings = findings
            }
            if !detectorMetadata.isEmpty {
                startDetectorWatchers()
            }
            updateMainWindowFindings(latestDetectorFindings)
            let count = latestDetectorFindings.count
            let detectorCount = Set(latestDetectorFindings.flatMap(\.detectors)).count
            #if !DEBUG
            if detectorCount == 0 {
                lastTelemetryFindingCount = nil
            } else if lastTelemetryFindingCount != detectorCount {
                postHogTelemetry.captureDetectorTriggered(count: detectorCount)
                lastTelemetryFindingCount = detectorCount
            }
            #endif
            if latestDetectorFindings.isEmpty {
                setBaseStatusImage(brandImage())
                setScanStatus(
                    "No Vulnerabilities Detected",
                    image: shieldImage(symbolName: "shield.fill", color: .systemGreen)
                )
            } else {
                let level = scanAlertLevel(latestDetectorFindings.map(\.severity))
                let image = switch level {
                case .medium: brandImage()
                case .high: brandImage(color: .systemRed)
                }
                setBaseStatusImage(image)
                setScanStatus(
                    vulnerabilityStatusTitle(count: count),
                    image: shieldImage(color: level.color)
                )
            }
        case .failed:
            setBaseStatusImage(brandImage(color: .systemRed))
            setScanStatus("Scan failed", image: shieldImage(color: .systemRed))
        }
        if scanWorkItem == nil, pendingFullScan || !pendingScanDetectors.isEmpty {
            runPendingScan()
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
        refreshTemporaryAccessGrantMenuItems()
    }

    private func didRecordAccessRequest(_ record: AccessRequestRecord) {
        if shouldShowAutomaticAccessToast(record) {
            showAutomaticAccessToast(automaticAccessRecord(record), below: statusItem.button)
        }
        (mainWindow?.contentViewController as? AutomicVaultMainWindowController)?.reload()
    }

    private func refreshAutoApprovalMenuItems() {
        guard !isUpdating else { return }
        guard let menu = statusItem.menu else { return }
        for item in autoApprovalItems {
            menu.removeItem(item)
        }
        if let heading = autoApprovalHeadingItem {
            menu.removeItem(heading)
            autoApprovalHeadingItem = nil
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
        guard let heading = autoApprovalHistoryHeading(hasRecords: !autoApprovalItems.isEmpty) else { return }
        menu.insertItem(heading, at: 0)
        autoApprovalHeadingItem = heading
        let separator = NSMenuItem.separator()
        menu.insertItem(separator, at: autoApprovalItems.count + 1)
        autoApprovalSeparator = separator
    }

    private func refreshTemporaryAccessGrants() {
        temporaryAccessGrantSnapshots = temporaryAccessGrants.snapshots()
        if temporaryAccessGrantSnapshots.isEmpty {
            temporaryAccessGrantTimer?.invalidate()
            temporaryAccessGrantTimer = nil
        } else if temporaryAccessGrantTimer == nil {
            let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshTemporaryAccessGrants() }
            }
            RunLoop.main.add(timer, forMode: .common)
            temporaryAccessGrantTimer = timer
        }
        refreshTemporaryAccessGrantMenuItems()
        refreshTemporaryAccessGrantPanel()
        statusItem.button?.image = temporaryAccessGrantSnapshots.isEmpty
            ? (baseStatusImage ?? brandImage())
            : brandImage(color: .systemOrange)
    }

    private func refreshTemporaryAccessGrantMenuItems() {
        guard !isUpdating, let menu = statusItem.menu else { return }
        temporaryAccessGrantMenuItems.forEach(menu.removeItem)
        temporaryAccessGrantMenuItems.removeAll()
        if let temporaryAccessGrantHeadingItem {
            menu.removeItem(temporaryAccessGrantHeadingItem)
            self.temporaryAccessGrantHeadingItem = nil
        }
        if let temporaryAccessGrantSeparator {
            menu.removeItem(temporaryAccessGrantSeparator)
            self.temporaryAccessGrantSeparator = nil
        }
        guard !temporaryAccessGrantSnapshots.isEmpty else { return }

        let wallNow = Date()
        let monotonicNow = ProcessInfo.processInfo.systemUptime
        temporaryAccessGrantMenuItems = temporaryAccessGrantSnapshots.map { grant in
            let item = NSMenuItem(
                title: temporaryAccessGrantMenuTitle(
                    grant,
                    wallNow: wallNow,
                    monotonicNow: monotonicNow
                ),
                action: #selector(endTemporaryAccessGrant(_:)),
                keyEquivalent: ""
            )
            item.target = self
            item.representedObject = grant.id.uuidString
            item.image = shieldImage(
                symbolName: "exclamationmark.shield.fill",
                color: .systemOrange,
                accessibilityDescription: "Temporary access warning"
            )
            return item
        }
        for item in temporaryAccessGrantMenuItems.reversed() {
            menu.insertItem(item, at: 0)
        }
        let heading = makeStatusMenuItem(title: "Temporary Access Grants")
        menu.insertItem(heading, at: 0)
        temporaryAccessGrantHeadingItem = heading
        let separator = NSMenuItem.separator()
        menu.insertItem(separator, at: temporaryAccessGrantMenuItems.count + 1)
        temporaryAccessGrantSeparator = separator
    }

    @objc private func endTemporaryAccessGrant(_ sender: NSMenuItem) {
        guard let rawID = sender.representedObject as? String,
              let id = UUID(uuidString: rawID)
        else { return }
        _ = temporaryAccessGrants.cancel(id: id)
        refreshTemporaryAccessGrants()
    }

    private func refreshTemporaryAccessGrantPanel() {
        guard !temporaryAccessGrantSnapshots.isEmpty,
              let button = statusItem.button,
              let statusWindow = button.window
        else {
            temporaryAccessGrantPanel?.orderOut(nil)
            temporaryAccessGrantPanel = nil
            temporaryAccessGrantStripFrame = nil
            return
        }
        let panel = temporaryAccessGrantPanel ?? makeTemporaryAccessGrantPanel()
        temporaryAccessGrantPanel = panel
        let wallNow = Date()
        let monotonicNow = ProcessInfo.processInfo.systemUptime
        let hostingView = NSHostingView(rootView: TemporaryAccessGrantStripView(
            grants: temporaryAccessGrantSnapshots,
            wallNow: wallNow,
            monotonicNow: monotonicNow,
            end: { [weak self] id in
                guard let self else { return }
                _ = self.temporaryAccessGrants.cancel(id: id)
                self.refreshTemporaryAccessGrants()
            }
        ))
        let size = hostingView.fittingSize
        hostingView.frame.size = size
        panel.contentView = hostingView
        let anchor = statusWindow.convertToScreen(button.convert(button.bounds, to: nil))
        let visibleFrame = statusWindow.screen?.visibleFrame ?? NSScreen.main?.visibleFrame
            ?? NSRect(x: 0, y: 0, width: 800, height: 600)
        let frame = autoApprovalToastFrame(anchor: anchor, visibleFrame: visibleFrame, size: size)
        panel.setFrame(frame, display: true)
        temporaryAccessGrantStripFrame = frame
        panel.orderFrontRegardless()
        reanchorToastWindows(below: frame, visibleFrame: visibleFrame)
    }

    private func setBaseStatusImage(_ image: NSImage?) {
        baseStatusImage = image
        if temporaryAccessGrantSnapshots.isEmpty {
            statusItem.button?.image = image
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
            string: record.displayCommand.replacingOccurrences(of: " \\\n  ", with: " "),
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

private func scanDetectorGroup(_ detectors: Set<String>) -> Set<String> {
    guard !detectors.isDisjoint(with: ["bash", "zsh"]) else { return detectors }
    return detectors.union(["bash", "zsh"])
}

extension AppDelegate: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) {
        guard !isStartingUp, !isUpdating else { return }
        refreshAutoApprovalMenuItems()
        refreshTemporaryAccessGrantMenuItems()
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

private func autoApprovalHistoryHeading(hasRecords: Bool) -> NSMenuItem? {
    guard hasRecords else { return nil }
    let item = makeStatusMenuItem(title: "Automic Authorization History")
    item.isEnabled = false
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
    let displayCommand: String
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
        displayCommand: authorizationHistoryCommand(request, scriptPath: script?.path),
        keys: request.keys,
        wasCanceled: false,
        wasDenied: false
    )
}

private func autoApprovalRecord(_ record: AccessRequestRecord) -> AutoApprovalRecord? {
    guard record.decision == "Approved", record.approvalSourceLabel == "Policy" else { return nil }
    return automaticAccessRecord(record)
}

private func automaticAccessRecord(_ record: AccessRequestRecord) -> AutoApprovalRecord {
    return AutoApprovalRecord(
        accessRequestID: record.id,
        date: record.date,
        launcher: record.launcher ?? "Unknown app",
        launcherIconPath: "",
        tool: record.tool,
        displayCommand: record.commandForDisplay,
        keys: record.keys,
        wasCanceled: record.decision == "Canceled",
        wasDenied: record.decision == "Denied"
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
        command: exactAuthorizationCommand(request),
        displayCommand: authorizationHistoryCommand(request),
        decision: decision,
        approvalSource: approvalSource,
        reason: reason,
        launcher: launcher.map { approvalPromptRequester(launcher: $0, fallback: $0.path).name },
        callerPath: callerPath,
        target: request.target,
        cwd: request.cwd,
        keys: request.keys.sorted(),
        detail: request.detail,
        secretValueSources: request.selectedValues.mapValues { $0.source.displayName }
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

private struct AuthorizationCommandParts {
    let tool: String
    let arguments: [String]
}

private func authorizationCommandParts(
    _ request: ApprovalRequest,
    scriptPath: String? = nil
) -> AuthorizationCommandParts {
    let scriptPath = scriptPath ?? resolvedShebangScriptPath(request)
    var args = request.args
    if let scriptPath,
       let scriptIndex = args.firstIndex(where: { standardizedPath($0, cwd: request.cwd) == scriptPath })
    {
        args.removeFirst(scriptIndex + 1)
    }
    return AuthorizationCommandParts(
        tool: autoApprovalToolName(request, scriptPath: scriptPath),
        arguments: args
    )
}

private func exactAuthorizationCommand(_ request: ApprovalRequest, scriptPath: String? = nil) -> String {
    let parts = authorizationCommandParts(request, scriptPath: scriptPath)
    return prettyShellCommand(target: parts.tool, args: parts.arguments)
}

private func authorizationHistoryCommand(_ request: ApprovalRequest, scriptPath: String? = nil) -> String {
    let parts = authorizationCommandParts(request, scriptPath: scriptPath)
    return prettyShellCommand(
        target: parts.tool,
        args: redactedAuthorizationArguments(tool: parts.tool, arguments: parts.arguments)
    )
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
    case success([DetectorFinding], Set<String>?)
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

private func scanResult(detectors: Set<String>?) -> ScanResult {
    let executableURL = avExecutableURL()
    let process = Process()
    process.executableURL = executableURL
    process.arguments = ["scan", "--json"] + (detectors?.sorted().flatMap {
        ["--detector", $0]
    } ?? [])

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
          let findings = try? detectorFindings(from: data)
    else {
        return .failed
    }
    return .success(findings, detectors)
}

private func matchesMediumSeverity(_ severity: String?) -> Bool {
    switch severity?.lowercased() {
    case "medium", "mid": true
    default: false
    }
}

private func scanAlertLevel(_ severities: [String]) -> ScanAlertLevel {
    severities.allSatisfy(matchesMediumSeverity)
        ? .medium : .high
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
    let snapshotIncompatibleInterpreter: String?
    let tool: String?
    let title: String?
    let detail: String?
    let dockerServerURL: String?
    let dockerParent: DockerCredentialParent?
    let selectedValues: [String: StoredSecretValue]
    let dotenvPath: String?
    let dotenvChecksum: String?
    let dotenvProcesses: [BlessedDotenvProcess]

    init(
        op: String,
        keys: [String],
        target: String,
        args: [String],
        cwd: String,
        replaceExistingEnv: Bool,
        allowMissingKeys: Bool,
        envConflicts: [String],
        shebangScript: String?,
        scriptData: Data?,
        snapshotIncompatibleInterpreter: String? = nil,
        tool: String?,
        title: String?,
        detail: String?,
        dockerServerURL: String? = nil,
        dockerParent: DockerCredentialParent? = nil,
        selectedValues: [String: StoredSecretValue] = [:],
        dotenvPath: String? = nil,
        dotenvChecksum: String? = nil,
        dotenvProcesses: [BlessedDotenvProcess] = []
    ) {
        self.op = op
        self.keys = keys
        self.target = target
        self.args = args
        self.cwd = cwd
        self.replaceExistingEnv = replaceExistingEnv
        self.allowMissingKeys = allowMissingKeys
        self.envConflicts = envConflicts
        self.shebangScript = shebangScript
        self.scriptData = scriptData
        self.snapshotIncompatibleInterpreter = snapshotIncompatibleInterpreter
        self.tool = tool
        self.title = title
        self.detail = detail
        self.dockerServerURL = dockerServerURL
        self.dockerParent = dockerParent
        self.selectedValues = selectedValues
        self.dotenvPath = dotenvPath
        self.dotenvChecksum = dotenvChecksum
        self.dotenvProcesses = dotenvProcesses
    }

    func selecting(_ values: [String: StoredSecretValue]) -> ApprovalRequest {
        ApprovalRequest(
            op: op,
            keys: keys,
            target: target,
            args: args,
            cwd: cwd,
            replaceExistingEnv: replaceExistingEnv,
            allowMissingKeys: allowMissingKeys,
            envConflicts: envConflicts,
            shebangScript: shebangScript,
            scriptData: scriptData,
            snapshotIncompatibleInterpreter: snapshotIncompatibleInterpreter,
            tool: tool,
            title: title,
            detail: detail,
            dockerServerURL: dockerServerURL,
            dockerParent: dockerParent,
            selectedValues: values,
            dotenvPath: dotenvPath,
            dotenvChecksum: dotenvChecksum,
            dotenvProcesses: dotenvProcesses
        )
    }
}

enum SecretMutation {
    case save(
        account: String,
        value: String,
        accessibility: StoredSecretAccessibility,
        warning: String = ""
    )
    case saveProject(
        account: String,
        value: String,
        directory: String,
        accessibility: StoredSecretAccessibility,
        warning: String
    )
    case saveIfAbsentOrEqual(account: String, value: String, warning: String = "")
    case delete(account: String)
    case dockerSave(account: String, value: String, serverURL: String, username: String)
    case dockerDelete(account: String, serverURL: String)
    case deleteValue(account: String, source: StoredSecretValueSource)
    case rename(account: String, newAccount: String)
    case setAccessibility(account: String, accessibility: StoredSecretAccessibility)

    fileprivate func approvalRequest(callerPath: String) -> ApprovalRequest {
        let properties: (op: String, keys: [String], args: [String], title: String, detail: String)
        switch self {
        case .save(let account, _, _, let warning):
            properties = (
                "save", [account], ["save", account], "Store \(account)?",
                "This will create or replace a Global Value in Automic Vault."
                    + (warning.isEmpty ? "" : " \(warning)")
            )
        case .saveProject(let account, _, let directory, _, let warning):
            properties = (
                "save", [account], ["save", "--project-directory=\(escapedSecurityPath(directory))", account],
                "Store \(account) Project Value?", warning
            )
        case .saveIfAbsentOrEqual(let account, _, let warning):
            properties = (
                "save-if-absent", [account], ["save-if-absent", account], "Store \(account)?",
                "This will create the Global Value only if no differing value already exists."
                    + (warning.isEmpty ? "" : " \(warning)")
            )
        case .delete(let account):
            properties = (
                "delete", [account], ["delete", account], "Delete \(account)?",
                "This will remove the secret from Automic Vault."
            )
        case .dockerSave(let account, _, let serverURL, let username):
            properties = (
                "docker-save", [account], ["credential", "store", serverURL],
                "Store Docker credential for \(serverURL)?",
                "Docker will use the \(username) credential for this registry through its Automic Vault Secret Gate."
            )
        case .dockerDelete(let account, let serverURL):
            properties = (
                "docker-delete", [account], ["credential", "erase", serverURL],
                "Delete Docker credential for \(serverURL)?",
                "Docker will no longer be able to authenticate to this registry with the stored credential."
            )
        case .deleteValue(let account, let source):
            properties = (
                "delete", [account], ["delete", account, escapedSecurityPath(source.displayName)],
                "Delete \(account) Value?", "This will remove the selected Secret Value."
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
        let tool = switch self {
        case .dockerSave, .dockerDelete: "docker"
        default: URL(fileURLWithPath: callerPath).lastPathComponent
        }
        let cwd: String
        let selectedValues: [String: StoredSecretValue]
        switch self {
        case .saveProject(let account, _, let directory, let accessibility, _):
            cwd = directory
            selectedValues = [account: StoredSecretValue(
                source: .projectDirectory(directory),
                keychainAccount: storedSecretKeychainAccount(
                    secretName: account,
                    source: .projectDirectory(directory)
                ),
                accessibility: accessibility,
                keychainProperties: []
            )]
        default:
            cwd = ""
            selectedValues = [:]
        }
        return ApprovalRequest(
            op: properties.op,
            keys: properties.keys,
            target: callerPath,
            args: properties.args,
            cwd: cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: tool,
            title: properties.title,
            detail: properties.detail,
            selectedValues: selectedValues
        )
    }

    fileprivate func perform() -> OSStatus {
        guard let pendingNames = pendingSecretMutationNames() else { return errSecDecode }
        if !pendingNames.isEmpty {
            let repairStatus = resumePendingSecretMutation()
            return repairStatus == errSecSuccess ? errSecNotAvailable : repairStatus
        }
        switch self {
        case .save(let account, let value, let accessibility, _):
            let secrets: [StoredSecret]
            switch loadStoredSecretsResult() {
            case .success(let loaded): secrets = loaded
            case .failure(let status): return status
            }
            let existing = secrets.first { $0.account == account }
            guard existing?.hasConsistentAccessibility != false else { return errSecDecode }
            return saveStoredSecret(
                account: account,
                value: value,
                accessibility: existing?.accessibility ?? accessibility
            )
        case .saveProject(let account, let value, let directory, let accessibility, _):
            guard (try? validateCanonicalProjectDirectory(directory)) != nil else { return errSecParam }
            let secrets: [StoredSecret]
            switch loadStoredSecretsResult() {
            case .success(let loaded): secrets = loaded
            case .failure(let status): return status
            }
            let existing = secrets.first { $0.account == account }
            guard existing?.hasConsistentAccessibility != false else { return errSecDecode }
            return saveStoredSecret(
                account: account,
                value: value,
                accessibility: existing?.accessibility ?? accessibility,
                source: .projectDirectory(directory)
            )
        case .saveIfAbsentOrEqual(let account, let value, _):
            return saveStoredSecretIfAbsentOrEqual(account: account, value: value)
        case .delete(let account):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .dockerSave(let account, let value, _, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .dockerDelete(let account, _):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .deleteValue(let account, let source):
            return deleteStoredSecretValueRevokingDirectAccessIfLast(
                secretName: account,
                source: source
            )
        case .rename(let account, let newAccount):
            return renameStoredSecretRevokingDirectAccess(account: account, to: newAccount)
        case .setAccessibility(let account, let accessibility):
            return setStoredSecretAccessibility(account: account, accessibility: accessibility)
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
    let selectedValueSources: [String]
}

private enum ApprovalDecision: Equatable {
    case canceled
    case denied
    case approved
    case alwaysApproved
    case temporaryWriteAccess
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
    perform: ((SecretMutation) -> OSStatus)? = nil,
    preflight: (() -> String?)? = nil,
    requestOverride: ApprovalRequest? = nil
) -> (status: OSStatus?, error: String?) {
    let request = requestOverride ?? mutation.approvalRequest(callerPath: callerPath)
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
    if let error = preflight?() {
        _ = onAccessRequest(accessRequestRecord(
            request: request,
            callerPath: callerPath,
            decision: "Failed",
            approvalSource: "Manual",
            reason: error,
            launcher: launcher
        ))
        return (nil, error)
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

private func blessingReply(
    for outcome: BlessedScriptReviewOutcome
) -> (ok: Bool, error: String?, humanApprovalDecision: String?) {
    switch outcome {
    case .approved: (true, nil, "approved")
    case .denied: (false, "script blessing denied", "denied")
    case .failed(let error): (false, error, nil)
    }
}

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
    exists: ((String) -> Bool)? = nil
) -> String? {
    guard !request.allowMissingKeys else { return nil }
    let conflicts = Set(request.envConflicts)
    return request.keys.first {
        (request.replaceExistingEnv || !conflicts.contains($0))
            && !(exists?($0) ?? (request.selectedValues[$0] != nil))
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
        case .canceled, .temporaryWriteAccess: return
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

private struct TemporaryAccessGrantCandidate {
    let scope: TemporaryAccessGrantScope
    let launcher: LauncherIdentity
    let launcherName: String
    let authorizationGateName: String
}

private func agentTaskContext(pid: pid_t) -> AgentTaskContext? {
    var environment: [String: String] = [:]
    for provider in AgentProvider.allCases {
        var value = [CChar](repeating: 0, count: 64)
        guard av_process_environment_value(
            pid,
            provider.environmentVariable,
            &value,
            value.count
        ) else { continue }
        environment[provider.environmentVariable] = String(
            decoding: value.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
    }
    return AgentTaskContext(environment: environment)
}

private func processEnvironmentValueSelfCheck() -> Bool {
    let expected = "11111111-2222-3333-4444-555555555555"
    let process = Process()
    guard let executableURL = Bundle.main.executableURL else { return false }
    process.executableURL = executableURL
    process.arguments = ["--self-check-sleep"]
    process.environment = ["CODEX_THREAD_ID": expected]
    do {
        try process.run()
    } catch {
        return false
    }
    defer {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }
    var value = [CChar](repeating: 0, count: 64)
    var absent = [CChar](repeating: 0, count: 64)
    var tooSmall = [CChar](repeating: 0, count: 4)
    let found = av_process_environment_value(
        process.processIdentifier,
        "CODEX_THREAD_ID",
        &value,
        value.count
    )
    let foundAbsent = av_process_environment_value(
        process.processIdentifier,
        "CLAUDE_CODE_SESSION_ID",
        &absent,
        absent.count
    )
    let foundInSmallBuffer = av_process_environment_value(
        process.processIdentifier,
        "CODEX_THREAD_ID",
        &tooSmall,
        tooSmall.count
    )
    let decoded = String(
        decoding: value.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
    if !found || foundAbsent || foundInSmallBuffer || decoded != expected {
        print(
            "peer env values:",
            found,
            foundAbsent,
            foundInSmallBuffer,
            decoded
        )
        return false
    }
    return true
}

private func temporaryAccessGrantCandidate(
    gate: SecretGate?,
    classification: SecretGateRequestClassification?,
    launcher: LauncherIdentity?,
    agentTaskContext: AgentTaskContext?
) -> TemporaryAccessGrantCandidate? {
    guard let gate, let classification, let launcher, let agentTaskContext else { return nil }
    switch classification {
    case .localWrite, .update, .mutating:
        break
    case .readOnly, .secretDump, .unknown:
        return nil
    }
    guard let runtimeRequirement = launcher.runtimeProtection.secretGateAdmissionRequirement else {
        return nil
    }
    let launcherName = approvalPromptRequester(launcher: launcher, fallback: launcher.path).name
    return TemporaryAccessGrantCandidate(
        scope: TemporaryAccessGrantScope(
            authorizationGateID: gate.id,
            launcherDesignatedRequirement: launcher.designatedRequirement,
            launcherRuntimeRequirement: runtimeRequirement,
            agentTaskContext: agentTaskContext
        ),
        launcher: launcher,
        launcherName: launcherName,
        authorizationGateName: "\(gate.id.uppercased()) Authorization Gate"
    )
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
        && script.allowsExecution(
            snapshotIncompatibleInterpreter: request.snapshotIncompatibleInterpreter
        )
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
    descriptors: [SecretGateDescriptor]
) -> Bool {
    guard let gate = matchingSecretGateDefinition(
        request: request,
        signing: signing,
        descriptors: descriptors
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
    let generation: AWSRuntimeGeneration
    let chain: AWSProfileChain
    let args: [String]
    let target: String
    let interpreter: String
    let useLongLivedCredentials: Bool
}

private struct AWSRegistration {
    let generation: AWSRuntimeGeneration
    let chain: AWSProfileChain
    let args: [String]
    let target: String
    let interpreter: String
    let useLongLivedCredentials: Bool
    let secretValues: [String: StoredSecretValue]
    var credentials: AWSCredentials?
}

private struct DockerCredentialParent: Sendable {
    let pid: pid_t
    let startUsec: UInt64
    let euid: uid_t
    let target: String
    let arguments: [String]
}

private struct DockerCredentialCandidate: Sendable {
    let parent: DockerCredentialParent
    let serverURL: String
    let secretName: String
}

private struct StoredDockerCredential {
    let serverURL: String
    let username: String
    let secret: String
}

private struct ApprovedPayload {
    let secrets: [String: String]
    let value: String?
}

private struct DotenvExecutionKey: Hashable {
    let pid: Int32
    let startUsec: UInt64
    let path: String
    let checksum: String
    let processes: [BlessedDotenvProcess]
}

private final class ApprovalServer: @unchecked Sendable {
    private let serviceName: String
    private let teamIdentifier: String
    private let secretGateDescriptors: [SecretGateDescriptor]
    private let onAutoApproval: @MainActor (AutoApprovalRecord) -> Void
    private let onAccessRequest: @Sendable (AccessRequestRecord) -> Bool
    private let onBlessRequest: @MainActor (
        BlessedScriptReviewRequest,
        @escaping (BlessedScriptReviewOutcome) -> Void
    ) -> Void
    private let onOpenWindow: @MainActor () -> Void
    private let onTemporaryAccessGrantsChanged: @MainActor () -> Void
    private let canRequestHumanApproval: @MainActor () -> Bool
    private let temporaryAccessGrants: TemporaryAccessGrantController
    private var listener: xpc_connection_t?
    // ponytail: helper-lifetime caches; persistent policy remains the cross-restart trust boundary.
    private var transientApprovals = TransientApprovalCache()
    private let retainedProcessProvenanceLock = NSLock()
    private var retainedProcessProvenance = RetainedProcessProvenanceStore()
    private let blessedExecutionsLock = NSLock()
    private var blessedExecutions: [BlessedExecutionKey: BlessedScript] = [:]
    private let awsRegistrationsLock = NSLock()
    private var awsRegistrations: [BlessedExecutionKey: AWSRegistration] = [:]
    private var dotenvExecutions: [DotenvExecutionKey: ApprovalDecision] = [:]

    init(
        serviceName: String,
        temporaryAccessGrants: TemporaryAccessGrantController,
        onAutoApproval: @escaping @MainActor (AutoApprovalRecord) -> Void = { _ in },
        onAccessRequest: @escaping @Sendable (AccessRequestRecord) -> Bool = { appendAccessRequestRecord($0) },
        onBlessRequest: @escaping @MainActor (
            BlessedScriptReviewRequest,
            @escaping (BlessedScriptReviewOutcome) -> Void
        ) -> Void = { _, completion in completion(.failed("script blessing is unavailable")) },
        onOpenWindow: @escaping @MainActor () -> Void = {},
        onTemporaryAccessGrantsChanged: @escaping @MainActor () -> Void = {},
        canRequestHumanApproval: @escaping @MainActor () -> Bool = { true }
    ) throws {
        guard let teamIdentifier = selfTeamIdentifier() else {
            throw AppError("missing menu bar signing team identifier")
        }
        self.serviceName = serviceName
        self.temporaryAccessGrants = temporaryAccessGrants
        self.teamIdentifier = teamIdentifier
        self.secretGateDescriptors = try loadSecretGateDescriptors(
            avExecutableURL: avExecutableURL()
        )
        self.onAutoApproval = onAutoApproval
        self.onAccessRequest = onAccessRequest
        self.onBlessRequest = onBlessRequest
        self.onOpenWindow = onOpenWindow
        self.onTemporaryAccessGrantsChanged = onTemporaryAccessGrantsChanged
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
        (identifier "com.automicvault" or identifier "com.automicvault.av" or \
        identifier "com.automicvault.av-brew-stub" or \
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
        guard let op = ApprovalServiceOperation(rawValue: String(cString: opPointer)) else {
            reply(peer, to: message, ok: false, error: "invalid XPC operation")
            return
        }

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

        if op.requiresLauncherBundleIntegrity,
           let error = launcherBundleIntegrityError(for: identity) {
            reply(peer, to: message, ok: false, error: error)
            return
        }

        switch op {
        case .openWindow where isTrustedMenuHelperCaller(path: callerPath, signing: signing):
            DispatchQueue.main.async { self.onOpenWindow() }
            reply(peer, to: message, ok: true, error: nil)
        case .awsHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard let negotiated = negotiatedAWSHelperProtocolVersion(requested: requested) else {
                reply(peer, to: message, ok: false, error: "AWS helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: String(negotiated))
        case .dockerHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "Docker helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .inject, .keys, .authorize, .dockerGet:
            handleInject(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case .awsCredentials where isTrustedAvCaller(path: callerPath, signing: signing):
            handleAWSCredentials(message, on: peer, pid: pid, identity: identity)
        case .dockerSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleDockerSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .dockerDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleDockerDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .list where isTrustedAvCaller(path: callerPath, signing: signing):
            handleList(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case .save where isTrustedAvCaller(path: callerPath, signing: signing):
            handleSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .saveIfAbsentOrEqual where isTrustedAvCaller(path: callerPath, signing: signing):
            handleSave(
                message,
                on: peer,
                cancellation: cancellation,
                caller: mutationCaller,
                ifAbsentOrEqual: true
            )
        case .bless where isTrustedAvCaller(path: callerPath, signing: signing):
            handleBless(message, on: peer, identity: identity)
        case .dotenv where isTrustedAvCaller(path: callerPath, signing: signing):
            handleDotenv(
                message,
                on: peer,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case .delete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .save where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .ghSave where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .delete where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .ghDelete where isTrustedGhCaller(path: callerPath, signing: signing):
            handleGhDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .stripeSave where isTrustedStripeCaller(path: callerPath, signing: signing):
            handleStripeSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .stripeDelete where isTrustedStripeCaller(path: callerPath, signing: signing):
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
        let names: [String]
        switch loadStoredSecretsResult() {
        case .success(let secrets): names = secrets.map(\.account)
        case .failure(let status):
            _ = onAccessRequest(accessRequestRecord(
                request: request,
                callerPath: callerPath,
                decision: "Failed",
                approvalSource: approvalSource,
                reason: "Stored Secret names are unavailable: \(status)",
                launcher: launcher
            ))
            reply(peer, to: message, ok: false, error: "stored Secret names are unavailable: \(status)")
            return
        }
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
        let request: ApprovalRequest
        do {
            let dockerRequest = try dockerCredentialRequest(
                from: message,
                request: parsedRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let conflicts = Set(dockerRequest.envConflicts)
            let selectionNames = dockerRequest.keys.filter {
                dockerRequest.replaceExistingEnv || !conflicts.contains($0)
            }
            if !selectionNames.isEmpty {
                let repairStatus = resumePendingSecretMutation()
                if repairStatus != errSecSuccess {
                    let names = pendingSecretMutationNames()
                    if names.map({ !Set(selectionNames).isDisjoint(with: $0) }) ?? true {
                        reply(
                            peer,
                            to: message,
                            ok: false,
                            error: "secret repair must complete before this request: \(repairStatus)"
                        )
                        return
                    }
                }
            }
            let selected: [String: StoredSecretValue]
            if selectionNames.isEmpty {
                selected = [:]
            } else {
                let storedSecrets: [StoredSecret]
                switch loadStoredSecretsResult() {
                case .success(let loaded): storedSecrets = loaded
                case .failure(let status):
                    throw AppError("failed to inspect stored Secrets: \(status)")
                }
                selected = try resolveStoredSecretValues(
                    names: selectionNames,
                    cwd: dockerRequest.cwd,
                    secrets: storedSecrets
                )
            }
            request = approvalRequestWithCredentialContext(dockerRequest.selecting(selected))
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
            return
        }
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
        let activeBlessing = activeBlessedScript(pid: pid, identity: identity)
        if let script = activeBlessing {
            if handleBlessedCapability(
                script,
                request: request,
                signing: signing,
                descriptors: secretGateDescriptors,
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
            descriptors: secretGateDescriptors
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
        let currentAgentTaskContext = agentTaskContext(pid: pid)
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
        if let resolvedPolicy,
           let classification,
           let explanation = launcherRuntimeProtectionApprovalExplanation(
               policy: resolvedPolicy,
               classification: classification
           )
        {
            automaticApprovalExplanation = explanation
        } else if let configuredGate,
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
        if let configuredGate,
           let classification,
           let currentAgentTaskContext,
           handleTemporaryAccessGrant(
               request: request,
               gate: configuredGate,
               classification: classification,
               agentTaskContext: currentAgentTaskContext,
               launchers: launchers,
               callerPath: callerPath,
               awsRegistration: awsRegistration,
               scriptApproval: scriptApproval,
               authorizationGate: authorizationGate,
               processChains: processChains,
               pid: pid,
               identity: identity,
               peer: peer,
               message: message
           )
        {
            return
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
        let temporaryGrantCandidate = temporaryAccessGrantCandidate(
            gate: configuredGate,
            classification: classification,
            launcher: launcher,
            agentTaskContext: currentAgentTaskContext
        )
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
            tool: request.tool,
            selectedValueSources: request.selectedValues
                .map { "\($0.key)=\($0.value.source.displayName)" }
                .sorted()
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
                temporaryGrantCandidate: temporaryGrantCandidate,
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
            if decision == .temporaryWriteAccess {
                guard !cancellation.isCanceled,
                      self.canRequestHumanApproval(),
                      let originalCandidate = temporaryGrantCandidate,
                      let liveLauncher = launcherIdentities(for: identity).first(where: {
                          $0.designatedRequirement
                              == originalCandidate.scope.launcherDesignatedRequirement
                      }),
                      let refreshedCandidate = temporaryAccessGrantCandidate(
                          gate: configuredGate,
                          classification: classification,
                          launcher: liveLauncher,
                          agentTaskContext: agentTaskContext(pid: pid)
                      ),
                      refreshedCandidate.scope == originalCandidate.scope
                else {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Failed",
                        approvalSource: "Manual",
                        reason: "Temporary Access Grant eligibility changed before activation",
                        launcher: temporaryGrantCandidate?.launcher
                    ))
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "temporary access grant eligibility changed",
                        humanApprovalDecision: "approved"
                    )
                    return
                }
                do {
                    let payload = try self.approvedPayload(
                        for: request,
                        awsRegistration: awsRegistration,
                        pid: pid,
                        identity: identity
                    )
                    guard self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Approved",
                        approvalSource: "Manual",
                        reason: "Temporary Access Grant — Write Access",
                        launcher: refreshedCandidate.launcher
                    )) else {
                        self.reply(
                            peer,
                            to: message,
                            ok: false,
                            error: "approval audit log is unavailable",
                            humanApprovalDecision: "approved"
                        )
                        return
                    }
                    self.temporaryAccessGrants.startWithLease(
                        scope: refreshedCandidate.scope,
                        launcherName: refreshedCandidate.launcherName,
                        authorizationGateName: refreshedCandidate.authorizationGateName
                    ) { _ in
                        self.reply(
                            peer,
                            to: message,
                            ok: true,
                            error: nil,
                            secrets: payload.secrets,
                            value: payload.value,
                            humanApprovalDecision: "approved"
                        )
                    }
                    self.onTemporaryAccessGrantsChanged()
                } catch {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Failed",
                        approvalSource: "Manual",
                        reason: error.localizedDescription,
                        launcher: refreshedCandidate.launcher
                    ))
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: error.localizedDescription,
                        humanApprovalDecision: "approved"
                    )
                }
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

    private func handleTemporaryAccessGrant(
        request: ApprovalRequest,
        gate: SecretGate,
        classification: SecretGateRequestClassification,
        agentTaskContext: AgentTaskContext,
        launchers: [LauncherIdentity],
        callerPath: String,
        awsRegistration: AWSRegistrationCandidate?,
        scriptApproval: ScriptApproval?,
        authorizationGate: RetainedAuthorizationGate,
        processChains: [[RetainedProcessChainNode]],
        pid: pid_t,
        identity: AVProcessIdentity,
        peer: xpc_connection_t,
        message: xpc_object_t
    ) -> Bool {
        for launcher in launchers {
            do {
                let handled = try temporaryAccessGrants.withActiveLease(
                    authorizationGateID: gate.id,
                    launcherDesignatedRequirement: launcher.designatedRequirement,
                    launcherRuntimeProtection: launcher.runtimeProtection,
                    agentTaskContext: agentTaskContext,
                    classification: classification
                ) { _ in
                    let payload = try approvedPayload(
                        for: request,
                        awsRegistration: awsRegistration,
                        pid: pid,
                        identity: identity
                    )
                    let accessRequestID = UUID()
                    guard onAccessRequest(accessRequestRecord(
                        id: accessRequestID,
                        request: request,
                        callerPath: callerPath,
                        decision: "Approved",
                        approvalSource: "Auto",
                        reason: "Temporary Access Grant — Write Access",
                        launcher: launcher
                    )) else {
                        reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                        return true
                    }
                    rememberRetainedProvenance(
                        at: authorizationGate,
                        launcher: launcher,
                        chains: processChains,
                        retainedMatch: nil
                    )
                    Task { @MainActor in
                        self.onAutoApproval(autoApprovalRecord(
                            accessRequestID: accessRequestID,
                            request: request,
                            script: scriptApproval,
                            launcher: launcher
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
                    return true
                }
                if handled == true { return true }
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
                return true
            }
        }
        return false
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
            $0.allowsExecution(
                snapshotIncompatibleInterpreter: request.snapshotIncompatibleInterpreter
            )
                && $0.matchesExecution(
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
        descriptors: [SecretGateDescriptor],
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
            descriptors: descriptors
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

    private func handleDotenv(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        pid: pid_t,
        identity: AVProcessIdentity,
        callerPath: String,
        signing: SigningInfo
    ) {
        guard let schemaPointer = xpc_dictionary_get_string(message, "schema"),
              let itemPointer = xpc_dictionary_get_string(message, "item"),
              let keyPointer = xpc_dictionary_get_string(message, "key")
        else {
            reply(peer, to: message, ok: false, error: "invalid dotenv request")
            return
        }
        let path = String(cString: schemaPointer)
        let item = String(cString: itemPointer)
        let key = String(cString: keyPointer)
        let url = URL(fileURLWithPath: path)
        guard validSecretKeyName(item), validSecretKeyName(key),
              path.hasPrefix("/"), url.lastPathComponent == ".env.schema",
              url.standardizedFileURL.path == path,
              url.resolvingSymlinksInPath().path == path,
              let data = try? readBlessedScript(path: path),
              dotenvSchemaDeclaration(data: data, item: item, secret: key) != nil,
              storedSecretExists(account: key)
        else {
            reply(peer, to: message, ok: false, error: "dotenv request is not declared by a canonical .env.schema")
            return
        }
        guard let launcher = launcherIdentities(startingAt: identity.ppid).first,
              let parentIdentity = processIdentity(identity.ppid),
              let processes = dotenvProcessChain(startingAt: parentIdentity, launcherPID: launcher.pid),
              !processes.isEmpty
        else {
            reply(peer, to: message, ok: false, error: "dotenv launcher ancestry could not be verified")
            return
        }

        let checksum = dotenvSchemaChecksum(data)
        let launcherRecord = BlessedScriptLauncher(
            bundleIdentifier: launcher.identifier,
            requirement: launcher.designatedRequirement
        )
        let existing = loadBlessedDotenvs().first { $0.id == BlessedDotenv(
            path: path,
            checksum: checksum,
            processes: processes,
            launchers: []
        ).id }
        let launchers = (existing?.launchers ?? []).contains(launcherRecord)
            ? existing!.launchers
            : (existing?.launchers ?? []) + [launcherRecord]
        let blessing = BlessedDotenv(
            path: path,
            checksum: checksum,
            processes: processes,
            launchers: launchers
        )
        let request = ApprovalRequest(
            op: "dotenv",
            keys: [key],
            target: processes.last?.path ?? callerPath,
            args: processes.last?.arguments ?? [],
            cwd: processes.first?.cwd ?? "",
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "Varlock",
            title: "Allow \(item) from this dotenv?",
            detail: "The verified process tree will receive \(key) through Varlock.",
            dotenvPath: path,
            dotenvChecksum: checksum,
            dotenvProcesses: processes
        )
        let execution = DotenvExecutionKey(
            pid: parentIdentity.pid,
            startUsec: parentIdentity.start_usec,
            path: path,
            checksum: checksum,
            processes: processes
        )
        let persistent = loadBlessedDotenvs().contains {
            $0.matches(
                path: path,
                checksum: checksum,
                processes: processes,
                launcherRequirement: launcher.designatedRequirement
            )
        }
        blessedExecutionsLock.lock()
        dotenvExecutions = dotenvExecutions.filter { execution, _ in
            guard let current = processIdentity(execution.pid) else { return false }
            return current.start_usec == execution.startUsec
        }
        let transient = dotenvExecutions[execution]
        blessedExecutionsLock.unlock()

        if persistent {
            discloseDotenvSecret(
                key: key,
                request: request,
                callerPath: callerPath,
                launcher: launcher,
                approvalSource: "Auto",
                reason: "Blessed dotenv \(path)",
                peer: peer,
                message: message
            )
            return
        }
        if let transient {
            guard transient == .approved else {
                reply(peer, to: message, ok: false, error: "dotenv access denied for this process")
                return
            }
            discloseDotenvSecret(
                key: key,
                request: request,
                callerPath: callerPath,
                launcher: launcher,
                approvalSource: "Auto",
                reason: "Allowed once for this process tree",
                peer: peer,
                message: message
            )
            return
        }

        DispatchQueue.main.async {
            guard self.canRequestHumanApproval() else {
                self.reply(peer, to: message, ok: false, error: "dotenv approval is unavailable")
                return
            }
            let decision = showApprovalAlert(
                request: request,
                callerPath: callerPath,
                pid: pid,
                signing: signing,
                scriptApproval: nil,
                launcher: launcher,
                launcherFallbackPath: launcher.path,
                automaticApprovalExplanation: nil,
                allowsPersistentApproval: true,
                persistentApprovalTitle: "Bless for \(approvalPromptRequester(launcher: launcher, fallback: launcher.path).name)"
            )
            self.blessedExecutionsLock.lock()
            self.dotenvExecutions[execution] = decision
            self.blessedExecutionsLock.unlock()
            guard decision != .denied else {
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Denied",
                    approvalSource: "Manual",
                    reason: "Denied in prompt",
                    launcher: launcher
                ))
                self.reply(peer, to: message, ok: false, error: "dotenv access denied")
                return
            }
            if decision == .alwaysApproved {
                let status = saveBlessedDotenv(blessing)
                guard status == errSecSuccess else {
                    self.reply(peer, to: message, ok: false, error: "failed to save dotenv blessing: \(status)")
                    return
                }
            }
            self.discloseDotenvSecret(
                key: key,
                request: request,
                callerPath: callerPath,
                launcher: launcher,
                approvalSource: "Manual",
                reason: decision == .alwaysApproved ? "Blessed in prompt" : "Allowed once in prompt",
                peer: peer,
                message: message
            )
        }
    }

    private func discloseDotenvSecret(
        key: String,
        request: ApprovalRequest,
        callerPath: String,
        launcher: LauncherIdentity,
        approvalSource: String,
        reason: String,
        peer: xpc_connection_t,
        message: xpc_object_t
    ) {
        guard let value = loadStoredSecret(account: key) else {
            reply(peer, to: message, ok: false, error: "failed to load Secret Value for \(key): \(errSecItemNotFound)")
            return
        }
        let id = UUID()
        guard onAccessRequest(accessRequestRecord(
            id: id,
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
        if approvalSource == "Auto" {
            Task { @MainActor in
                self.onAutoApproval(autoApprovalRecord(
                    accessRequestID: id,
                    request: request,
                    script: nil,
                    launcher: launcher
                ))
            }
        }
        reply(peer, to: message, ok: true, error: nil, value: value)
    }

    private func handleSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller,
        ifAbsentOrEqual: Bool = false
    ) {
        guard let pendingNames = pendingSecretMutationNames() else {
            reply(peer, to: message, ok: false, error: "pending Secret mutation state is unavailable")
            return
        }
        if !pendingNames.isEmpty {
            let status = resumePendingSecretMutation()
            reply(
                peer,
                to: message,
                ok: false,
                error: status == errSecSuccess
                    ? "a previous Secret mutation was repaired; retry this save"
                    : "a previous Secret mutation still requires repair: \(status)"
            )
            return
        }
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
        let projectDirectory = xpc_dictionary_get_string(message, "project_directory")
            .map(String.init(cString:))
        if ifAbsentOrEqual, projectDirectory != nil {
            reply(peer, to: message, ok: false, error: "conditional save does not support Project Values")
            return
        }
        let directAccessRules: [DirectAccessRule]
        switch loadDirectAccessRulesResult() {
        case .success(let loaded): directAccessRules = loaded
        case .failure(let status):
            reply(peer, to: message, ok: false, error: "Direct Access policy is unavailable: \(status)")
            return
        }
        let storedSecrets: [StoredSecret]
        switch loadStoredSecretsResult(directAccessRules: directAccessRules) {
        case .success(let loaded): storedSecrets = loaded
        case .failure(let status):
            reply(peer, to: message, ok: false, error: "stored Secrets are unavailable: \(status)")
            return
        }
        let storedSecret = storedSecrets.first { $0.account == key }
        if let storedSecret, !storedSecret.hasConsistentAccessibility {
            reply(peer, to: message, ok: false, error: "secret \(key) must be repaired before it can be changed")
            return
        }
        let accessibility = storedSecret?.accessibility ?? .whenUnlocked
        let directAccessWarning: String
        if let launchers = storedSecret?.directAccessLaunchers, !launchers.isEmpty {
            directAccessWarning = "Direct Access Launchers already authorized for \(key) can use this value immediately: "
                + launchers.map(\.bundleIdentifier).joined(separator: ", ") + "."
        } else {
            directAccessWarning = ""
        }
        let mutation: SecretMutation
        if ifAbsentOrEqual {
            mutation = .saveIfAbsentOrEqual(
                account: key,
                value: value,
                warning: directAccessWarning
            )
        } else if let projectDirectory {
            do {
                _ = try validateCanonicalProjectDirectory(projectDirectory)
            } catch {
                reply(peer, to: message, ok: false, error: error.localizedDescription)
                return
            }
            var warning = "This will create or replace a Project Value for \(escapedSecurityPath(projectDirectory))."
            if !directAccessWarning.isEmpty { warning += " \(directAccessWarning)" }
            let source: StoredSecretValueSource = .projectDirectory(projectDirectory)
            if storedSecret?.values.contains(where: { $0.source == source }) != true,
               let inherited = try? resolveStoredSecretValues(
                   names: [key], cwd: projectDirectory, secrets: storedSecret.map { [$0] } ?? []
               )[key]
            {
                warning += " It will mask the inherited \(escapedSecurityPath(inherited.source.displayName))."
            }
            mutation = .saveProject(
                account: key,
                value: value,
                directory: projectDirectory,
                accessibility: accessibility,
                warning: warning
            )
        } else {
            mutation = .save(
                account: key,
                value: value,
                accessibility: accessibility,
                warning: directAccessWarning
            )
        }
        handleMutation(
            mutation,
            on: peer,
            message: message,
            cancellation: cancellation,
            caller: caller
        )
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
        let declaration: BlessedScriptDeclaration
        do {
            declaration = try blessedScriptDeclaration(data: readBlessedScript(path: path))
        } catch {
            reply(peer, to: message, ok: false, error: "script cannot be blessed: \(error.localizedDescription)")
            return
        }
        for (id, protection) in declaration.manifest.capabilities {
            guard let descriptor = secretGateDescriptors.first(where: { $0.id == id }) else {
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
                && $0.allowsExecution(
                    snapshotIncompatibleInterpreter: declaration.snapshotIncompatibleInterpreter
                )
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
            self.sendEvent(humanApprovalRequiredEvent, to: peer)
            self.onBlessRequest(request) { outcome in
                let reply = blessingReply(for: outcome)
                self.reply(
                    peer,
                    to: message,
                    ok: reply.ok,
                    error: reply.error,
                    humanApprovalDecision: reply.humanApprovalDecision
                )
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

    private func handleDockerSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              let valuePointer = xpc_dictionary_get_string(message, "value")
        else {
            reply(peer, to: message, ok: false, error: "invalid Docker credential store request")
            return
        }
        let key = String(cString: keyPointer)
        let value = String(cString: valuePointer)
        guard let credential = parseDockerCredential(value),
              key == dockerCredentialSecretName(credential.serverURL)
        else {
            reply(peer, to: message, ok: false, error: "invalid Docker credential")
            return
        }
        do {
            let parent = try dockerCredentialParent(for: caller.identity)
            handleMutation(
                .dockerSave(account: key, value: value, serverURL: credential.serverURL, username: credential.username),
                on: peer,
                message: message,
                cancellation: cancellation,
                caller: caller,
                requiredDockerParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleDockerDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let keyPointer = xpc_dictionary_get_string(message, "key"),
              let serverPointer = xpc_dictionary_get_string(message, "docker_server_url")
        else {
            reply(peer, to: message, ok: false, error: "invalid Docker credential erase request")
            return
        }
        let key = String(cString: keyPointer)
        let serverURL = String(cString: serverPointer)
        guard validDockerServerURL(serverURL), key == dockerCredentialSecretName(serverURL) else {
            reply(peer, to: message, ok: false, error: "invalid Docker credential")
            return
        }
        do {
            let parent = try dockerCredentialParent(for: caller.identity)
            handleMutation(
                .dockerDelete(account: key, serverURL: serverURL),
                on: peer,
                message: message,
                cancellation: cancellation,
                caller: caller,
                requiredDockerParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
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
        caller: MutationCaller,
        requiredDockerParent: DockerCredentialParent? = nil
    ) {
        let launcher = requiredDockerParent.flatMap { parent in
            var identity = AVProcessIdentity()
            guard av_process_identity(parent.pid, &identity) else { return nil }
            return launcherIdentity(pid: parent.pid, identity: identity)
        } ?? launcherIdentities(for: caller.identity).first
        let launcherFallbackPath = launcherFallbackPath(for: caller.identity) ?? caller.path
        let requestOverride = requiredDockerParent.map { parent in
            let request = mutation.approvalRequest(callerPath: caller.path)
            return ApprovalRequest(
                op: request.op,
                keys: request.keys,
                target: parent.target,
                args: Array(parent.arguments.dropFirst()),
                cwd: request.cwd,
                replaceExistingEnv: request.replaceExistingEnv,
                allowMissingKeys: request.allowMissingKeys,
                envConflicts: request.envConflicts,
                shebangScript: request.shebangScript,
                scriptData: request.scriptData,
                snapshotIncompatibleInterpreter: request.snapshotIncompatibleInterpreter,
                tool: request.tool,
                title: request.title,
                detail: request.detail,
                dockerServerURL: request.dockerServerURL,
                dockerParent: request.dockerParent,
                selectedValues: request.selectedValues
            )
        }
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
                cancellation: cancellation,
                preflight: requiredDockerParent.map { parent in
                    {
                        self.dockerCredentialParentValid(parent)
                            ? nil
                            : "Docker Target changed before the approved credential mutation"
                    }
                },
                requestOverride: requestOverride
            )
            guard let status = result.status else {
                self.reply(peer, to: message, ok: false, error: result.error)
                return
            }
            switch mutation {
            case .save(let account, _, _, _),
                 .saveProject(let account, _, _, _, _),
                 .saveIfAbsentOrEqual(let account, _, _),
                 .dockerSave(let account, _, _, _):
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
            case .delete(let account), .dockerDelete(let account, _):
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
            case .deleteValue, .rename, .setAccessibility:
                self.reply(peer, to: message, ok: false, error: "invalid XPC mutation")
            }
        }
    }

    private func approvedSecrets(for request: ApprovalRequest) throws -> [String: String] {
        let conflicts = Set(request.envConflicts)
        var secrets: [String: String] = [:]
        for key in request.keys where request.replaceExistingEnv || !conflicts.contains(key) {
            guard let selected = request.selectedValues[key] else {
                if request.allowMissingKeys { continue }
                throw AppError("failed to load secret \(key): \(errSecItemNotFound)")
            }
            switch loadStoredSecretValue(selected) {
            case .success(let value):
                secrets[key] = value
            case .notFound:
                throw AppError("selected value for \(key) no longer exists")
            case .failure(let status):
                throw AppError("failed to load selected value for \(key): \(status)")
            case .invalidUTF8:
                throw AppError("selected value for \(key) is not valid UTF-8")
            }
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
        let generation: AWSRuntimeGeneration
        if let generationPointer = xpc_dictionary_get_string(message, "aws_generation") {
            guard let parsed = AWSRuntimeGeneration(rawValue: String(cString: generationPointer)) else {
                throw AWSCredentialError.unsupportedRuntime("unknown AWS launcher generation")
            }
            generation = parsed
        } else {
            generation = .homebrewV1
        }
        let installedStub = readProtectedAWSStub(path: "/usr/local/bin/aws")
        guard installedStub.map({
            awsGenerationMatchesInstalledStub(generation, target: request.target, stub: $0)
        }) == true else {
            throw AWSCredentialError.unsupportedRuntime("installed AWS launcher does not match the requested generation")
        }
        let chain = try AWSProfileChain.parse(
            configText,
            selectedProfile: String(cString: profilePointer)
        )
        let interpreter: String
        switch generation {
        case .homebrewV1:
            let firstLine = try String(contentsOfFile: request.target, encoding: .utf8)
                .split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)[0]
            interpreter = try awsInterpreter(fromShebang: String(firstLine))
        case .officialV2:
            guard let signing = executableSigningInfo(path: request.target),
                  signing.teamIdentifier == "94KV3E626L",
                  signing.isDeveloperID,
                  signing.runtimeProtection.allowsSecretGateAccess
            else { throw AWSCredentialError.unsupportedRuntime("official AWS CLI identity or Hardened Runtime is invalid") }
            interpreter = request.target
        }
        return AWSRegistrationCandidate(
            generation: generation,
            chain: chain,
            args: request.args,
            target: request.target,
            interpreter: interpreter,
            useLongLivedCredentials: awsRequestMayUseLongLivedCredentials(request)
                && chain.selected.roleARN == nil
                && chain.selected.mfaSerial == nil
        )
    }

    private func dockerCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "docker-get" else {
            guard request.tool != "docker" else {
                throw AppError("Docker credentials require the Docker helper protocol")
            }
            return request
        }
        guard request.tool == "docker",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys.count == 1,
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil,
              let serverPointer = xpc_dictionary_get_string(message, "docker_server_url")
        else { throw AppError("invalid Docker credential request") }
        let serverURL = String(cString: serverPointer)
        let secretName = dockerCredentialSecretName(serverURL)
        guard validDockerServerURL(serverURL), request.keys == [secretName] else {
            throw AppError("Docker registry Secret Name does not match its address")
        }
        let parent = try dockerCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op,
            keys: [secretName],
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: request.cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "docker",
            title: "Use Docker credential for \(serverURL)?",
            detail: "The verified Docker Target will receive the usable registry credential in plaintext, as required by Docker's credential-helper protocol.",
            dockerServerURL: serverURL,
            dockerParent: parent
        )
    }

    private func dockerCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> DockerCredentialParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("Docker credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard dockerTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("Docker credential helper parent is not an eligible Docker Target")
        }
        return DockerCredentialParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func dockerCredentialParentValid(_ parent: DockerCredentialParent) -> Bool {
        var identity = AVProcessIdentity()
        return av_process_identity(parent.pid, &identity)
            && identity.start_usec == parent.startUsec
            && identity.euid == parent.euid
            && pathString(identity) == parent.target
            && processArguments(parent.pid) == parent.arguments
            && dockerTargetIdentityValid(pid: parent.pid, path: parent.target)
    }

    private func dockerTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        let identifiers = [
            "/Applications/Docker.app/Contents/Resources/bin/docker": "docker",
            "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose": "docker-compose",
            "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-buildx": "docker-buildx",
        ]
        guard let identifier = identifiers[path],
              let signing = liveSigningInfo(pid: pid),
              signing.mainExecutable == path
        else { return false }
        return signing.identifier == identifier
            && signing.teamIdentifier == "9BNSXJN65R"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func approvedPayload(
        for request: ApprovalRequest,
        awsRegistration: AWSRegistrationCandidate?,
        pid: pid_t,
        identity: AVProcessIdentity
    ) throws -> ApprovedPayload {
        let dockerParent: DockerCredentialParent?
        if request.op == "docker-get" {
            guard let serverURL = request.dockerServerURL,
                  request.keys == [dockerCredentialSecretName(serverURL)],
                  let parent = request.dockerParent,
                  dockerCredentialParentValid(parent),
                  parent.target == request.target,
                  Array(parent.arguments.dropFirst()) == request.args
            else { throw AppError("invalid Docker credential request") }
            dockerParent = parent
        } else {
            dockerParent = nil
        }
        let secrets = try approvedSecrets(for: request)
        if let dockerParent,
           let serverURL = request.dockerServerURL
        {
            guard dockerCredentialParentValid(dockerParent),
                  let value = secrets[dockerCredentialSecretName(serverURL)],
                  let credential = parseDockerCredential(value),
                  credential.serverURL == serverURL
            else { throw AppError("Docker credential changed before Secret Application") }
        }
        guard let awsRegistration else { return ApprovedPayload(secrets: secrets, value: nil) }
        let key = BlessedExecutionKey(pid: pid, startUsec: identity.start_usec)
        awsRegistrationsLock.lock()
        awsRegistrations = awsRegistrations.filter { key, _ in
            var current = AVProcessIdentity()
            return av_process_identity(key.pid, &current) && current.start_usec == key.startUsec
        }
        awsRegistrations[key] = AWSRegistration(
            generation: awsRegistration.generation,
            chain: awsRegistration.chain,
            args: awsRegistration.args,
            target: awsRegistration.target,
            interpreter: awsRegistration.interpreter,
            useLongLivedCredentials: awsRegistration.useLongLivedCredentials,
            secretValues: request.selectedValues,
            credentials: nil
        )
        awsRegistrationsLock.unlock()
        let section = awsRegistration.chain.selected.name == "default"
            ? "default"
            : "profile \(awsRegistration.chain.selected.name)"
        let config = """
        [\(section)]
        credential_process = /usr/local/bin/av aws-credentials\(awsRegistration.generation == .officialV2 ? " official-v2" : "")
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
        let requestedGeneration = xpc_dictionary_get_string(message, "aws_generation")
            .map { String(cString: $0) }
        guard requestedGeneration == (registration.generation == .officialV2 ? "official-v2" : nil) else {
            reply(peer, to: message, ok: false, error: "AWS credential helper generation does not match its registered parent")
            return
        }
        let parentPath = pathString(parentIdentity)
        guard let arguments = processArguments(parentPID),
              awsRuntimeMatches(
                  generation: registration.generation,
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

        Task {
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

    private func resolveAWSCredentials(
        _ registration: AWSRegistration,
        parentPID: pid_t
    ) async throws -> AWSCredentials {
        guard let accessKeyValue = registration.secretValues["AWS_ACCESS_KEY_ID"],
              let secretKeyValue = registration.secretValues["AWS_SECRET_ACCESS_KEY"],
              case .success(let accessKey) = loadStoredSecretValue(accessKeyValue),
              case .success(let secretKey) = loadStoredSecretValue(secretKeyValue)
        else { throw AppError("selected AWS access keys are unavailable") }
        var credentials = AWSCredentials(accessKeyID: accessKey, secretAccessKey: secretKey)
        if registration.useLongLivedCredentials { return credentials }

        let profiles = registration.chain.profiles
        let base = profiles[0]
        if let serial = base.mfaSerial {
            let tokenCode = try await requestMFACode(serial: serial)
            credentials = try await requestSTSCredentials(
                region: registration.chain.region,
                parameters: [
                    "Action": "GetSessionToken",
                    "Version": "2011-06-15",
                    "DurationSeconds": "3600",
                    "SerialNumber": serial,
                    "TokenCode": tokenCode,
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
                let tokenCode = try await requestMFACode(serial: serial)
                parameters["SerialNumber"] = serial
                parameters["TokenCode"] = tokenCode
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
        guard op == "inject" || op == "keys" || op == "authorize" || op == "docker-get" else { return nil }
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
            snapshotIncompatibleInterpreter: xpc_dictionary_get_string(
                message,
                "snapshot_incompatible_interpreter"
            ).map(String.init(cString:)),
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
    if isTrustedMenuHelperCaller(path: path, signing: signing) {
        return true
    }
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

private func isTrustedMenuHelperCaller(path: String, signing: SigningInfo) -> Bool {
    URL(fileURLWithPath: path).lastPathComponent == "AutomicVaultMenubar"
        && signing.identifier == "com.automicvault"
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
    let configuredProtection: SecretGateProtection
    let source: String
    let launcher: LauncherIdentity?
    let runtimeProtectionFailure: LauncherRuntimeProtection?
}

private func matchingSecretGate(
    request: ApprovalRequest,
    signing: SigningInfo,
    descriptors: [SecretGateDescriptor],
    service: String = secretGatePoliciesKeychainService
) -> SecretGate? {
    loadSecretGates(descriptors: descriptors, service: service).first {
        secretGateMatches($0, request: request, signing: signing)
    }
}

private func matchingSecretGateDefinition(
    request: ApprovalRequest,
    signing: SigningInfo,
    descriptors: [SecretGateDescriptor]
) -> SecretGate? {
    descriptors.lazy.map {
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
            let runtimeProtectionFailure = !policy.runtimeRequirement.allows(
                launcher.runtimeProtection
            )
                ? launcher.runtimeProtection
                : nil
            return ResolvedSecretGatePolicy(
                protection: runtimeProtectionFailure == nil ? policy.protection : .noAccess,
                configuredProtection: policy.protection,
                source: shortAppName(launcher.identifier),
                launcher: launcher,
                runtimeProtectionFailure: runtimeProtectionFailure
            )
        }
    }
    guard let defaultLauncher = launchers.first(where: { !$0.isStandalone })
        ?? launchers.first(where: { $0.runtimeProtection.allowsSecretGateAccess })
        ?? launchers.first
    else { return nil }
    let runtimeProtectionFailure = !defaultLauncher.runtimeProtection.allowsSecretGateAccess
        ? defaultLauncher.runtimeProtection
        : nil
    return ResolvedSecretGatePolicy(
        protection: runtimeProtectionFailure == nil ? gate.defaultProtection : .noAccess,
        configuredProtection: gate.defaultProtection,
        source: gate.defaultPolicyLabel,
        launcher: defaultLauncher,
        runtimeProtectionFailure: runtimeProtectionFailure
    )
}

private func launcherRuntimeProtectionApprovalExplanation(
    policy: ResolvedSecretGatePolicy,
    classification: SecretGateRequestClassification
) -> String? {
    guard let launcher = policy.launcher,
          let failure = policy.runtimeProtectionFailure,
          secretGateProtectionAllows(
              policy.configuredProtection,
              classification: classification
          )
    else { return nil }

    let name = shortAppName(launcher.identifier)
    switch failure {
    case .hardened:
        return nil
    case .hardenedWithLibraryValidationDisabled:
        return "\(name) disables library validation, so third-party code can run inside the Launcher. Automic Vault cannot apply the Authorization Gate’s configured Access Level because this rule requires a stricter runtime posture. Approval is required."
    case .hardenedRuntimeMissing:
        return "\(name) does not enable Hardened Runtime, so Automic Vault cannot apply the Authorization Gate’s configured Access Level. Approval is required."
    case .unsafeEntitlements(let entitlements):
        return "\(name) weakens Hardened Runtime with these entitlements: \(entitlements.joined(separator: ", ")). Automic Vault cannot apply the Authorization Gate’s configured Access Level, so approval is required."
    }
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
    case "docker":
        return dockerRequestClassification(request.args)
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

private func dockerRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = dockerCommandWords(args).map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    if words.contains("--push") { return .mutating }
    switch command {
    case "search": return .readOnly
    case "manifest" where words.dropFirst().first == "inspect": return .readOnly
    case "pull", "run", "create", "build": return .localWrite
    case "image" where words.dropFirst().first == "pull": return .localWrite
    case "push": return .mutating
    case "image" where words.dropFirst().first == "push": return .mutating
    case "buildx":
        guard words.count >= 2 else { return .unknown }
        if words[1] == "imagetools", words.dropFirst(2).first == "inspect" { return .readOnly }
        return words[1] == "build" ? .localWrite : .unknown
    case "compose":
        guard words.count >= 2 else { return .unknown }
        if words[1] == "push" { return .mutating }
        return ["build", "create", "pull", "run", "up"].contains(words[1]) ? .localWrite : .unknown
    default: return .unknown
    }
}

private func dockerCommandWords(_ args: [String]) -> [String] {
    let optionsWithValue = Set(["--config", "-c", "--context", "-H", "--host", "-l", "--log-level"])
    let flags = Set(["--debug", "-D", "--tls", "--tlsverify"])
    var index = 0
    while index < args.count {
        let argument = args[index]
        if argument == "--" { return [] }
        if optionsWithValue.contains(argument) {
            guard index + 1 < args.count else { return [] }
            index += 2
            continue
        }
        if optionsWithValue.contains(where: { argument.hasPrefix("\($0)=") }) || flags.contains(argument) {
            index += 1
            continue
        }
        if argument.hasPrefix("-") { return [] }
        return Array(args[index...])
    }
    return []
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
        snapshotIncompatibleInterpreter: request.snapshotIncompatibleInterpreter,
        tool: request.tool,
        title: "Use long-lived AWS credentials?",
        detail: "AWS does not allow non-MFA GetSessionToken credentials to call this operation. Unless the selected profile uses MFA or assumes a role, Automic Vault will provide your original AWS access keys directly to AWS CLI; they retain every IAM permission assigned to those keys.",
        selectedValues: request.selectedValues
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

private func validDockerServerURL(_ serverURL: String) -> Bool {
    !serverURL.isEmpty
        && serverURL.utf8.count <= 2048
        && !serverURL.unicodeScalars.contains(where: { $0.value == 0 || $0.value == 10 || $0.value == 13 })
}

private func dockerCredentialSecretName(_ serverURL: String) -> String {
    let hash = SHA256.hash(data: Data(serverURL.utf8)).map { String(format: "%02X", $0) }.joined()
    return "DOCKER_REGISTRY_CREDENTIAL_\(hash)"
}

private func parseDockerCredential(_ value: String) -> StoredDockerCredential? {
    guard value.utf8.count <= 64 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["ServerURL", "Username", "Secret"]),
          let serverURL = object["ServerURL"] as? String,
          let username = object["Username"] as? String,
          let secret = object["Secret"] as? String,
          validDockerServerURL(serverURL),
          !username.isEmpty,
          !secret.isEmpty,
          !username.unicodeScalars.contains(where: { $0.value == 0 }),
          !secret.unicodeScalars.contains(where: { $0.value == 0 })
    else { return nil }
    return StoredDockerCredential(serverURL: serverURL, username: username, secret: secret)
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
        if requestExistingInstanceToOpenWindow() {
            return true
        }
        // A pre-open-window release may still be running. Restart it once so
        // the pending request is consumed by the current release.
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

private func requestExistingInstanceToOpenWindow() -> Bool {
    let connection = approvalServiceName.withCString {
        xpc_connection_create_mach_service($0, nil, 0)
    }
    xpc_connection_set_event_handler(connection) { _ in }
    xpc_connection_activate(connection)
    let message = xpc_dictionary_create_empty()
    ApprovalServiceOperation.openWindow.rawValue.withCString {
        xpc_dictionary_set_string(message, "op", $0)
    }
    let reply = xpc_connection_send_message_with_reply_sync(connection, message)
    xpc_connection_cancel(connection)
    return xpc_get_type(reply) == XPC_TYPE_DICTIONARY
        && xpc_dictionary_get_bool(reply, "ok")
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

private func processIdentity(_ pid: pid_t) -> AVProcessIdentity? {
    var identity = AVProcessIdentity()
    return av_process_identity(pid, &identity) ? identity : nil
}

private func dotenvProcessChain(
    startingAt start: AVProcessIdentity,
    launcherPID: pid_t
) -> [BlessedDotenvProcess]? {
    var identity = start
    var seen = Set<pid_t>()
    var processes: [BlessedDotenvProcess] = []
    for _ in 0..<32 {
        guard seen.insert(identity.pid).inserted else { return nil }
        if identity.pid == launcherPID { return processes }
        guard let arguments = processArguments(identity.pid),
              let cwd = processCWD(identity.pid),
              !pathString(identity).isEmpty
        else {
            return nil
        }
        processes.append(BlessedDotenvProcess(
            path: pathString(identity),
            arguments: arguments,
            cwd: cwd
        ))
        guard identity.ppid > 1, let parent = processIdentity(identity.ppid) else { return nil }
        identity = parent
    }
    return nil
}

private func processArguments(_ pid: pid_t) -> [String]? {
    var buffer = [CChar](repeating: 0, count: 8192)
    guard av_process_arguments(pid, &buffer, buffer.count) else { return nil }
    guard let end = buffer.firstIndex(of: 0) else { return nil }
    guard let value = String(bytes: buffer[..<end].map(UInt8.init(bitPattern:)), encoding: .utf8) else { return nil }
    return value.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
}

private func processCWD(_ pid: pid_t) -> String? {
    var buffer = [CChar](repeating: 0, count: 4096)
    guard av_process_cwd(pid, &buffer, buffer.count) else { return nil }
    guard let end = buffer.firstIndex(of: 0) else { return nil }
    return String(bytes: buffer[..<end].map(UInt8.init(bitPattern:)), encoding: .utf8)
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
    var seen = Set<String>()
    let appURLs = (
        appBundleURLs(containing: path)
        + appBundleURLs(containing: signing.mainExecutable)
        + [associatedAppBundleURL(path: path, signing: signing)].compactMap { $0 }
    ).filter { seen.insert($0.path).inserted }
    let claimsLauncherBundleIdentity = signing.identifier.hasPrefix(launcherBundleIdentifierPrefix)
        || appURLs.contains(where: launcherBundleClaimsReservedIdentity)
    if claimsLauncherBundleIdentity {
        guard let appURL = appURLs.first(where: {
            launcherBundleAppURL(containing: $0.path) == $0
        }),
            let liveCodeIdentifier = liveCodeIdentity(pid: pid),
            let enrollment = try? verifyLauncherBundleProcess(
                at: appURL,
                executableURL: URL(fileURLWithPath: path),
                liveIdentifier: signing.identifier,
                liveCodeIdentifier: liveCodeIdentifier,
                liveRuntimeProtection: signing.runtimeProtection
            )
        else { return [] }
        return [LauncherIdentity(
            pid: pid,
            path: path,
            identifier: enrollment.bundleIdentifier,
            teamIdentifier: signing.teamIdentifier,
            designatedRequirement: enrollment.launcherRequirement,
            runtimeProtection: signing.runtimeProtection
        )]
    }
    guard !signing.isAdHoc else { return [] }
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

private func launcherBundleIntegrityError(for identity: AVProcessIdentity) -> String? {
    for startPID in launcherAncestorStartPIDs(identity) {
        var pid = startPID
        var seen = Set<pid_t>()
        for _ in 0..<32 {
            guard pid > 1, seen.insert(pid).inserted else { break }
            var ancestor = AVProcessIdentity()
            guard av_process_identity(pid, &ancestor) else { break }
            let path = pathString(ancestor)
            guard let signing = liveSigningInfo(pid: pid) else {
                pid = ancestor.ppid
                continue
            }
            var seenApps = Set<String>()
            let appURLs = (
                appBundleURLs(containing: path)
                + appBundleURLs(containing: signing.mainExecutable)
                + [associatedAppBundleURL(path: path, signing: signing)].compactMap { $0 }
            ).filter { seenApps.insert($0.path).inserted }
            let claimsLauncherBundleIdentity = signing.identifier.hasPrefix(
                launcherBundleIdentifierPrefix
            ) || appURLs.contains(where: launcherBundleClaimsReservedIdentity)
            if claimsLauncherBundleIdentity {
                guard let appURL = appURLs.first(where: {
                    launcherBundleAppURL(containing: $0.path) == $0
                }),
                    let codeIdentifier = liveCodeIdentity(pid: pid)
                else { return "Launcher Bundle is outside its managed location" }
                do {
                    _ = try verifyLauncherBundleProcess(
                        at: appURL,
                        executableURL: URL(fileURLWithPath: path),
                        liveIdentifier: signing.identifier,
                        liveCodeIdentifier: codeIdentifier,
                        liveRuntimeProtection: signing.runtimeProtection
                    )
                } catch {
                    return "Launcher Bundle denied: \(error.localizedDescription)"
                }
            }
            pid = ancestor.ppid
        }
    }
    return nil
}

private extension ApprovalServiceOperation {
    var requiresLauncherBundleIntegrity: Bool {
        switch self {
        case .openWindow, .awsHelperVersion, .dockerHelperVersion: false
        default: true
        }
    }
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

    var info: CFDictionary?
    let flags = SecCSFlags(
        rawValue: kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSDynamicInformation
    )
    // The C API accepts live SecCode objects despite importing as SecStaticCode in Swift.
    let inspectableCode = unsafeBitCast(code, to: SecStaticCode.self)
    guard SecCodeCopySigningInformation(inspectableCode, flags, &info) == errSecSuccess,
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
    var url = URL(fileURLWithPath: path).standardizedFileURL
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
private func makeApprovalPanel() -> ApprovalPanel {
    let panel = ApprovalPanel(
        contentRect: NSRect(x: 0, y: 0, width: 560, height: 660),
        styleMask: [.borderless, .nonactivatingPanel],
        backing: .buffered,
        defer: false
    )
    panel.backgroundColor = .clear
    panel.isOpaque = false
    panel.hasShadow = true
    panel.isMovableByWindowBackground = false
    panel.isFloatingPanel = true
    panel.hidesOnDeactivate = false
    panel.level = .modalPanel
    panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
    return panel
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
    temporaryGrantCandidate: TemporaryAccessGrantCandidate? = nil,
    allowsPersistentApproval: Bool = false,
    persistentApprovalTitle: String = "Always Allow",
    cancellation: ApprovalCancellation? = nil
) -> ApprovalDecision {
    guard cancellation?.isCanceled != true else { return .canceled }
    let receivedAt = Date()
    let requester = approvalPromptRequester(launcher: launcher, fallback: launcherFallbackPath)
    let content = ApprovalPromptContent(
        requesterName: requester.name,
        requesterIconPath: requester.iconPath,
        credentialConsumer: autoApprovalToolName(request),
        command: exactAuthorizationCommand(request),
        commandPath: approvalCommandPath(request),
        title: request.title,
        detail: request.detail,
        automaticApprovalExplanation: automaticApprovalExplanation,
        cwd: escapedSecurityPath(request.cwd),
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
    let panel = makeApprovalPanel()
    panel.contentView = NSHostingView(
        rootView: ApprovalPromptView(
            content: content,
            maximumHeight: maximumHeight,
            allowsPersistentApproval: allowsPersistentApproval,
            temporaryGrantCandidate: temporaryGrantCandidate,
            persistentApprovalTitle: persistentApprovalTitle,
            decide: {
                decision = $0
                #if !DEBUG
                if decision == .approved || decision == .alwaysApproved {
                    PostHogTelemetry.shared.captureExplicitApproval()
                }
                #endif
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
    defer {
        cancellation?.stopObserving()
    }
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

    if !request.keys.isEmpty {
        sections.insert(ApprovalPromptSection(
            "Secret Values",
            "key.horizontal",
            request.keys.sorted().map { key in
                let source = request.selectedValues[key]?.source
                let display = switch source {
                case .global: "Global Value"
                case .projectDirectory(let path): escapedSecurityPath(path)
                case nil: "(missing)"
                }
                return ApprovalPromptRow(key, display)
            }
        ), at: 1)
    }

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

    if let path = request.dotenvPath, let checksum = request.dotenvChecksum {
        var rows = [
            ApprovalPromptRow("Path", path),
            ApprovalPromptRow("SHA-256", checksum),
        ]
        rows.append(contentsOf: request.dotenvProcesses.enumerated().map { index, process in
            ApprovalPromptRow(
                index == 0 ? "Entrypoint" : "Parent \(index)",
                ([process.path] + process.arguments.dropFirst()).joined(separator: " ") + "\nwd: \(process.cwd)"
            )
        })
        sections.append(ApprovalPromptSection("Dotenv", "doc.badge.key", rows))
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
    let temporaryGrantCandidate: TemporaryAccessGrantCandidate?
    var persistentApprovalTitle = "Always Allow"
    let decide: (ApprovalDecision) -> Void
    let contentSizeDidChange: () -> Void
    @State private var showsDetails = false

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 8) {
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([
                        URL(fileURLWithPath: content.requesterIconPath),
                    ])
                } label: {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: content.requesterIconPath))
                        .resizable()
                        .interpolation(.high)
                        .frame(width: 72, height: 72)
                        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Reveal \(content.requesterName) in Finder")
                .help("Reveal in Finder")
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
                    Button(persistentApprovalTitle) { decide(.alwaysApproved) }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .tint(.blue)
                        .frame(maxWidth: .infinity)
                }
            }

            if let candidate = temporaryGrantCandidate {
                Button { decide(.temporaryWriteAccess) } label: {
                    HStack {
                        Image(systemName: "clock.badge.checkmark")
                        Text("Allow Write Access for 10 Minutes…")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .accessibilityLabel(
                    "Allow Write Access for 10 minutes for \(candidate.scope.agentTaskContext.provider.taskLabel) \(candidate.scope.agentTaskContext.abbreviatedID)"
                )

                Text(
                    "Limited to \(candidate.launcherName), \(candidate.authorizationGateName), and \(candidate.scope.agentTaskContext.provider.taskLabel) \(candidate.scope.agentTaskContext.abbreviatedID)."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            }

            Text(allowsPersistentApproval
                ? "Persistent access remains until its Blessing is removed."
                : "Automic Authorization can be configured for Verified Launchers in the Automic Vault app.")
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

private func automaticAccessToastAccessibilityLabel(_ record: AutoApprovalRecord) -> String {
    "Dismiss \(record.wasDenied ? "rejection" : "approval") notification for \(record.displayCommand)"
}

private struct AutomaticAccessToastView: View {
    let record: AutoApprovalRecord
    let dismiss: () -> Void

    var body: some View {
        Button(action: dismiss) {
            content
        }
        .buttonStyle(.plain)
        .accessibilityLabel(automaticAccessToastAccessibilityLabel(record))
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
                Text(record.displayCommand)
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

private func temporaryAccessGrantRemainingText(_ remaining: TimeInterval) -> String {
    let seconds = max(0, Int(ceil(remaining)))
    return String(format: "%d:%02d", seconds / 60, seconds % 60)
}

private func temporaryAccessGrantMenuTitle(
    _ grant: TemporaryAccessGrantSnapshot,
    wallNow: Date,
    monotonicNow: TimeInterval
) -> String {
    let remaining = temporaryAccessGrantRemainingText(
        grant.remaining(wallNow: wallNow, monotonicNow: monotonicNow)
    )
    return "\(grant.launcherName) → \(grant.authorizationGateName) · \(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID) · \(remaining) — End"
}

private final class TemporaryAccessGrantPanel: NSPanel {
    private var allowsKey = false

    override var canBecomeKey: Bool { allowsKey }

    override func sendEvent(_ event: NSEvent) {
        if event.type == .leftMouseDown, !isKeyWindow {
            allowsKey = true
            makeKey()
        }
        super.sendEvent(event)
    }

    override func close() {}
    override func performClose(_ sender: Any?) {}
}

@MainActor
private func makeTemporaryAccessGrantPanel() -> TemporaryAccessGrantPanel {
    let panel = TemporaryAccessGrantPanel(
        contentRect: .zero,
        styleMask: [.borderless, .nonactivatingPanel],
        backing: .buffered,
        defer: false
    )
    panel.isFloatingPanel = true
    panel.level = .statusBar
    panel.hidesOnDeactivate = false
    panel.canHide = false
    panel.worksWhenModal = true
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.animationBehavior = .none
    panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
    return panel
}

private struct TemporaryAccessGrantStripView: View {
    let grants: [TemporaryAccessGrantSnapshot]
    let wallNow: Date
    let monotonicNow: TimeInterval
    let end: (UUID) -> Void
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Label("TEMPORARY WRITE ACCESS", systemImage: "exclamationmark.shield.fill")
                .font(.caption.weight(.semibold))
                .tracking(1.1)
                .foregroundStyle(.orange)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .accessibilityLabel("Warning: Temporary Write Access is active")

            Divider()

            ForEach(Array(grants.enumerated()), id: \.element.id) { index, grant in
                TemporaryAccessGrantRow(
                    grant: grant,
                    remaining: grant.remaining(wallNow: wallNow, monotonicNow: monotonicNow),
                    end: { end(grant.id) }
                )
                if index != grants.indices.last {
                    Divider().padding(.leading, 42)
                }
            }
        }
        .frame(width: 430)
        .background {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(reduceTransparency
                    ? AnyShapeStyle(Color(nsColor: .windowBackgroundColor))
                    : AnyShapeStyle(.regularMaterial))
        }
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(.separator.opacity(0.8), lineWidth: 1)
        }
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct TemporaryAccessGrantRow: View {
    let grant: TemporaryAccessGrantSnapshot
    let remaining: TimeInterval
    let end: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text("\(grant.launcherName) → \(grant.authorizationGateName)")
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("\(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID) · \(temporaryAccessGrantRemainingText(remaining)) remaining")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                "\(grant.launcherName), \(grant.authorizationGateName), \(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID), \(temporaryAccessGrantRemainingText(remaining)) remaining"
            )

            Button("End", action: end)
                .buttonStyle(.bordered)
                .controlSize(.small)
                .accessibilityLabel(
                    "End temporary Write Access for \(grant.launcherName), \(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID)"
                )
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

private func autoApprovalToastFrame(anchor: NSRect, visibleFrame: NSRect, size: NSSize) -> NSRect {
    let margin: CGFloat = 8
    let x = min(max(anchor.midX - size.width / 2, visibleFrame.minX + margin), visibleFrame.maxX - size.width - margin)
    let y = max(visibleFrame.minY + margin, min(anchor.minY - 4, visibleFrame.maxY) - size.height)
    return NSRect(origin: NSPoint(x: x, y: y), size: size)
}

@MainActor
private func reanchorToastWindows(below frame: NSRect, visibleFrame: NSRect) {
    for window in toastWindows where window.isVisible {
        window.setFrame(
            autoApprovalToastFrame(anchor: frame, visibleFrame: visibleFrame, size: window.frame.size),
            display: true
        )
    }
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
    let frame = autoApprovalToastFrame(
        anchor: temporaryAccessGrantStripFrame ?? anchor,
        visibleFrame: visibleFrame,
        size: size
    )
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
        SecretMutation.saveIfAbsentOrEqual(account: "TEST_SECRET", value: "secret"),
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

    var performedWhileInactive = false
    let inactive = performApprovedSecretMutation(
        .saveIfAbsentOrEqual(account: "TEST_SECRET", value: "secret"),
        callerPath: "/usr/local/bin/av",
        pid: 42,
        signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
        launcher: nil,
        launcherFallbackPath: "/Applications/Terminal.app",
        canRequestHumanApproval: { false },
        onAccessRequest: { _ in true },
        decision: { _ in .approved },
        perform: { _ in
            performedWhileInactive = true
            return errSecSuccess
        }
    )
    guard inactive.status == nil,
          inactive.error == "secret mutation denied while user session is inactive",
          !performedWhileInactive
    else { return 1 }

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
    guard unaudited.status == nil, !performedWithoutAudit else { return 1 }

    let dockerRequest = ApprovalRequest(
        op: "docker-save",
        keys: ["DOCKER_REGISTRY_CREDENTIAL_TEST"],
        target: "/Applications/Docker.app/Contents/Resources/bin/docker",
        args: ["login", "registry.example"],
        cwd: "",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: "docker",
        title: nil,
        detail: nil
    )
    var approvedRequest: ApprovalRequest?
    var performedAfterFailedPreflight = false
    let changedDocker = performApprovedSecretMutation(
        .dockerDelete(account: "DOCKER_REGISTRY_CREDENTIAL_TEST", serverURL: "registry.example"),
        callerPath: "/usr/local/bin/av",
        pid: 42,
        signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
        launcher: nil,
        launcherFallbackPath: "/Applications/Terminal.app",
        canRequestHumanApproval: { true },
        onAccessRequest: { _ in true },
        decision: {
            approvedRequest = $0
            return .approved
        },
        perform: { _ in
            performedAfterFailedPreflight = true
            return errSecSuccess
        },
        preflight: { "Docker Target changed before mutation" },
        requestOverride: dockerRequest
    )
    guard approvedRequest?.target == dockerRequest.target,
          approvedRequest?.args == dockerRequest.args,
          changedDocker.status == nil,
          changedDocker.error == "Docker Target changed before mutation",
          !performedAfterFailedPreflight
    else { return 1 }
    return 0
}

@MainActor
private func runApprovalSelfCheck() -> Int32 {
    let helperSigning = SigningInfo(identifier: "com.automicvault", teamIdentifier: "TEAM")
    guard processEnvironmentValueSelfCheck() else {
        print("bounded peer environment self-check failed")
        return 2
    }
    guard !makeApprovalPanel().isMovableByWindowBackground else { return 1 }
    guard isTrustedMenuHelperCaller(
        path: "/Applications/Automic Vault.app/Contents/MacOS/AutomicVaultMenubar",
        signing: helperSigning
    ), !isTrustedMenuHelperCaller(path: "/tmp/av", signing: helperSigning)
    else { return 1 }

    let approvedBlessing = blessingReply(for: .approved)
    let deniedBlessing = blessingReply(for: .denied)
    let failedBlessing = blessingReply(for: .failed("failed"))
    guard approvedBlessing.ok,
          approvedBlessing.error == nil,
          approvedBlessing.humanApprovalDecision == "approved",
          !deniedBlessing.ok,
          deniedBlessing.error == "script blessing denied",
          deniedBlessing.humanApprovalDecision == "denied",
          !failedBlessing.ok,
          failedBlessing.error == "failed",
          failedBlessing.humanApprovalDecision == nil
    else { return 1 }

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
    let candidateGate = SecretGate(
        id: "gh",
        keyPatterns: ["GH_TOKEN_*"],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: []
    )
    let candidateLauncher = LauncherIdentity(
        pid: 41,
        path: "/Applications/Codex.app/Contents/MacOS/Codex",
        identifier: "com.openai.codex",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.openai.codex" and anchor apple generic"#,
        runtimeProtection: .hardened
    )
    let candidateAgent = AgentTaskContext(
        provider: .codex,
        id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    )
    guard temporaryAccessGrantCandidate(
        gate: candidateGate,
        classification: .mutating,
        launcher: candidateLauncher,
        agentTaskContext: candidateAgent
    )?.scope.agentTaskContext == candidateAgent,
    temporaryAccessGrantCandidate(
        gate: candidateGate,
        classification: .readOnly,
        launcher: candidateLauncher,
        agentTaskContext: candidateAgent
    ) == nil,
    temporaryAccessGrantCandidate(
        gate: candidateGate,
        classification: .secretDump,
        launcher: candidateLauncher,
        agentTaskContext: candidateAgent
    ) == nil,
    temporaryAccessGrantCandidate(
        gate: nil,
        classification: .mutating,
        launcher: candidateLauncher,
        agentTaskContext: candidateAgent
    ) == nil,
    temporaryAccessGrantCandidate(
        gate: candidateGate,
        classification: .mutating,
        launcher: LauncherIdentity(
            pid: 41,
            path: candidateLauncher.path,
            identifier: candidateLauncher.identifier,
            teamIdentifier: candidateLauncher.teamIdentifier,
            designatedRequirement: candidateLauncher.designatedRequirement,
            runtimeProtection: .hardenedRuntimeMissing
        ),
        agentTaskContext: candidateAgent
    ) == nil
    else { return 1 }
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
            temporaryGrantCandidate: nil,
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
            temporaryGrantCandidate: nil,
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
    let ghDescriptor = ghMetadata.secretGate!
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
    let stripeDescriptor = stripeMetadata.secretGate!
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
          matchingSecretGate(request: readOnlyGh, signing: ghSigning, descriptors: [ghDescriptor])?.id == "gh",
          matchingSecretGate(request: ghRequest(keys: ["OTHER_TOKEN"]), signing: ghSigning, descriptors: [ghDescriptor]) == nil,
          matchingSecretGate(request: ghRequest(keys: []), signing: ghSigning, descriptors: [ghDescriptor]) == nil,
          matchingSecretGate(request: ghRequest(op: "inject"), signing: ghSigning, descriptors: [ghDescriptor]) == nil,
          matchingSecretGate(
              request: readOnlyGh,
              signing: SigningInfo(identifier: "com.automicvault.av", teamIdentifier: "TEAM"),
              descriptors: [ghDescriptor]
          ) == nil,
          classifySecretGateRequest(gateID: "gh", request: readOnlyGh) == .readOnly,
          classifySecretGateRequest(gateID: "gh", request: ghRequest(args: ["repo", "delete", "owner/name"])) == .mutating,
          classifySecretGateRequest(gateID: "gh", request: ghRequest(args: ["auth", "token"])) == .secretDump,
          classifySecretGateRequest(gateID: "gh", request: ghRequest(args: ["auth", "status", "--show-token"])) == .secretDump,
          isGhTokenKey("GH_TOKEN_GITHUB_COM_MXCL"),
          !isGhTokenKey("GITHUB_TOKEN"),
          !isGhTokenKey("GH_TOKEN_bad-key"),
          matchingSecretGate(request: stripeRequest, signing: stripeSigning, descriptors: [stripeDescriptor])?.id == "stripe",
          matchingSecretGate(
              request: stripeRequest,
              signing: SigningInfo(identifier: "gh", teamIdentifier: "TEAM"),
              descriptors: [stripeDescriptor]
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
    let awsDescriptor = awsMetadata.secretGate!
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
        descriptors: [awsDescriptor]
    ),
        !blessedScriptCanAutoApprove(
            blessedScript,
            request: awsRequest(args: ["s3", "rm", "s3://bucket/key"]),
            signing: avSigning,
            descriptors: [awsDescriptor]
        ),
        !blessedScriptCanAutoApprove(
            blessedScript,
            request: readOnlyGh,
            signing: ghSigning,
            descriptors: [ghDescriptor]
        ),
        matchingSecretGateDefinition(
            request: readOnlyAws,
            signing: avSigning,
            descriptors: [awsDescriptor]
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

    guard matchingSecretGate(request: readOnlyAws, signing: avSigning, descriptors: [awsDescriptor])?.id == "aws",
          matchingSecretGate(request: longLivedAws, signing: avSigning, descriptors: [awsDescriptor])?.id == "aws",
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
          matchingSecretGate(request: awsRequest(keys: ["AWS_ACCESS_KEY_ID"]), signing: avSigning, descriptors: [awsDescriptor]) == nil,
          matchingSecretGate(request: awsRequest(shebangScript: "/tmp/script"), signing: avSigning, descriptors: [awsDescriptor]) == nil,
          matchingSecretGate(
              request: readOnlyAws,
              signing: SigningInfo(identifier: "aws", teamIdentifier: "TEAM"),
              descriptors: [awsDescriptor]
          ) == nil,
          classifySecretGateRequest(gateID: "aws", request: readOnlyAws) == .readOnly,
          classifySecretGateRequest(gateID: "aws", request: longLivedAws) == .secretDump,
          classifySecretGateRequest(
              gateID: "aws",
              request: awsRequest(args: ["--profile", "dev", "iam", "get-role"])
          ) == .secretDump,
          contextualLongLivedAws.title == "Use long-lived AWS credentials?",
          contextualLongLivedAws.detail?.contains("retain every IAM permission") == true,
          classifySecretGateRequest(
              gateID: "aws",
              request: awsRequest(args: ["s3", "rm", "s3://bucket/key"])
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
    let brewDescriptor = brewMetadata.secretGate!
    guard matchingSecretGate(request: brewRequest, signing: brewSigning, descriptors: [brewDescriptor])?.id == "brew",
          matchingSecretGate(request: brewRequest, signing: avSigning, descriptors: [brewDescriptor]) == nil,
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
    guard launcherPickerAllows(filenameExtension: "226"),
          satisfiesDeveloperIDRequirement({ _ in errSecSuccess }),
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
          ]) == "example → zsh → gh",
          appBundleURL(containing: "/Applications/Example.app/Contents/MacOS/../Resources/payload")?.path
              == "/Applications/Example.app"
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
    let bundledLauncher = LauncherIdentity(
        pid: 40,
        path: "/Applications/Example.app/Contents/MacOS/Example",
        identifier: "com.example.app",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.example.app" and anchor apple generic"#,
        runtimeProtection: .hardened
    )
    let unhardenedBundledLauncher = LauncherIdentity(
        pid: bundledLauncher.pid,
        path: bundledLauncher.path,
        identifier: bundledLauncher.identifier,
        teamIdentifier: bundledLauncher.teamIdentifier,
        designatedRequirement: bundledLauncher.designatedRequirement,
        runtimeProtection: .hardenedRuntimeMissing
    )
    let injectableBundledLauncher = LauncherIdentity(
        pid: bundledLauncher.pid,
        path: bundledLauncher.path,
        identifier: bundledLauncher.identifier,
        teamIdentifier: bundledLauncher.teamIdentifier,
        designatedRequirement: bundledLauncher.designatedRequirement,
        runtimeProtection: injectableLauncher.runtimeProtection
    )

    let unconfiguredGate = SecretGate(
        id: "test",
        keyPatterns: [],
        routes: [],
        defaultProtection: .fullIncludingSecretDumps,
        appPolicies: []
    )
    let explicitlyBlockedGate = SecretGate(
        id: "test",
        keyPatterns: [],
        routes: [],
        defaultProtection: .fullIncludingSecretDumps,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: developerID.identifier,
            requirement: requirement,
            protection: .noAccess,
            requiresHardenedRuntime: true
        )]
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
    let defaultRuntimeBlockedPolicy = resolveSecretGatePolicy(
        gate: unconfiguredGate,
        launchers: [unhardenedLauncher]
    )
    let explicitRuntimeBlockedPolicy = resolveSecretGatePolicy(
        gate: configuredGate,
        launchers: [unhardenedLauncher]
    )
    let explicitlyNoAccessPolicy = resolveSecretGatePolicy(
        gate: explicitlyBlockedGate,
        launchers: [unhardenedLauncher]
    )
    let unsafeRuntimeBlockedPolicy = resolveSecretGatePolicy(
        gate: unconfiguredGate,
        launchers: [injectableLauncher]
    )
    let strictLibraryValidationPolicy = resolveSecretGatePolicy(
        gate: configuredGate,
        launchers: [libraryValidationLauncher]
    )
    let unhardenedBundledPolicy = resolveSecretGatePolicy(
        gate: unconfiguredGate,
        launchers: [unhardenedBundledLauncher]
    )
    let injectableBundledPolicy = resolveSecretGatePolicy(
        gate: unconfiguredGate,
        launchers: [injectableBundledLauncher]
    )
    let mixedRuntimeBlockedPolicy = resolveSecretGatePolicy(
        gate: unconfiguredGate,
        launchers: [launcher, unhardenedBundledLauncher]
    )
    guard let defaultRuntimeBlockedPolicy,
          let explicitRuntimeBlockedPolicy,
          let explicitlyNoAccessPolicy,
          let unsafeRuntimeBlockedPolicy,
          let strictLibraryValidationPolicy,
          let unhardenedBundledPolicy,
          let injectableBundledPolicy,
          let mixedRuntimeBlockedPolicy,
          resolveSecretGatePolicy(gate: unconfiguredGate, launchers: []) == nil,
          resolveSecretGatePolicy(gate: unconfiguredGate, launchers: [launcher])?.protection == .fullIncludingSecretDumps,
          resolveSecretGatePolicy(
              gate: unconfiguredGate,
              launchers: [libraryValidationLauncher]
          )?.protection == .fullIncludingSecretDumps,
          resolveSecretGatePolicy(gate: unconfiguredGate, launchers: [launcher])?.launcher?.designatedRequirement == requirement,
          resolveSecretGatePolicy(
              gate: unconfiguredGate,
              launchers: [launcher, bundledLauncher]
          )?.launcher?.designatedRequirement == bundledLauncher.designatedRequirement,
          resolveSecretGatePolicy(
              gate: unconfiguredGate,
              launchers: [unhardenedLauncher, bundledLauncher]
          )?.launcher?.designatedRequirement == bundledLauncher.designatedRequirement,
          defaultRuntimeBlockedPolicy.protection == .noAccess,
          defaultRuntimeBlockedPolicy.configuredProtection == .fullIncludingSecretDumps,
          defaultRuntimeBlockedPolicy.runtimeProtectionFailure == .hardenedRuntimeMissing,
          launcherRuntimeProtectionApprovalExplanation(
              policy: defaultRuntimeBlockedPolicy,
              classification: .readOnly
          )?.contains("does not enable Hardened Runtime") == true,
          launcherRuntimeProtectionApprovalExplanation(
              policy: defaultRuntimeBlockedPolicy,
              classification: .unknown
          ) == nil,
          resolveSecretGatePolicy(gate: explicitlyBlockedGate, launchers: [launcher])?.protection == .noAccess,
          resolveSecretGatePolicy(gate: configuredGate, launchers: [launcher])?.protection == .readOnly,
          resolveSecretGatePolicy(
              gate: configuredGate,
              launchers: [bundledLauncher, launcher]
          )?.launcher?.designatedRequirement == launcher.designatedRequirement,
          explicitRuntimeBlockedPolicy.protection == .noAccess,
          launcherRuntimeProtectionApprovalExplanation(
              policy: explicitRuntimeBlockedPolicy,
              classification: .readOnly
          )?.contains("Approval is required") == true,
          launcherRuntimeProtectionApprovalExplanation(
              policy: explicitlyNoAccessPolicy,
              classification: .readOnly
          ) == nil,
          strictLibraryValidationPolicy.protection == .noAccess,
          strictLibraryValidationPolicy.runtimeProtectionFailure == .hardenedWithLibraryValidationDisabled,
          launcherRuntimeProtectionApprovalExplanation(
              policy: strictLibraryValidationPolicy,
              classification: .readOnly
          )?.contains("disables library validation") == true,
          unhardenedBundledPolicy.protection == .noAccess,
          unhardenedBundledPolicy.runtimeProtectionFailure == .hardenedRuntimeMissing,
          launcherRuntimeProtectionApprovalExplanation(
              policy: unhardenedBundledPolicy,
              classification: .readOnly
          )?.contains("does not enable Hardened Runtime") == true,
          injectableBundledPolicy.protection == .noAccess,
          injectableBundledPolicy.runtimeProtectionFailure == injectableLauncher.runtimeProtection,
          mixedRuntimeBlockedPolicy.protection == .noAccess,
          mixedRuntimeBlockedPolicy.launcher?.designatedRequirement == bundledLauncher.designatedRequirement,
          resolveSecretGatePolicy(
              gate: libraryLoadingGate,
              launchers: [launcher]
          )?.protection == .readOnly,
          resolveSecretGatePolicy(
              gate: libraryLoadingGate,
              launchers: [libraryValidationLauncher]
          )?.protection == .readOnly,
          resolveSecretGatePolicy(
              gate: libraryLoadingGate,
              launchers: [injectableLauncher]
          )?.protection == .noAccess,
          unsafeRuntimeBlockedPolicy.protection == .noAccess,
          launcherRuntimeProtectionApprovalExplanation(
              policy: unsafeRuntimeBlockedPolicy,
              classification: .readOnly
          )?.contains("com.apple.security.cs.allow-dyld-environment-variables") == true
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

private func runDockerCredentialSelfCheck() -> Int32 {
    guard dockerRequestClassification(["search", "alpine"]) == .readOnly,
          dockerRequestClassification(["pull", "alpine"]) == .localWrite,
          dockerRequestClassification(["push", "example/image"]) == .mutating,
          dockerRequestClassification(["future-command"]) == .unknown,
          dockerRequestClassification(["buildx", "build", "--push", "."]) == .mutating,
          dockerCredentialSecretName("https://ghcr.io")
              == "DOCKER_REGISTRY_CREDENTIAL_82445E613488865FCEA004BCAB798DA99E6D3695EEC0072488AFB0A3B0A3D323",
          let credential = parseDockerCredential(
              #"{"ServerURL":"https://ghcr.io","Username":"octocat","Secret":"token"}"#
          ),
          credential.serverURL == "https://ghcr.io",
          credential.username == "octocat",
          credential.secret == "token",
          parseDockerCredential(
              #"{"ServerURL":"https://ghcr.io","Username":"octocat","Secret":"token","Extra":true}"#
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
            tool: "gh",
            selectedValueSources: []
        )
    }
    let approval = key()
    let denial = key(
        args: ["auth", "token"],
        keys: ["GH_TOKEN_GITHUB_COM_MXCL"]
    )
    let temporaryGrant = key(startUsec: 987, args: ["repo", "create"])
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
    cache.remember(
        .temporaryWriteAccess,
        for: temporaryGrant,
        now: Date(timeIntervalSince1970: 200)
    )
    guard cache.decision(for: denial, now: Date(timeIntervalSince1970: 300)) == .denied,
          cache.decision(for: fallbackAfterDenial, now: Date(timeIntervalSince1970: 300)) == .denied,
          cache.decision(for: temporaryGrant, now: Date(timeIntervalSince1970: 300)) == nil,
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
        displayCommand: String = """
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
            displayCommand: displayCommand,
            keys: ["GH_TOKEN"],
            wasCanceled: false,
            wasDenied: false
        )
    }
    let groupedMenuRecords = groupedAutoApprovals([
        menuRecord(19_800),
        menuRecord(18_900, displayCommand: "gh issue list"),
        menuRecord(18_000, launcher: "Codex"),
        menuRecord(17_100),
    ])
    let groupedMenuItem = AppDelegate().autoApprovalMenuItem(groupedMenuRecords[0])
    guard let groupedSubmenuTitle = groupedMenuItem.submenu?.items.first?.attributedTitle else {
        return 1
    }
    let groupedCommand = groupedMenuRecords[0].record.displayCommand.replacingOccurrences(of: " \\\n  ", with: " ")
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
    let rawCredential = ["ghp", String(repeating: "a", count: 24)].joined(separator: "_")
    let sensitiveRequest = ApprovalRequest(
        op: "inject",
        keys: ["GH_TOKEN"],
        target: "/opt/homebrew/bin/gh",
        args: ["api", "-H", "Authorization: Bearer \(rawCredential)"],
        cwd: "/tmp",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: "gh",
        title: nil,
        detail: nil
    )
    let sensitiveRecord = accessRequestRecord(
        request: sensitiveRequest,
        callerPath: "/usr/local/bin/av",
        decision: "Approved",
        approvalSource: "Auto",
        reason: "Read Only from app policy",
        launcher: nil
    )
    guard let sensitiveRetrospectiveRecord = autoApprovalRecord(sensitiveRecord) else { return 1 }
    let sensitiveMenuItem = AppDelegate().autoApprovalMenuItem(
        groupedAutoApprovals([sensitiveRetrospectiveRecord, sensitiveRetrospectiveRecord])[0]
    )
    guard let sensitiveMenuTitle = sensitiveMenuItem.submenu?.items.first?.attributedTitle?.string else {
        return 1
    }
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
    func retrospectiveRecord(_ decision: String, source: String = "Auto") -> AccessRequestRecord {
        AccessRequestRecord(
            date: recordedApproval.date,
            tool: recordedApproval.tool,
            command: recordedApproval.command,
            decision: decision,
            approvalSource: source,
            reason: recordedApproval.reason,
            launcher: recordedApproval.launcher,
            callerPath: recordedApproval.callerPath,
            target: recordedApproval.target,
            cwd: recordedApproval.cwd,
            keys: recordedApproval.keys,
            detail: recordedApproval.detail
        )
    }
    let policyDenial = retrospectiveRecord("Denied")
    let grantController = TemporaryAccessGrantController()
    let grantWallNow = Date(timeIntervalSince1970: 20_000)
    let grantMonotonicNow: TimeInterval = 100
    let grantAgent = AgentTaskContext(
        provider: .codex,
        id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    )
    let grant = grantController.start(
        scope: TemporaryAccessGrantScope(
            authorizationGateID: "aws",
            launcherDesignatedRequirement: #"identifier "com.openai.codex" and anchor apple generic"#,
            launcherRuntimeRequirement: .hardened,
            agentTaskContext: grantAgent
        ),
        launcherName: "Codex",
        authorizationGateName: "AWS Authorization Gate",
        wallNow: grantWallNow,
        monotonicNow: grantMonotonicNow
    )
    _ = grantController.start(
        scope: TemporaryAccessGrantScope(
            authorizationGateID: "gh",
            launcherDesignatedRequirement: #"identifier "com.anthropic.claude-code" and anchor apple generic"#,
            launcherRuntimeRequirement: .hardened,
            agentTaskContext: AgentTaskContext(provider: .claudeCode, id: UUID())
        ),
        launcherName: "Claude Code",
        authorizationGateName: "GH Authorization Gate",
        wallNow: grantWallNow,
        monotonicNow: grantMonotonicNow
    )
    let grantSnapshots = grantController.snapshots(
        wallNow: grantWallNow,
        monotonicNow: grantMonotonicNow
    )
    let stripView = NSHostingView(rootView: TemporaryAccessGrantStripView(
        grants: grantSnapshots,
        wallNow: grantWallNow,
        monotonicNow: grantMonotonicNow,
        end: { _ in }
    ))
    let grantPanel = makeTemporaryAccessGrantPanel()
    let sampleStripFrame = NSRect(x: 200, y: 400, width: 430, height: 120)
    let stackedToastFrame = autoApprovalToastFrame(
        anchor: sampleStripFrame,
        visibleFrame: NSRect(x: 0, y: 0, width: 800, height: 600),
        size: NSSize(width: 360, height: 120)
    )
    guard grantSnapshots.count == 2,
          temporaryAccessGrantMenuTitle(
              grant,
              wallNow: grantWallNow,
              monotonicNow: grantMonotonicNow
          ) == "Codex → AWS Authorization Gate · Codex task 11111111 · 10:00 — End",
          stripView.fittingSize.width == 430,
          stackedToastFrame.maxY == sampleStripFrame.minY - 4,
          grantPanel.styleMask.contains(.borderless),
          grantPanel.styleMask.contains(.nonactivatingPanel),
          grantPanel.level == .statusBar,
          grantPanel.collectionBehavior.contains(.canJoinAllSpaces),
          grantPanel.collectionBehavior.contains(.fullScreenAuxiliary),
          !grantPanel.hidesOnDeactivate,
          !grantPanel.canHide,
          grantPanel.animationBehavior == .none
    else {
        print(
            "temporary grant UI self-check failed:",
            grantSnapshots.count,
            temporaryAccessGrantMenuTitle(
                grant,
                wallNow: grantWallNow,
                monotonicNow: grantMonotonicNow
            ),
            stripView.fittingSize,
            stackedToastFrame,
            grantPanel.styleMask.rawValue,
            grantPanel.level.rawValue,
            grantPanel.collectionBehavior.rawValue,
            grantPanel.hidesOnDeactivate,
            grantPanel.canHide,
            grantPanel.animationBehavior.rawValue
        )
        return 2
    }
    guard let historyHeading = autoApprovalHistoryHeading(hasRecords: true) else { return 1 }
    guard historyHeading.title == "Automic Authorization History",
          historyHeading.isSectionHeader,
          !historyHeading.isEnabled,
          autoApprovalHistoryHeading(hasRecords: false) == nil,
          autoApprovalRecord(retrospectiveRecord("Approved", source: "Human")) == nil,
          autoApprovalRecord(policyDenial) == nil,
          autoApprovalRecord(retrospectiveRecord("Canceled", source: "Manual")) == nil,
          autoApprovalRecord(retrospectiveRecord("Failed")) == nil,
          shortAppName("com.openai.codex") == "Codex",
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
          exactAuthorizationCommand(envWrapperRequest) == """
          pulumi \\
            stack \\
            ls
          """,
          exactAuthorizationCommand(sensitiveRequest).contains(rawCredential),
          sensitiveRecord.command.contains(rawCredential),
          !sensitiveRecord.commandForDisplay.contains(rawCredential),
          sensitiveRecord.commandForDisplay.contains("<redacted>"),
          !sensitiveRetrospectiveRecord.displayCommand.contains(rawCredential),
          sensitiveRetrospectiveRecord.displayCommand.contains("<redacted>"),
          !sensitiveMenuTitle.contains(rawCredential),
          sensitiveMenuTitle.contains("<redacted>"),
          !automaticAccessToastAccessibilityLabel(sensitiveRetrospectiveRecord).contains(rawCredential),
          automaticAccessToastAccessibilityLabel(sensitiveRetrospectiveRecord).contains("<redacted>"),
          scanAlertLevel(["medium"]) == .medium,
          scanAlertLevel(["medium", "high"]) == .high,
          doctorStatusTitle(count: 0) == nil,
          doctorStatusTitle(count: 1) == "One Doctor Report",
          doctorStatusTitle(count: 2) == "Two Doctor Reports",
          vulnerabilityStatusTitle(count: 1) == "One Vulnerability Detected",
          vulnerabilityStatusTitle(count: 2) == "Two Vulnerabilities Detected",
          groupedMenuRecords.map(\.count) == [2, 1, 1],
          groupedMenuRecords[0].records[1].displayCommand == "gh issue list",
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
                  displayCommand: "aws s3 ls",
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
          restoredApproval.displayCommand == "aws <arguments hidden>",
          restoredApproval.keys == ["AWS_SECRET_ACCESS_KEY"],
          shouldShowAutomaticAccessToast(policyDenial),
          !shouldShowAutomaticAccessToast(retrospectiveRecord("Denied", source: "Manual")),
          automaticAccessDecisionLabel(wasDenied: true) == "AUTO REJECTED",
          automaticAccessDecisionSymbol(wasDenied: true) == "xmark.shield.fill",
          automaticAccessDecisionLabel(wasDenied: restoredApproval.wasDenied) == "AUTO APPROVED",
          automaticAccessDecisionSymbol(wasDenied: restoredApproval.wasDenied) == "checkmark.shield.fill",
          exactAuthorizationCommand(request) == """
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
    ) == 0,
    scanDetectorGroup(["npm"]) == ["npm"],
    scanDetectorGroup(["bash"]) == ["bash", "zsh"]
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

if CommandLine.arguments.contains("--self-check-sleep") {
    sleep(5)
    exit(0)
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

if CommandLine.arguments.contains("--self-check-docker-credentials") {
    exit(runDockerCredentialSelfCheck())
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
