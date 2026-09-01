import AppKit
import AppUpdater
import ApprovalCore
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
private let varlockProtocolVersion: UInt64 = 1
let secCodeSignatureAdHoc: UInt32 = 0x2
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
    private var isStatusMenuOpen = false
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
    private let liveSecretUses = LiveSecretUseController<LiveSecretUseProcess>()
    private var liveSecretUseSnapshots: [LiveSecretUseSnapshot] = []
    private var liveSecretUseMenuItems: [NSMenuItem] = []
    private var liveSecretUseHeadingItem: NSMenuItem?
    private var liveSecretUseSeparator: NSMenuItem?
    private var liveSecretUseTimer: Timer?
    private var baseStatusImage: NSImage?
    #if !DEBUG
    private let postHogTelemetry = PostHogTelemetry.shared
    private var dailyHeartbeatTask: Task<Void, Never>?
    private var lastTelemetryFindingCount: Int?
    #endif

    func applicationDidFinishLaunching(_ notification: Notification) {
        installTextEditingShortcuts()
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
        #if !DEBUG
        startDailyHeartbeat()
        #endif
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
        _ = migrateLegacyGPGSigningSecrets()
        _ = backfillBlessedScriptReviewedContents()
        autoApprovals = loadAccessRequestRecords().compactMap(autoApprovalRecord)
        refreshAutoApprovalMenuItems()
        refreshTemporaryAccessGrants()
        refreshLiveSecretUses()
        refreshCLIInstallState()
        do {
            let approval = try ApprovalServer(
                serviceName: approvalServiceName,
                temporaryAccessGrants: temporaryAccessGrants,
                liveSecretUses: liveSecretUses
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
            } onLiveSecretUsesChanged: { [weak self] in
                self?.refreshLiveSecretUses()
            } canRequestHumanApproval: { [weak self] in
                PhoneApprovalCoordinator.shared.isEnabled
                    || (self?.isUserSessionActive == true && self?.areScreensAwake == true)
            } canRequestMacInput: { [weak self] in
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
        #if !DEBUG
        dailyHeartbeatTask?.cancel()
        #endif
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        stopServices()
    }

    private func stopServices() {
        temporaryAccessGrants.cancelAll()
        refreshTemporaryAccessGrants()
        temporaryAccessGrantTimer?.invalidate()
        temporaryAccessGrantTimer = nil
        liveSecretUses.cancelAll()
        refreshLiveSecretUses()
        liveSecretUseTimer?.invalidate()
        liveSecretUseTimer = nil
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
            alert.addButton(withTitle: "View Release Notes")
            let response = alert.runModal()
            if response == .alertThirdButtonReturn {
                NSWorkspace.shared.open(URL(
                    string: "https://github.com/automic-vault/automic-vault/releases/tag/\(update.version)"
                )!)
                return
            }
            guard response == .alertFirstButtonReturn else { return }

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

    #if !DEBUG
    private func startDailyHeartbeat() {
        dailyHeartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let delay = self?.postHogTelemetry.captureDailyHeartbeat() else { return }
                do {
                    try await Task.sleep(for: .seconds(delay))
                } catch {
                    return
                }
            }
        }
    }
    #endif

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
        guard !isStatusMenuOpen else { return }
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
                guard self?.isStatusMenuOpen == false else { return }
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
        guard !isUpdating, !isStatusMenuOpen else { return }
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
        let insertionIndex = temporaryAccessGrantMenuItemCount + liveSecretUseMenuItemCount
        for item in autoApprovalItems.reversed() {
            menu.insertItem(item, at: insertionIndex)
        }
        guard let heading = autoApprovalHistoryHeading(hasRecords: !autoApprovalItems.isEmpty) else { return }
        menu.insertItem(heading, at: insertionIndex)
        autoApprovalHeadingItem = heading
        let separator = NSMenuItem.separator()
        menu.insertItem(separator, at: insertionIndex + autoApprovalItems.count + 1)
        autoApprovalSeparator = separator
    }

    private var temporaryAccessGrantMenuItemCount: Int {
        temporaryAccessGrantHeadingItem == nil ? 0 : temporaryAccessGrantMenuItems.count + 2
    }

    private var liveSecretUseMenuItemCount: Int {
        liveSecretUseHeadingItem == nil ? 0 : liveSecretUseMenuItems.count + 2
    }

    private func refreshTemporaryAccessGrants() {
        temporaryAccessGrantSnapshots = temporaryAccessGrants.snapshots()
        if temporaryAccessGrantSnapshots.allSatisfy(\.isCountdownSuspended) {
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
        guard !isUpdating, !isStatusMenuOpen, let menu = statusItem.menu else { return }
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
                action: nil,
                keyEquivalent: ""
            )
            item.image = shieldImage(
                symbolName: "exclamationmark.shield.fill",
                color: .systemOrange,
                accessibilityDescription: "Temporary access warning"
            )
            let submenu = NSMenu()
            let addTenMinutes = NSMenuItem(
                title: "Add 10 Minutes",
                action: #selector(addTenMinutesToTemporaryAccessGrant(_:)),
                keyEquivalent: ""
            )
            addTenMinutes.target = self
            addTenMinutes.representedObject = grant.id.uuidString
            submenu.addItem(addTenMinutes)
            submenu.addItem(.separator())
            let toggle = NSMenuItem(
                title: grant.isCountdownSuspended
                    ? "Resume Write Access"
: "Suspend Write Access",
                action: #selector(toggleTemporaryAccessGrantCountdown(_:)),
                keyEquivalent: ""
            )
            toggle.target = self
            toggle.representedObject = grant.id.uuidString
            submenu.addItem(toggle)
            let end = NSMenuItem(
                title: "End temporary Write Access",
                action: #selector(endTemporaryAccessGrant(_:)),
                keyEquivalent: ""
            )
            end.target = self
            end.representedObject = grant.id.uuidString
            submenu.addItem(end)
            item.submenu = submenu
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

    @objc private func addTenMinutesToTemporaryAccessGrant(_ sender: NSMenuItem) {
        guard let rawID = sender.representedObject as? String,
              let id = UUID(uuidString: rawID)
        else { return }
        _ = temporaryAccessGrants.addTenMinutes(id: id)
        refreshTemporaryAccessGrants()
    }

    @objc private func toggleTemporaryAccessGrantCountdown(_ sender: NSMenuItem) {
        guard let rawID = sender.representedObject as? String,
              let id = UUID(uuidString: rawID),
              let grant = temporaryAccessGrantSnapshots.first(where: { $0.id == id })
        else { return }
        _ = temporaryAccessGrants.setCountdownSuspended(
            id: id,
            suspended: !grant.isCountdownSuspended
        )
        refreshTemporaryAccessGrants()
    }

    private func refreshLiveSecretUses() {
        liveSecretUseSnapshots = liveSecretUses.snapshots(isLive: liveSecretUseProcessIsLive)
        if liveSecretUseSnapshots.isEmpty {
            liveSecretUseTimer?.invalidate()
            liveSecretUseTimer = nil
        } else if liveSecretUseTimer == nil {
            let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshLiveSecretUses() }
            }
            RunLoop.main.add(timer, forMode: .common)
            liveSecretUseTimer = timer
        }
        refreshLiveSecretUseMenuItems()
    }

    private func refreshLiveSecretUseMenuItems() {
        guard !isUpdating, !isStatusMenuOpen, let menu = statusItem.menu else { return }
        liveSecretUseMenuItems.forEach(menu.removeItem)
        liveSecretUseMenuItems.removeAll()
        if let liveSecretUseHeadingItem {
            menu.removeItem(liveSecretUseHeadingItem)
            self.liveSecretUseHeadingItem = nil
        }
        if let liveSecretUseSeparator {
            menu.removeItem(liveSecretUseSeparator)
            self.liveSecretUseSeparator = nil
        }
        guard !liveSecretUseSnapshots.isEmpty else { return }

        liveSecretUseMenuItems = liveSecretUseSnapshots.map { use in
            let launcher = use.launcherName ?? "Launcher unavailable"
            let target = URL(fileURLWithPath: use.targetPath).lastPathComponent
            let count = "\(use.secretNames.count) \(use.secretNames.count == 1 ? "Secret" : "Secrets")"
            let item = NSMenuItem(
                title: "\(launcher) → \(target) · \(count)",
                action: nil,
                keyEquivalent: ""
            )
            let submenu = NSMenu()
            let launcherItem = NSMenuItem(
                title: use.launcherName.map { "Verified Launcher: \($0)" }
                    ?? "Verified Launcher unavailable",
                action: nil,
                keyEquivalent: ""
            )
            launcherItem.isEnabled = false
            submenu.addItem(launcherItem)
            let targetItem = NSMenuItem(
                title: "Target: \(use.targetPath) (PID \(use.processID))",
                action: nil,
                keyEquivalent: ""
            )
            targetItem.isEnabled = false
            submenu.addItem(targetItem)
            submenu.addItem(.separator())
            submenu.addItem(makeStatusMenuItem(title: "Secret Names"))
            for name in use.secretNames {
                let secretItem = NSMenuItem(title: name, action: nil, keyEquivalent: "")
                secretItem.isEnabled = false
                submenu.addItem(secretItem)
            }
            submenu.addItem(.separator())
            for text in [
                "Shown while this Target process remains live.",
                "The Target may pass values to child processes; released values cannot be revoked.",
            ] {
                let note = NSMenuItem(title: text, action: nil, keyEquivalent: "")
                note.isEnabled = false
                submenu.addItem(note)
            }
            item.submenu = submenu
            return item
        }
        let insertionIndex = temporaryAccessGrantMenuItemCount
        for item in liveSecretUseMenuItems.reversed() {
            menu.insertItem(item, at: insertionIndex)
        }
        let heading = makeStatusMenuItem(title: "Live Secret Uses")
        menu.insertItem(heading, at: insertionIndex)
        liveSecretUseHeadingItem = heading
        let separator = NSMenuItem.separator()
        menu.insertItem(separator, at: insertionIndex + liveSecretUseMenuItems.count + 1)
        liveSecretUseSeparator = separator
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
            addTenMinutes: { [weak self] id in
                guard let self else { return }
                _ = self.temporaryAccessGrants.addTenMinutes(id: id)
                self.refreshTemporaryAccessGrants()
            },
            end: { [weak self] id in
                guard let self else { return }
                _ = self.temporaryAccessGrants.cancel(id: id)
                self.refreshTemporaryAccessGrants()
            },
            setCountdownSuspended: { [weak self] id, suspended in
                guard let self else { return }
                _ = self.temporaryAccessGrants.setCountdownSuspended(
                    id: id,
                    suspended: suspended
                )
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

    fileprivate func statusMenuTrackingSelfCheck() -> Bool {
        installStatusMenu()
        defer { NSStatusBar.system.removeStatusItem(statusItem) }
        guard let menu = statusItem.menu else { return false }

        menuWillOpen(menu)
        let presentedItems = menu.items
        let process = LiveSecretUseProcess(
            pid: 42,
            startUsec: 1,
            effectiveUserID: geteuid(),
            auditSessionID: 1
        )
        liveSecretUses.record(
            process: process,
            launcherDesignatedRequirement: nil,
            launcherName: "Self Check",
            targetPath: "/usr/bin/true",
            processID: process.pid,
            secretNames: ["TEST_SECRET"]
        )
        liveSecretUseSnapshots = liveSecretUses.snapshots(isLive: { _ in true })
        refreshLiveSecretUseMenuItems()
        let stayedStable = menu.items.count == presentedItems.count
            && zip(menu.items, presentedItems).allSatisfy { $0 === $1 }

        menuDidClose(menu)
        return stayedStable
            && !isStatusMenuOpen
            && liveSecretUseMenuItems.count == 1
            && liveSecretUseHeadingItem != nil
    }
}

private func scanDetectorGroup(_ detectors: Set<String>) -> Set<String> {
    guard !detectors.isDisjoint(with: ["bash", "zsh"]) else { return detectors }
    return detectors.union(["bash", "zsh"])
}

extension AppDelegate: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) {
        if !isStartingUp, !isUpdating {
            refreshAutoApprovalMenuItems()
            refreshTemporaryAccessGrantMenuItems()
            refreshLiveSecretUses()
            refreshDoctorStatus()
        }
        isStatusMenuOpen = true
    }

    func menuDidClose(_ menu: NSMenu) {
        isStatusMenuOpen = false
        guard !isStartingUp, !isUpdating else { return }
        refreshAutoApprovalMenuItems()
        refreshTemporaryAccessGrantMenuItems()
        refreshLiveSecretUseMenuItems()
        refreshDoctorStatus()
        refreshCLIInstallState()
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
        targetRuntimeProtection: automaticTargetRuntimeProtection(
            request: request,
            decision: decision,
            approvalSource: approvalSource
        ),
        cwd: request.cwd,
        keys: request.keys.sorted(),
        detail: request.detail,
        secretValueSources: request.selectedSecretValues.sourceDisplayNames
    )
}

private func automaticTargetRuntimeProtection(
    request: ApprovalRequest,
    decision: String,
    approvalSource: String
) -> String? {
    guard decision == "Approved",
          approvalSource.caseInsensitiveCompare("Auto") == .orderedSame,
          !request.selectedSecretValues.isEmpty
    else { return nil }

    let protection: LauncherRuntimeProtection?
    if let parent = request.credentialParent {
        protection = liveSigningInfo(for: parent)?.runtimeProtection
    } else {
        protection = executableSigningInfo(path: request.target)?.runtimeProtection
    }
    return protection?.targetAuthorizationHistoryDescription
        ?? "Hardened Runtime could not be verified; Secret may be exposed to debugging or process-memory inspection"
}

private func liveSigningInfo(for parent: CredentialHelperParent) -> LiveSigningInfo? {
    func matches(_ identity: AVProcessIdentity) -> Bool {
        identity.start_usec == parent.startUsec
            && identity.euid == parent.euid
            && pathString(identity) == parent.target
    }
    var before = AVProcessIdentity()
    guard av_process_identity(parent.pid, &before),
          matches(before),
          let signing = liveSigningInfo(pid: parent.pid),
          signing.mainExecutable == parent.target
    else { return nil }
    var after = AVProcessIdentity()
    return av_process_identity(parent.pid, &after) && matches(after) ? signing : nil
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

func avExecutableURL() -> URL {
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
    let credentialScope: String?
    let credentialParent: CredentialHelperParent?
    let selectedSecretValues: SelectedSecretValues

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
        credentialScope: String? = nil,
        credentialParent: CredentialHelperParent? = nil,
        selectedSecretValues: SelectedSecretValues = SelectedSecretValues(values: [:])
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
        self.credentialScope = credentialScope
        self.credentialParent = credentialParent
        self.selectedSecretValues = selectedSecretValues
    }

    func selecting(_ values: SelectedSecretValues) -> ApprovalRequest {
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
            credentialScope: credentialScope,
            credentialParent: credentialParent,
            selectedSecretValues: values
        )
    }

    func requesting(keys: [String], title: String, detail: String) -> ApprovalRequest {
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
            credentialScope: credentialScope,
            credentialParent: credentialParent,
            selectedSecretValues: selectedSecretValues
        )
    }

    func decisionReuseRequest(
        clientIdentity: AVProcessIdentity,
        callerPath: String,
        signing: SigningInfo
    ) -> AuthorizationDecisionReuseRequest {
        AuthorizationDecisionReuseRequest(
            client: AuthorizationClientExecution(
                pid: clientIdentity.pid,
                pidVersion: clientIdentity.pidversion,
                startUsec: clientIdentity.start_usec,
                effectiveUserID: clientIdentity.euid,
                auditSessionID: clientIdentity.audit_session_id
            ),
            callerPath: callerPath,
            signingIdentifier: signing.identifier,
            signingTeamIdentifier: signing.teamIdentifier,
            operation: op,
            secretNames: keys,
            target: target,
            arguments: args,
            workingDirectory: cwd,
            replaceExistingEnvironment: replaceExistingEnv,
            allowMissingSecrets: allowMissingKeys,
            environmentConflicts: envConflicts,
            shebangScript: shebangScript,
            scriptData: scriptData,
            snapshotIncompatibleInterpreter: snapshotIncompatibleInterpreter,
            tool: tool,
            title: title,
            detail: detail,
            credentialScope: credentialScope,
            credentialParent: credentialParent.map {
                AuthorizationCredentialHelperParent(
                    pid: $0.pid,
                    startUsec: $0.startUsec,
                    effectiveUserID: $0.euid,
                    target: $0.target,
                    arguments: $0.arguments
                )
            },
            selectedSecretValues: selectedSecretValues,
            policy: awsRequestMayUseLongLivedCredentials(self)
                ? .freshApprovalRequired
                : .reusable
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
    case goatSave(account: String, value: String, scope: String)
    case goatDelete(account: String, scope: String)
    case ordercliSave(account: String, value: String, scope: String)
    case ordercliDelete(account: String, scope: String)
    case openhueSave(account: String, value: String, scope: String)
    case plumberSave(account: String, value: String, scope: String)
    case uaaSave(account: String, value: String, scope: String)
    case uaaDelete(account: String, scope: String)
    case railwaySave(account: String, value: String, scope: String)
    case railwayDelete(account: String, scope: String)
    case oxideSave(account: String, value: String, scope: String)
    case oxideDelete(account: String, scope: String)
    case terraformSave(account: String, value: String, hostname: String)
    case terraformDelete(account: String, hostname: String)
    case deleteValue(account: String, source: StoredSecretValueSource)
    case rename(account: String, newAccount: String)
    case setAccessibility(account: String, accessibility: StoredSecretAccessibility)

    fileprivate var usesCompactApproval: Bool {
        switch self {
        case .save, .saveProject, .saveIfAbsentOrEqual: true
        default: false
        }
    }

    fileprivate func approvalRequest(callerPath: String, requestCWD: String = "") -> ApprovalRequest {
        let properties: (op: String, keys: [String], args: [String], title: String, detail: String)
        switch self {
        case .save(let account, _, _, let warning):
            properties = (
                "save", [account], ["save", account], "Add or modify \(account)?",
                "This will create or replace a Global Value in Automic Vault."
                    + (warning.isEmpty ? "" : " \(warning)")
            )
        case .saveProject(let account, _, let directory, _, let warning):
            properties = (
                "save", [account], ["save", "--project-directory=\(escapedSecurityPath(directory))", account],
                "Add or modify \(account) Project Value?", warning
            )
        case .saveIfAbsentOrEqual(let account, _, let warning):
            properties = (
                "save-if-absent", [account], ["save-if-absent", account], "Add \(account)?",
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
        case .goatSave(let account, _, let scope):
            properties = (
                "goat-save", [account], ["credential", "store", scope],
                "Store goat auth session?",
                "goat will use this password session through its Automic Vault Secret Gate."
            )
        case .goatDelete(let account, let scope):
            properties = (
                "goat-delete", [account], ["credential", "forget", scope],
                "Delete goat auth session?",
                "goat will no longer be able to authenticate with this session."
            )
        case .ordercliSave(let account, _, let scope):
            properties = (
                "ordercli-save", [account], ["credential", "store", scope],
                "Store ordercli session?",
                "ordercli will use this Foodora session through its Automic Vault Secret Gate."
            )
        case .ordercliDelete(let account, let scope):
            properties = (
                "ordercli-delete", [account], ["credential", "forget", scope],
                "Delete ordercli session?",
                "ordercli will no longer be able to authenticate to Foodora with this session."
            )
        case .openhueSave(let account, _, let scope):
            properties = (
                "openhue-save", [account], ["credential", "store", scope],
                "Store Hue application key?",
                "OpenHue CLI will use this bridge credential through its Automic Vault Secret Gate."
            )
        case .plumberSave(let account, _, let scope):
            properties = (
                "plumber-save", [account], ["credential", "store", scope],
                "Store Plumber local config?",
                "Plumber will use this config through its Automic Vault Secret Gate."
            )
        case .uaaSave(let account, _, let scope):
            properties = (
                "uaa-save", [account], ["credential", "store", scope],
                "Store UAA OAuth contexts?",
                "UAA CLI will use these OAuth tokens through its Automic Vault Secret Gate."
            )
        case .uaaDelete(let account, let scope):
            properties = (
                "uaa-delete", [account], ["credential", "forget", scope],
                "Delete UAA OAuth contexts?",
                "UAA CLI will no longer be able to authenticate with these stored contexts."
            )
        case .railwaySave(let account, _, let scope):
            properties = (
                "railway-save", [account], ["credential", "store", scope],
                "Store Railway credential?",
                "Railway CLI will use this credential through its Automic Vault Secret Gate."
            )
        case .railwayDelete(let account, let scope):
            properties = (
                "railway-delete", [account], ["credential", "forget", scope],
                "Delete Railway credential?",
                "Railway CLI will no longer be able to authenticate in this environment."
            )
        case .oxideSave(let account, _, let scope):
            properties = (
                "oxide-save", [account], ["credential", "store", scope],
                "Store Oxide credential?",
                "Oxide CLI will use this profile token through its Automic Vault Secret Gate."
            )
        case .oxideDelete(let account, let scope):
            properties = (
                "oxide-delete", [account], ["credential", "forget", scope],
                "Delete Oxide credential?",
                "Oxide CLI will no longer be able to authenticate with this profile."
            )
        case .terraformSave(let account, _, let hostname):
            properties = (
                "terraform-save", [account], ["credential", "store", hostname],
                "Store Terraform/OpenTofu credential for \(hostname)?",
                "Terraform and OpenTofu will use this token through their Automic Vault Secret Gates."
            )
        case .terraformDelete(let account, let hostname):
            properties = (
                "terraform-delete", [account], ["credential", "forget", hostname],
                "Delete Terraform/OpenTofu credential for \(hostname)?",
                "Terraform and OpenTofu will no longer be able to authenticate to this host with the stored credential."
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
        case .goatSave, .goatDelete: "goat"
        case .ordercliSave, .ordercliDelete: "ordercli"
        case .openhueSave: "openhue-cli"
        case .plumberSave: "plumber"
        case .uaaSave, .uaaDelete: "uaa-cli"
        case .railwaySave, .railwayDelete: "railway"
        case .oxideSave, .oxideDelete: "oxide-cli"
        case .terraformSave, .terraformDelete: "terraform"
        default: URL(fileURLWithPath: callerPath).lastPathComponent
        }
        let cwd: String
        let selectedSecretValues: SelectedSecretValues
        let credentialScope: String?
        switch self {
        case .saveProject(let account, _, let directory, let accessibility, _):
            cwd = directory
            selectedSecretValues = SelectedSecretValues(values: [account: StoredSecretValue(
                source: .projectDirectory(directory),
                keychainAccount: storedSecretKeychainAccount(
                    secretName: account,
                    source: .projectDirectory(directory)
                ),
                accessibility: accessibility,
                keychainProperties: []
            )])
            credentialScope = nil
        case .dockerSave(_, _, let serverURL, _), .dockerDelete(_, let serverURL):
            cwd = requestCWD
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = serverURL
        case .goatSave(_, _, let scope), .goatDelete(_, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .ordercliSave(_, _, let scope), .ordercliDelete(_, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .openhueSave(_, _, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .plumberSave(_, _, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .uaaSave(_, _, let scope), .uaaDelete(_, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .railwaySave(_, _, let scope), .railwayDelete(_, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .oxideSave(_, _, let scope), .oxideDelete(_, let scope):
            cwd = ""
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = scope
        case .terraformSave(_, _, let hostname), .terraformDelete(_, let hostname):
            cwd = requestCWD
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = hostname
        default:
            cwd = requestCWD
            selectedSecretValues = SelectedSecretValues(values: [:])
            credentialScope = nil
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
            credentialScope: credentialScope,
            selectedSecretValues: selectedSecretValues
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
        case .goatSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .goatDelete(let account, _):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .ordercliSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .ordercliDelete(let account, _):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .openhueSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .plumberSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .uaaSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .uaaDelete(let account, _):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .railwaySave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .railwayDelete(let account, _):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .oxideSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .oxideDelete(let account, _):
            return deleteStoredSecretRevokingDirectAccess(account: account)
        case .terraformSave(let account, let value, _):
            return saveStoredSecret(account: account, value: value, accessibility: .whenUnlocked)
        case .terraformDelete(let account, _):
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

private enum ApprovalDecision: Equatable {
    case canceled
    case interrupted
    case denied
    case approved
    case alwaysApproved
    case temporaryWriteAccess
}

private extension ApprovalDecision {
    var reuseOutcome: AuthorizationDecisionReuseOutcome {
        switch self {
        case .canceled: .canceled
        case .interrupted: .interrupted
        case .denied: .denied
        case .approved: .approved
        case .alwaysApproved: .alwaysApproved
        case .temporaryWriteAccess: .temporaryAccessGrant
        }
    }
}

private func terminalApprovalDecision(
    _ decision: ApprovalDecision,
    cancellation: ApprovalCancellation?
) -> ApprovalDecision {
    guard cancellation?.isCanceled != true else { return .canceled }
    return decision == .canceled ? .interrupted : decision
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

private func interruptedAccessRequestRecord(
    request: ApprovalRequest,
    callerPath: String,
    launcher: LauncherIdentity?
) -> AccessRequestRecord {
    accessRequestRecord(
        request: request,
        callerPath: callerPath,
        decision: "Failed",
        approvalSource: "Auto",
        reason: "Approval presentation interrupted",
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
        cancellation: cancellation,
        compact: mutation.usesCompactApproval
    )
    if approval == .interrupted {
        _ = onAccessRequest(interruptedAccessRequestRecord(
            request: request, callerPath: callerPath, launcher: launcher
        ))
        return (nil, "approval presentation interrupted")
    }
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

private func approvalDecision(
    for reusedOutcome: AuthorizationDecisionReuseOutcome?
) -> ApprovalDecision? {
    switch reusedOutcome {
    case .denied: .denied
    case .approved, .alwaysApproved: .approved
    case nil: nil
    case .canceled, .interrupted, .temporaryAccessGrant:
        preconditionFailure("the decision reuse cache returned a non-reusable outcome")
    }
}

final class ApprovalCancellation: @unchecked Sendable {
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
            && !(exists?($0) ?? request.selectedSecretValues.contains($0))
    }
}

private enum RetainedAuthorizationGate: Hashable {
    case blessing(path: String, checksum: String)
    case directSecret
    case secretGate(String)
}

private struct RetainedProcessExecution: Hashable, Sendable {
    let pid: Int32
    let pidVersion: Int32
    let startUsec: UInt64
    let effectiveUserID: UInt32
    let auditSessionID: UInt32
    let codeIdentity: Data
}

private struct ApprovalProcessExecution: Sendable {
    let pid: Int32
    let pidVersion: Int32?
    let startUsec: UInt64
    let effectiveUserID: UInt32
    let auditSessionID: UInt32?
    let codeIdentity: Data
}

private struct LiveSecretUseProcess: Hashable, Sendable {
    let pid: Int32
    let startUsec: UInt64
    let effectiveUserID: UInt32
    let auditSessionID: UInt32
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
        for execution in executions
            where execution.effectiveUserID == geteuid() && isLive(execution)
        {
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
    guard temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: gate != nil,
        classification: classification,
        launcherRuntimeProtection: launcher?.runtimeProtection,
        agentTaskContext: agentTaskContext
    ) == nil,
    let gate, let launcher, let agentTaskContext,
    let runtimeRequirement = launcher.runtimeProtection.secretGateAdmissionRequirement
    else {
        return nil
    }
    let launcherName = temporaryAccessGrantLauncherName(launcher)
    return TemporaryAccessGrantCandidate(
        scope: TemporaryAccessGrantScope(
            authorizationGateID: gate.id,
            launcherDesignatedRequirement: launcher.designatedRequirement,
            launcherRuntimeRequirement: runtimeRequirement,
            agentTaskContext: agentTaskContext
        ),
        launcher: launcher,
        launcherName: launcherName,
        authorizationGateName: gate.authorizationGateName
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
    launcher: LauncherIdentity
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
            launcherRequirement: launcher.designatedRequirement
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

private struct AWSRegistration: Sendable {
    let generation: AWSRuntimeGeneration
    let chain: AWSProfileChain
    let args: [String]
    let target: String
    let interpreter: String
    let useLongLivedCredentials: Bool
    let secretValues: SelectedSecretValues
    var credentials: AWSCredentials?
}

private struct CredentialHelperParent: Sendable {
    let pid: pid_t
    let startUsec: UInt64
    let euid: uid_t
    let target: String
    let arguments: [String]
}

private struct DockerCredentialCandidate: Sendable {
    let parent: CredentialHelperParent
    let serverURL: String
    let secretName: String
}

private struct StoredDockerCredential {
    let serverURL: String
    let username: String
    let secret: String
}

private struct ApprovedPayload: Sendable {
    let secrets: [String: String]
    let value: String?
}

private struct ApprovedFulfillmentMaterial: Sendable {
    let payload: ApprovedPayload
    let awsRegistration: AWSRegistration?
}

private let dockerHelperProtocolVersion: UInt64 = 2

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
    private let onLiveSecretUsesChanged: @MainActor () -> Void
    private let canRequestHumanApproval: @MainActor () -> Bool
    private let temporaryAccessGrants: TemporaryAccessGrantController
    private let liveSecretUses: LiveSecretUseController<LiveSecretUseProcess>
    private let secretValueCustody: SecretValueCustody
    private let canRequestMacInput: @MainActor () -> Bool
    private var listener: xpc_connection_t?
    // ponytail: helper-lifetime caches; persistent policy remains the cross-restart trust boundary.
    private var transientApprovals = AuthorizationDecisionReuseCache()
    private let retainedProcessProvenanceLock = NSLock()
    private var retainedProcessProvenance = RetainedProcessProvenanceStore()
    private let blessedExecutionsLock = NSLock()
    private var blessedExecutions: [BlessedExecutionKey: BlessedScript] = [:]
    private let awsRegistrationsLock = NSLock()
    private var awsRegistrations: [BlessedExecutionKey: AWSRegistration] = [:]

    init(
        serviceName: String,
        temporaryAccessGrants: TemporaryAccessGrantController,
        liveSecretUses: LiveSecretUseController<LiveSecretUseProcess>,
        secretValueCustody: SecretValueCustody = SecretValueCustody(),
        onAutoApproval: @escaping @MainActor (AutoApprovalRecord) -> Void = { _ in },
        onAccessRequest: @escaping @Sendable (AccessRequestRecord) -> Bool = { appendAccessRequestRecord($0) },
        onBlessRequest: @escaping @MainActor (
            BlessedScriptReviewRequest,
            @escaping (BlessedScriptReviewOutcome) -> Void
        ) -> Void = { _, completion in completion(.failed("script blessing is unavailable")) },
        onOpenWindow: @escaping @MainActor () -> Void = {},
        onTemporaryAccessGrantsChanged: @escaping @MainActor () -> Void = {},
        onLiveSecretUsesChanged: @escaping @MainActor () -> Void = {},
        canRequestHumanApproval: @escaping @MainActor () -> Bool = { true },
        canRequestMacInput: @escaping @MainActor () -> Bool = { true }
    ) throws {
        guard let teamIdentifier = selfTeamIdentifier() else {
            throw AppError("missing menu bar signing team identifier")
        }
        self.serviceName = serviceName
        self.temporaryAccessGrants = temporaryAccessGrants
        self.liveSecretUses = liveSecretUses
        self.secretValueCustody = secretValueCustody
        self.teamIdentifier = teamIdentifier
        self.secretGateDescriptors = try loadSecretGateDescriptors(
            avExecutableURL: avExecutableURL()
        )
        self.onAutoApproval = onAutoApproval
        self.onAccessRequest = onAccessRequest
        self.onBlessRequest = onBlessRequest
        self.onOpenWindow = onOpenWindow
        self.onTemporaryAccessGrantsChanged = onTemporaryAccessGrantsChanged
        self.onLiveSecretUsesChanged = onLiveSecretUsesChanged
        self.canRequestHumanApproval = canRequestHumanApproval
        self.canRequestMacInput = canRequestMacInput
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
        identifier "com.automicvault.varlock-plugin-helper" or \
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
            guard requested == dockerHelperProtocolVersion else {
                reply(peer, to: message, ok: false, error: "Docker helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: String(dockerHelperProtocolVersion))
        case .goatHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "goat helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .ordercliHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "ordercli helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .openhueHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "OpenHue helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .plumberHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "Plumber helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .uaaHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "UAA helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .railwayHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "Railway helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .oxideHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "Oxide helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .terraformHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "Terraform helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .aliyunHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "Alibaba Cloud helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .wakatimeHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "WakaTime helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .rcloneHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "rclone helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .kubectlHelperVersion where isTrustedAvCaller(path: callerPath, signing: signing):
            let requested = xpc_dictionary_get_uint64(message, "requested_version")
            guard requested == 1 else {
                reply(peer, to: message, ok: false, error: "kubectl helper protocol upgrade is required")
                return
            }
            reply(peer, to: message, ok: true, error: nil, value: "1")
        case .gpgSign where isTrustedAvCaller(path: callerPath, signing: signing):
            handleInject(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case .inject, .keys, .authorize, .dockerGet, .goatGet, .ordercliGet, .openhueGet, .plumberGet, .uaaGet, .railwayGet,
             .oxideGet, .terraformGet, .aliyunGet, .wakatimeGet, .rcloneGet, .kubectlGet:
            handleInject(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case .varlock where isTrustedVarlockPluginHelperCaller(path: callerPath, signing: signing):
            handleVarlock(
                message,
                on: peer,
                cancellation: cancellation,
                pid: pid,
                identity: identity,
                callerPath: callerPath,
                signing: signing
            )
        case .proxyStart where isTrustedAvCaller(path: callerPath, signing: signing):
            handleProxyStart(
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
        case .goatSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleGoatSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .goatDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleGoatDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .ordercliSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleOrdercliSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .ordercliDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleOrdercliDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .openhueSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleOpenHueSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .plumberSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handlePlumberSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .uaaSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleUAASave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .uaaDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleUAADelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .railwaySave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleRailwaySave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .railwayDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleRailwayDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .oxideSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleOxideSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .oxideDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleOxideDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .terraformSave where isTrustedAvCaller(path: callerPath, signing: signing):
            handleTerraformSave(message, on: peer, cancellation: cancellation, caller: mutationCaller)
        case .terraformDelete where isTrustedAvCaller(path: callerPath, signing: signing):
            handleTerraformDelete(message, on: peer, cancellation: cancellation, caller: mutationCaller)
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
        let cwd = xpc_dictionary_get_string(message, "cwd")
            .map { String(cString: $0) } ?? ""
        let globalOnly = xpc_dictionary_get_bool(message, "global_only")
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
            cwd: cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "av",
            title: "List saved secret names?",
            detail: globalOnly
                ? "Secret values will remain hidden. The requesting app will receive every saved Global Value name."
                : "Secret values will remain hidden. The requesting app will receive every saved secret name."
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
                message: message,
                globalOnly: globalOnly
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
                cancellation: cancellation
            )
            if decision == .canceled {
                _ = self.onAccessRequest(canceledAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: launcher
                ))
                return
            }
            if decision == .interrupted {
                _ = self.onAccessRequest(interruptedAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: launcher
                ))
                self.reply(peer, to: message, ok: false, error: "approval presentation interrupted")
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
            self.discloseSecretNames(
                request: request,
                callerPath: callerPath,
                launcher: launcher,
                approvalSource: "Manual",
                reason: "Allowed once in prompt",
                peer: peer,
                message: message,
                globalOnly: globalOnly
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
        message: xpc_object_t,
        globalOnly: Bool
    ) {
        let names: [String]
        switch loadStoredSecretsResult() {
        case .success(let secrets):
            names = secrets.compactMap { secret in
                (!globalOnly || secret.values.contains { $0.source == .global })
                    ? secret.account : nil
            }
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
        guard var parsedRequest = approvalRequest(from: message) else {
            reply(peer, to: message, ok: false, error: "invalid approval request")
            return
        }
        var launchers = launcherIdentities(for: identity)
        if launchers.isEmpty, let launcher = launcherIdentity(pid: pid, identity: identity) {
            launchers.append(launcher)
        }
        if parsedRequest.op == "gpg-sign" {
            let migrationStatus = migrateLegacyGPGSigningSecrets()
            guard migrationStatus == errSecSuccess else {
                reply(
                    peer,
                    to: message,
                    ok: false,
                    error: "failed to repair the GPG signing credential: \(migrationStatus)"
                )
                return
            }
            let storedSecretNames: Set<String>
            switch loadStoredSecretsForUseResult() {
            case .success(let secrets):
                storedSecretNames = Set(secrets.map(\.account))
            case .failure(let status):
                reply(
                    peer,
                    to: message,
                    ok: false,
                    error: SecretValueCustodyError.inventoryUnavailable(status).localizedDescription
                )
                return
            }
            let names = gpgSigningSecretNames(
                configuration: loadGPGSigningConfiguration(),
                launcherRequirements: launchers.map(\.designatedRequirement),
                storedSecretNames: storedSecretNames
            )
            parsedRequest = parsedRequest.requesting(
                keys: names,
                title: "Sign this Git operation?",
                detail: names.first == gpgAlternatePrivateKeySecretName
                    ? "The Verified Launcher matches your alternate signing-key list. Automic Vault will use the alternate GPG credential."
                    : "Automic Vault will use your default GPG signing credential."
            )
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
            let goatRequest = try goatCredentialRequest(
                from: message,
                request: dockerRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let ordercliRequest = try ordercliCredentialRequest(
                from: message,
                request: goatRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let openhueRequest = try openhueCredentialRequest(
                from: message,
                request: ordercliRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let plumberRequest = try plumberCredentialRequest(
                request: openhueRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let uaaRequest = try uaaCredentialRequest(
                from: message,
                request: plumberRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let railwayRequest = try railwayCredentialRequest(
                from: message,
                request: uaaRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let helperRequest = try terraformCredentialRequest(
                from: message,
                request: railwayRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let aliyunRequest = try aliyunCredentialRequest(
                from: message,
                request: helperRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let oxideRequest = try oxideCredentialRequest(
                from: message,
                request: aliyunRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let wakatimeRequest = try wakatimeCredentialRequest(
                from: message,
                request: oxideRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let rcloneRequest = try rclonePasswordRequest(
                request: wakatimeRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let kubectlRequest = try kubectlCredentialRequest(
                from: message,
                request: rcloneRequest,
                helperIdentity: identity,
                helperPath: callerPath,
                helperSigning: signing
            )
            let conflicts = Set(kubectlRequest.envConflicts)
            let selectionNames = kubectlRequest.keys.filter {
                kubectlRequest.replaceExistingEnv || !conflicts.contains($0)
            }
            let selected = try secretValueCustody.bind(
                names: selectionNames,
                cwd: kubectlRequest.cwd
            )
            request = approvalRequestWithCredentialContext(kubectlRequest.selecting(selected))
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
        let ancestorFallbackPath = launcherFallbackPath(for: identity)
        let launcherFallbackPath = ancestorFallbackPath ?? callerPath
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
                guard try fulfillApprovedRequest(
                    request: request,
                    awsRegistration: awsRegistration,
                    pid: pid,
                    identity: identity,
                    record: record,
                    launcher: matchedLauncher,
                    activateAfterRecording: {
                        registerBlessedExecution(script, pid: pid, identity: identity)
                        rememberRetainedProvenance(
                            at: blessingGate,
                            launcher: matchedLauncher,
                            chains: processChains,
                            retainedMatch: currentBlessingMatch == nil
                                ? retainedBlessingProvenance
                                : nil
                        )
                        Task { @MainActor in
                            self.onAutoApproval(autoApprovalRecord(
                                accessRequestID: accessRequestID,
                                request: request,
                                script: scriptApproval,
                                launcher: matchedLauncher
                            ))
                        }
                    },
                    release: { payload in
                        reply(
                            peer,
                            to: message,
                            ok: true,
                            error: nil,
                            secrets: payload.secrets,
                            value: payload.value
                        )
                    }
                ) else {
                    reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                    return
                }
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
                gateName: configuredGate.map { "the \($0.displayName) gate" } ?? "the Direct Secret Gate"
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
                guard try fulfillApprovedRequest(
                    request: request,
                    awsRegistration: awsRegistration,
                    pid: pid,
                    identity: identity,
                    record: record,
                    launcher: directAccessLauncher,
                    activateAfterRecording: {
                        rememberRetainedProvenance(
                            at: authorizationGate,
                            launcher: directAccessLauncher,
                            chains: processChains,
                            retainedMatch: launchers.contains(where: {
                                $0.designatedRequirement
                                    == directAccessLauncher.designatedRequirement
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
                    },
                    release: { payload in
                        reply(
                            peer,
                            to: message,
                            ok: true,
                            error: nil,
                            secrets: payload.secrets,
                            value: payload.value
                        )
                    }
                ) else {
                    reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                    return
                }
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
                guard try fulfillApprovedRequest(
                    request: request,
                    awsRegistration: awsRegistration,
                    pid: pid,
                    identity: identity,
                    record: record,
                    launcher: authorizingLauncher,
                    activateAfterRecording: {
                        if let authorizingLauncher {
                            rememberRetainedProvenance(
                                at: authorizationGate,
                                launcher: authorizingLauncher,
                                chains: processChains,
                                retainedMatch: launchers.contains(where: {
                                    $0.designatedRequirement
                                        == authorizingLauncher.designatedRequirement
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
                    },
                    release: { payload in
                        reply(
                            peer,
                            to: message,
                            ok: true,
                            error: nil,
                            secrets: payload.secrets,
                            value: payload.value
                        )
                    }
                ) else {
                    reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                    return
                }
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
        let temporaryGrantUnavailableReason = temporaryAccessGrantUnavailableReason(
            hasToolSpecificGate: configuredGate != nil,
            classification: classification,
            launcherRuntimeProtection: launcher?.runtimeProtection,
            agentTaskContext: currentAgentTaskContext
        )
        let promptAccessLevel = if let configuredGate, let resolvedPolicy {
            configuredGate.protectionTitle(resolvedPolicy.protection)
        } else {
            SecretGateProtection.noAccess.title
        }
        let transientApproval = request.decisionReuseRequest(
            clientIdentity: identity,
            callerPath: callerPath,
            signing: signing
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
                explanation: "Approval activates this stored authority for one execution."
            )
        } else {
            promptBlessing = nil
        }
        RunLoop.main.perform(inModes: [.modalPanel, .default]) {
            MainActor.assumeIsolated {
                guard !cancellation.isCanceled,
                      let event = approvalEvent(
                          for: approvalDecision(
                              for: self.transientApprovals.decision(for: transientApproval)
                          ),
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
            var currentIdentity = AVProcessIdentity()
            if av_process_identity(pid, &currentIdentity),
               sameProcessIdentity(identity, currentIdentity),
               let currentLiveSigning = liveSigningInfo(pid: pid)
            {
                let currentCallerPath = pathString(currentIdentity)
                let currentSigning = SigningInfo(
                    identifier: currentLiveSigning.identifier,
                    teamIdentifier: currentLiveSigning.teamIdentifier
                )
                var currentLaunchers = launcherIdentities(for: currentIdentity)
                if currentLaunchers.isEmpty,
                   let currentLauncher = launcherIdentity(pid: pid, identity: currentIdentity)
                {
                    currentLaunchers.append(currentLauncher)
                }
                if currentLiveSigning.mainExecutable == currentCallerPath,
                   currentSigning.identifier == signing.identifier,
                   currentSigning.teamIdentifier == signing.teamIdentifier,
                   isAllowedCaller(path: currentCallerPath, signing: currentSigning),
                   let configuredGate,
                   let classification,
                   let currentAgentTaskContext = agentTaskContext(pid: pid),
                   self.handleTemporaryAccessGrant(
                       request: request,
                       gate: configuredGate,
                       classification: classification,
                       agentTaskContext: currentAgentTaskContext,
                       launchers: currentLaunchers,
                       callerPath: currentCallerPath,
                       awsRegistration: awsRegistration,
                       scriptApproval: scriptApproval,
                       authorizationGate: authorizationGate,
                       processChains: retainedProcessChains(for: currentIdentity),
                       pid: pid,
                       identity: currentIdentity,
                       peer: peer,
                       message: message
                   )
                {
                    return
                }
            }
            let cachedDecision = self.transientApprovals.decision(for: transientApproval)
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
                    let record = accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Approved",
                        approvalSource: "Auto",
                        reason: "Reused recent approval",
                        launcher: promptLauncher
                    )
                    guard try self.fulfillApprovedRequest(
                        request: request,
                        awsRegistration: awsRegistration,
                        pid: pid,
                        identity: identity,
                        record: record,
                        launcher: promptLauncher,
                        release: { payload in
                            self.reply(
                                peer,
                                to: message,
                                ok: true,
                                error: nil,
                                secrets: payload.secrets,
                                value: payload.value
                            )
                        }
                    ) else {
                        self.reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                        return
                    }
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
                accessLevel: promptAccessLevel,
                temporaryGrantCandidate: temporaryGrantCandidate,
                temporaryGrantUnavailableReason: temporaryGrantUnavailableReason,
                classification: classification,
                cancellation: cancellation
            )
            if decision == .canceled {
                _ = self.onAccessRequest(canceledAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: promptLauncher
                ))
                return
            }
            if decision == .interrupted {
                _ = self.onAccessRequest(interruptedAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: promptLauncher
                ))
                self.reply(peer, to: message, ok: false, error: "approval presentation interrupted")
                return
            }
            guard decision != .denied else {
                self.transientApprovals.remember(.denied, for: transientApproval)
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
                    let record = accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Approved",
                        approvalSource: "Manual",
                        reason: "Temporary Access Grant — Write Access",
                        launcher: refreshedCandidate.launcher
                    )
                    guard try self.fulfillApprovedRequest(
                        request: request,
                        awsRegistration: awsRegistration,
                        pid: pid,
                        identity: identity,
                        record: record,
                        launcher: refreshedCandidate.launcher,
                        release: { payload in
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
                        }
                    ) else {
                        self.reply(
                            peer,
                            to: message,
                            ok: false,
                            error: "approval audit log is unavailable",
                            humanApprovalDecision: "approved"
                        )
                        return
                    }
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
                let record = accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: "Approved",
                    approvalSource: "Manual",
                    reason: "Approved in prompt",
                    launcher: promptLauncher
                )
                guard try self.fulfillApprovedRequest(
                    request: request,
                    awsRegistration: awsRegistration,
                    pid: pid,
                    identity: identity,
                    record: record,
                    launcher: promptLauncher,
                    activateAfterRecording: {
                        if let scriptApproval,
                           let script = self.matchingBlessedScriptExecution(
                               request: request,
                               approval: scriptApproval
                           )
                        {
                            self.registerBlessedExecution(script, pid: pid, identity: identity)
                        }
                        self.transientApprovals.remember(
                            decision.reuseOutcome,
                            for: transientApproval
                        )
                    },
                    release: { payload in
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
                ) else {
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "approval audit log is unavailable",
                        humanApprovalDecision: "approved"
                    )
                    return
                }
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
                    let accessRequestID = UUID()
                    let record = accessRequestRecord(
                        id: accessRequestID,
                        request: request,
                        callerPath: callerPath,
                        decision: "Approved",
                        approvalSource: "Auto",
                        reason: "Temporary Access Grant — Write Access",
                        launcher: launcher
                    )
                    let committed = try fulfillApprovedRequest(
                        request: request,
                        awsRegistration: awsRegistration,
                        pid: pid,
                        identity: identity,
                        record: record,
                        launcher: launcher,
                        activateAfterRecording: {
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
                        },
                        release: { payload in
                            reply(
                                peer,
                                to: message,
                                ok: true,
                                error: nil,
                                secrets: payload.secrets,
                                value: payload.value
                            )
                        }
                    )
                    if !committed {
                        reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                        return true
                    }
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

    private func handleVarlock(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        pid: pid_t,
        identity: AVProcessIdentity,
        callerPath: String,
        signing: SigningInfo
    ) {
        guard supportsVarlockProtocol(xpc_dictionary_get_uint64(message, "protocol_version")) else {
            reply(peer, to: message, ok: false, error: "unsupported Varlock plugin protocol")
            return
        }
        guard let requestedKeys = stringArray(message, "keys"),
              let cwdPointer = xpc_dictionary_get_string(message, "cwd"),
              let schemaDigestPointer = xpc_dictionary_get_string(message, "schema_sha256")
        else {
            reply(peer, to: message, ok: false, error: "invalid Varlock plugin request")
            return
        }
        let keys = requestedKeys.sorted()
        let cwd = String(cString: cwdPointer)
        let schemaDigest = String(cString: schemaDigestPointer)
        guard 1...64 ~= keys.count,
              Set(keys).count == keys.count,
              keys.allSatisfy(validSecretKeyName),
              schemaDigest.utf8.count == 64,
              schemaDigest.utf8.allSatisfy({ 48...57 ~= $0 || 97...102 ~= $0 })
        else {
            reply(peer, to: message, ok: false, error: "invalid Varlock Secret declaration")
            return
        }
        var resolutionIdentity = AVProcessIdentity()
        guard identity.ppid > 1,
              av_process_identity(identity.ppid, &resolutionIdentity),
              let resolutionExecution = retainedProcessExecution(
                  pid: identity.ppid, identity: resolutionIdentity
              )
        else {
            reply(peer, to: message, ok: false, error: "Varlock resolution process is unavailable")
            return
        }
        var applicationIdentity = AVProcessIdentity()
        guard resolutionIdentity.ppid > 1,
              av_process_identity(resolutionIdentity.ppid, &applicationIdentity),
              let applicationExecution = retainedProcessExecution(
                  pid: resolutionIdentity.ppid, identity: applicationIdentity
              )
        else {
            reply(peer, to: message, ok: false, error: "Varlock application process is unavailable")
            return
        }
        let applicationPath = pathString(applicationIdentity)
        guard !applicationPath.isEmpty else {
            reply(peer, to: message, ok: false, error: "Varlock application path is unavailable")
            return
        }
        let launchers = launcherIdentities(for: identity)
        let ancestorFallbackPath = launcherFallbackPath(for: identity)
        guard let launcher = executionOrigin(
            among: launchers,
            callerPID: pid,
            ancestorFallbackPath: ancestorFallbackPath
        ) else {
            reply(peer, to: message, ok: false, error: "Verified Launcher is unavailable")
            return
        }
        var launcherProcessIdentity = AVProcessIdentity()
        guard av_process_identity(launcher.pid, &launcherProcessIdentity),
              let launcherExecution = retainedProcessExecution(
                  pid: launcher.pid, identity: launcherProcessIdentity
              )
        else {
            reply(peer, to: message, ok: false, error: "Verified Launcher process is unavailable")
            return
        }
        let selected: SelectedSecretValues
        do {
            selected = try secretValueCustody.bind(names: keys, cwd: cwd)
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
            return
        }
        guard let missingKey = keys.first(where: { !selected.contains($0) }) else {
            let title = keys.count == 1
                ? "Allow the Varlock plugin to receive \(keys[0])?"
                : "Allow the Varlock plugin to receive \(keys.count) Secrets?"
            let request = ApprovalRequest(
                op: ApprovalServiceOperation.varlock.rawValue,
                keys: keys,
                target: applicationPath,
                args: Array((processArguments(resolutionIdentity.ppid) ?? []).dropFirst()),
                cwd: cwd,
                replaceExistingEnv: false,
                allowMissingKeys: false,
                envConflicts: [],
                shebangScript: nil,
                scriptData: nil,
                tool: "Varlock plugin",
                title: title,
                detail: "This Secret Disclosure returns the selected Secret Values to Varlock for one application process. Schema SHA-256: \(schemaDigest).",
                selectedSecretValues: selected
            )
            RunLoop.main.perform(inModes: [.modalPanel, .default]) {
                MainActor.assumeIsolated {
                    guard !cancellation.isCanceled, self.canRequestHumanApproval() else { return }
                    self.sendEvent(humanApprovalRequiredEvent, to: peer)
                }
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
                        reason: "Human approval unavailable",
                        launcher: launcher
                    ))
                    self.reply(peer, to: message, ok: false, error: "human approval unavailable")
                    return
                }
                let decision = showApprovalAlert(
                    request: request,
                    callerPath: callerPath,
                    pid: pid,
                    targetPID: applicationIdentity.pid,
                    signing: signing,
                    scriptApproval: nil,
                    launcher: launcher,
                    launcherFallbackPath: ancestorFallbackPath ?? applicationPath,
                    automaticApprovalExplanation: nil,
                    cancellation: cancellation
                )
                if decision == .canceled {
                    _ = self.onAccessRequest(canceledAccessRequestRecord(
                        request: request, callerPath: callerPath, launcher: launcher
                    ))
                    return
                }
                if decision == .interrupted {
                    _ = self.onAccessRequest(interruptedAccessRequestRecord(
                        request: request, callerPath: callerPath, launcher: launcher
                    ))
                    self.reply(peer, to: message, ok: false, error: "approval presentation interrupted")
                    return
                }
                guard decision == .approved else {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Denied",
                        approvalSource: "Manual",
                        reason: "Denied in prompt",
                        launcher: launcher
                    ))
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "Varlock plugin request denied",
                        humanApprovalDecision: "denied"
                    )
                    return
                }
                do {
                    guard retainedProcessExecutionIsLive(resolutionExecution),
                          retainedProcessExecutionIsLive(applicationExecution),
                          retainedProcessExecutionIsLive(launcherExecution)
                    else {
                        throw AppError(
                            "Varlock, its application, or its Verified Launcher changed before Secret release"
                        )
                    }
                    let secrets = try self.approvedSecrets(for: request)
                    guard secrets.count == keys.count,
                          keys.allSatisfy({ secrets[$0] != nil })
                    else {
                        throw AppError("Automic Vault returned an incomplete Secret set")
                    }
                    let transaction = AuthorizationFulfillmentTransaction(material: secrets)
                    guard transaction.commit(
                        record: {
                            self.onAccessRequest(accessRequestRecord(
                                request: request,
                                callerPath: callerPath,
                                decision: "Approved",
                                approvalSource: "Manual",
                                reason: "Approved in prompt",
                                launcher: launcher
                            ))
                        },
                        activate: { _ in },
                        observe: { secrets in
                            self.recordLiveSecretUse(
                                request: request,
                                secretNames: Set(secrets.keys),
                                launcher: launcher,
                                execution: applicationExecution
                            )
                        },
                        release: { secrets in
                            self.reply(
                                peer,
                                to: message,
                                ok: true,
                                error: nil,
                                secrets: secrets,
                                protocolVersion: varlockProtocolVersion,
                                humanApprovalDecision: "approved"
                            )
                        }
                    ) else {
                        throw AppError("approval audit log is unavailable")
                    }
                } catch {
                    _ = self.onAccessRequest(accessRequestRecord(
                        request: request,
                        callerPath: callerPath,
                        decision: "Failed",
                        approvalSource: "Manual",
                        reason: error.localizedDescription,
                        launcher: launcher
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
            return
        }
        reply(
            peer,
            to: message,
            ok: false,
            error: "failed to load secret \(missingKey): \(errSecItemNotFound)"
        )
    }

    private func handleProxyStart(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        pid: pid_t,
        identity: AVProcessIdentity,
        callerPath: String,
        signing: SigningInfo
    ) {
        guard let parsed = approvalRequest(from: message),
              parsed.op == "proxy-start",
              !parsed.keys.isEmpty,
              Set(parsed.keys).count == parsed.keys.count,
              parsed.target.hasPrefix("/"),
              parsed.envConflicts.isEmpty || parsed.replaceExistingEnv,
              identity.pidversion > 0,
              identity.start_usec > 0,
              identity.euid == geteuid()
        else {
            reply(peer, to: message, ok: false, error: "invalid Proxy Session request")
            return
        }
        let selectedSecretValues: SelectedSecretValues
        do {
            selectedSecretValues = try secretValueCustody.bind(
                names: parsed.keys,
                cwd: parsed.cwd
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
            return
        }
        if let missingName = parsed.keys.first(where: { !selectedSecretValues.contains($0) }) {
            reply(
                peer,
                to: message,
                ok: false,
                error: "failed to load secret \(missingName): \(errSecItemNotFound)"
            )
            return
        }
        let request = ApprovalRequest(
            op: parsed.op,
            keys: parsed.keys.sorted(),
            target: parsed.target,
            args: parsed.args,
            cwd: parsed.cwd,
            replaceExistingEnv: parsed.replaceExistingEnv,
            allowMissingKeys: false,
            envConflicts: parsed.envConflicts,
            shebangScript: nil,
            scriptData: nil,
            tool: "Secret Proxy",
            title: "Start this Proxy Session?",
            detail: "The target receives random Secret References. Automic Vault will ask before releasing secrets to each new destination.",
            selectedSecretValues: selectedSecretValues
        )
        let launchers = launcherIdentities(for: identity)
        let ancestorFallbackPath = launcherFallbackPath(for: identity)
        let launcher = executionOrigin(
            among: launchers,
            callerPID: pid,
            ancestorFallbackPath: ancestorFallbackPath
        )
        let targetProtection = executableSigningInfo(path: request.target)?.runtimeProtection
        let targetCodeIdentity = proxyExecutableCodeIdentity(path: request.target)
        let warning = targetProtection?.allowsSecretGateAccess == true ? nil :
            "The target does not meet Automic Vault’s Hardened Runtime requirements. Code injected into it may steal this Proxy Session’s references and credential, then reuse destinations you allow for the session."

        DispatchQueue.main.async {
            guard !cancellation.isCanceled, self.canRequestHumanApproval() else {
                self.reply(peer, to: message, ok: false, error: "Proxy Session approval unavailable")
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
                automaticApprovalExplanation: warning,
                cancellation: cancellation
            )
            if decision == .interrupted {
                _ = self.onAccessRequest(interruptedAccessRequestRecord(
                    request: request, callerPath: callerPath, launcher: launcher
                ))
                self.reply(peer, to: message, ok: false, error: "approval presentation interrupted")
                return
            }
            guard decision == .approved else {
                let canceled = decision == .canceled
                _ = self.onAccessRequest(accessRequestRecord(
                    request: request,
                    callerPath: callerPath,
                    decision: canceled ? "Canceled" : "Denied",
                    approvalSource: "Manual",
                    reason: canceled ? "Approval canceled" : "Denied in prompt",
                    launcher: launcher
                ))
                if !canceled {
                    self.reply(
                        peer,
                        to: message,
                        ok: false,
                        error: "Proxy Session denied",
                        humanApprovalDecision: "denied"
                    )
                }
                return
            }
            guard self.onAccessRequest(accessRequestRecord(
                request: request,
                callerPath: callerPath,
                decision: "Approved",
                approvalSource: "Manual",
                reason: "Proxy Session approved once",
                launcher: launcher
            )) else {
                self.reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                return
            }
            let launch = ProxySessionLaunch(
                keys: request.keys,
                target: request.target,
                arguments: request.args,
                cwd: request.cwd,
                selectedSecretValues: request.selectedSecretValues,
                targetCodeIdentity: targetCodeIdentity,
                identity: ProxyTargetIdentity(
                    pid: identity.pid,
                    pidVersion: identity.pidversion,
                    startUsec: identity.start_usec,
                    effectiveUserID: identity.euid,
                    auditSessionID: identity.audit_session_id
                )
            )
            Task {
                do {
                    let material = try await SecretProxyCoordinator.shared.start(
                        launch: launch,
                        secretValueCustody: self.secretValueCustody,
                        approveDestination: { destination, cancellation in
                            let destinationRequest = ApprovalRequest(
                                op: "proxy-destination",
                                keys: destination.secretNames,
                                target: destination.target,
                                args: [destination.method, destination.origin + destination.path],
                                cwd: destination.cwd,
                                replaceExistingEnv: false,
                                allowMissingKeys: false,
                                envConflicts: [],
                                shebangScript: nil,
                                scriptData: nil,
                                tool: "Secret Proxy",
                                title: "Allow secrets for \(destination.origin)?",
                                detail: destination.queryNames.isEmpty
                                    ? "The proxy will request these secrets on demand for this URL."
                                    : "The proxy will request these secrets on demand. Query values remain hidden; names: \(destination.queryNames.sorted().joined(separator: ", ")).",
                                selectedSecretValues: destination.selectedSecretValues
                            )
                            return switch showApprovalAlert(
                                request: destinationRequest,
                                callerPath: callerPath,
                                pid: pid,
                                signing: signing,
                                scriptApproval: nil,
                                launcher: launcher,
                                launcherFallbackPath: ancestorFallbackPath ?? callerPath,
                                automaticApprovalExplanation: warning,
                                allowsPersistentApproval: true,
                                persistentApprovalLabel: "Allow for Session",
                                cancellation: cancellation
                            ) {
                            case .approved: ProxyDestinationDecision.allowOnce
                            case .alwaysApproved: ProxyDestinationDecision.allowForSession
                            case .canceled, .interrupted, .denied, .temporaryWriteAccess:
                                ProxyDestinationDecision.deny
                            }
                        }
                    )
                    self.reply(
                        peer,
                        to: message,
                        ok: true,
                        error: nil,
                        proxySession: material,
                        humanApprovalDecision: "approved"
                    )
                } catch {
                    self.reply(peer, to: message, ok: false, error: error.localizedDescription)
                }
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
            let accessRequestID = UUID()
            let record = accessRequestRecord(
                id: accessRequestID,
                request: request,
                callerPath: callerPath,
                decision: "Approved",
                approvalSource: "Auto",
                reason: "Blessed script \(script.path)",
                launcher: launcher
            )
            guard try fulfillApprovedRequest(
                request: request,
                awsRegistration: awsRegistration,
                pid: pid,
                identity: identity,
                record: record,
                launcher: launcher,
                activateAfterRecording: {
                    if let launcher {
                        Task { @MainActor in
                            self.onAutoApproval(autoApprovalRecord(
                                accessRequestID: accessRequestID,
                                request: request,
                                script: ScriptApproval(
                                    path: script.path,
                                    checksum: script.checksum
                                ),
                                launcher: launcher
                            ))
                        }
                    }
                },
                release: { payload in
                    reply(
                        peer,
                        to: message,
                        ok: true,
                        error: nil,
                        secrets: payload.secrets,
                        value: payload.value
                    )
                }
            ) else {
                reply(peer, to: message, ok: false, error: "approval audit log is unavailable")
                return true
            }
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
        let scriptData: Data
        let declaration: BlessedScriptDeclaration
        do {
            scriptData = try readBlessedScript(path: path)
            declaration = try blessedScriptDeclaration(data: scriptData)
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
            scriptData: scriptData,
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
                requiredCredentialParent: parent
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
                requiredCredentialParent: parent
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

    private func handleGoatSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "goat_scope"),
              let valuePointer = xpc_dictionary_get_string(message, "value"),
              let scope = parseGoatCredentialScope(String(cString: scopePointer)),
              let value = parseGoatCredential(String(cString: valuePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid goat credential store request")
            return
        }
        do {
            let parent = try goatCredentialParent(for: caller.identity)
            handleMutation(
                .goatSave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleGoatDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "goat_scope"),
              let scope = parseGoatCredentialScope(String(cString: scopePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid goat credential forget request")
            return
        }
        do {
            let parent = try goatCredentialParent(for: caller.identity)
            handleMutation(
                .goatDelete(account: scope.secretName, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleRailwaySave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "railway_scope"),
              let valuePointer = xpc_dictionary_get_string(message, "value"),
              let scope = parseRailwayCredentialScope(String(cString: scopePointer)),
              let value = parseRailwayCredential(String(cString: valuePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid Railway credential store request")
            return
        }
        do {
            let parent = try railwayCredentialParent(for: caller.identity)
            handleMutation(
                .railwaySave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleOrdercliSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "ordercli_scope"),
              let valuePointer = xpc_dictionary_get_string(message, "value"),
              let scope = parseOrdercliCredentialScope(String(cString: scopePointer)),
              let value = parseOrdercliCredential(String(cString: valuePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid ordercli credential store request")
            return
        }
        do {
            let parent = try ordercliCredentialParent(for: caller.identity)
            handleMutation(
                .ordercliSave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleOrdercliDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "ordercli_scope"),
              let scope = parseOrdercliCredentialScope(String(cString: scopePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid ordercli credential forget request")
            return
        }
        do {
            let parent = try ordercliCredentialParent(for: caller.identity)
            handleMutation(
                .ordercliDelete(account: scope.secretName, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleOpenHueSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "openhue_scope"),
              let valuePointer = xpc_dictionary_get_string(message, "value"),
              let scope = parseOpenHueCredentialScope(String(cString: scopePointer)),
              let value = parseOpenHueCredential(String(cString: valuePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid OpenHue credential store request")
            return
        }
        do {
            let parent = try openhueCredentialParent(for: caller.identity)
            handleMutation(
                .openhueSave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handlePlumberSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let valuePointer = xpc_dictionary_get_string(message, "value"),
              let value = parsePlumberCredential(String(cString: valuePointer)),
              let scope = parsePlumberCredentialScope(plumberCredentialScope)
        else {
            reply(peer, to: message, ok: false, error: "invalid Plumber config store request")
            return
        }
        do {
            let parent = try plumberCredentialParent(for: caller.identity)
            handleMutation(
                .plumberSave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleUAASave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "uaa_scope"),
              let valuePointer = xpc_dictionary_get_string(message, "value"),
              let scope = parseUAACredentialScope(String(cString: scopePointer)),
              let value = parseUAACredential(String(cString: valuePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid UAA credential store request")
            return
        }
        do {
            let parent = try uaaCredentialParent(for: caller.identity)
            handleMutation(
                .uaaSave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleUAADelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "uaa_scope"),
              let scope = parseUAACredentialScope(String(cString: scopePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid UAA credential forget request")
            return
        }
        do {
            let parent = try uaaCredentialParent(for: caller.identity)
            handleMutation(
                .uaaDelete(account: scope.secretName, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleRailwayDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "railway_scope"),
              let scope = parseRailwayCredentialScope(String(cString: scopePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid Railway credential forget request")
            return
        }
        do {
            let parent = try railwayCredentialParent(for: caller.identity)
            handleMutation(
                .railwayDelete(account: scope.secretName, scope: scope.canonical),
                on: peer, message: message, cancellation: cancellation, caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleOxideSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "oxide_scope"),
              let valuePointer = xpc_dictionary_get_string(message, "value"),
              let scope = parseOxideCredentialScope(String(cString: scopePointer)),
              let value = parseOxideCredential(String(cString: valuePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid Oxide credential store request")
            return
        }
        do {
            let parent = try oxideCredentialParent(for: caller.identity)
            handleMutation(
                .oxideSave(account: scope.secretName, value: value, scope: scope.canonical),
                on: peer,
                message: message,
                cancellation: cancellation,
                caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleOxideDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let scopePointer = xpc_dictionary_get_string(message, "oxide_scope"),
              let scope = parseOxideCredentialScope(String(cString: scopePointer))
        else {
            reply(peer, to: message, ok: false, error: "invalid Oxide credential forget request")
            return
        }
        do {
            let parent = try oxideCredentialParent(for: caller.identity)
            handleMutation(
                .oxideDelete(account: scope.secretName, scope: scope.canonical),
                on: peer,
                message: message,
                cancellation: cancellation,
                caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleTerraformSave(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let hostnamePointer = xpc_dictionary_get_string(message, "terraform_hostname"),
              let valuePointer = xpc_dictionary_get_string(message, "value")
        else {
            reply(peer, to: message, ok: false, error: "invalid Terraform credential store request")
            return
        }
        let hostname = String(cString: hostnamePointer)
        let value = String(cString: valuePointer)
        guard let normalized = normalizeTerraformHostname(hostname),
              normalized == hostname,
              parseTerraformCredential(value) != nil
        else {
            reply(peer, to: message, ok: false, error: "invalid Terraform credential")
            return
        }
        do {
            let parent = try terraformCredentialParent(for: caller.identity)
            handleMutation(
                .terraformSave(
                    account: terraformCredentialSecretName(hostname),
                    value: value,
                    hostname: hostname
                ),
                on: peer,
                message: message,
                cancellation: cancellation,
                caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleTerraformDelete(
        _ message: xpc_object_t,
        on peer: xpc_connection_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller
    ) {
        guard let hostnamePointer = xpc_dictionary_get_string(message, "terraform_hostname") else {
            reply(peer, to: message, ok: false, error: "invalid Terraform credential forget request")
            return
        }
        let hostname = String(cString: hostnamePointer)
        guard normalizeTerraformHostname(hostname) == hostname else {
            reply(peer, to: message, ok: false, error: "invalid Terraform hostname")
            return
        }
        do {
            let parent = try terraformCredentialParent(for: caller.identity)
            handleMutation(
                .terraformDelete(
                    account: terraformCredentialSecretName(hostname),
                    hostname: hostname
                ),
                on: peer,
                message: message,
                cancellation: cancellation,
                caller: caller,
                requiredCredentialParent: parent
            )
        } catch {
            reply(peer, to: message, ok: false, error: error.localizedDescription)
        }
    }

    private func handleMutation(
        _ mutation: SecretMutation,
        on peer: xpc_connection_t,
        message: xpc_object_t,
        cancellation: ApprovalCancellation,
        caller: MutationCaller,
        requiredCredentialParent: CredentialHelperParent? = nil
    ) {
        guard let cwdPointer = xpc_dictionary_get_string(message, "cwd") else {
            reply(peer, to: message, ok: false, error: "secret mutation is missing its working directory")
            return
        }
        let cwd = String(cString: cwdPointer)
        let launcher = requiredCredentialParent.flatMap { parent in
            var identity = AVProcessIdentity()
            guard av_process_identity(parent.pid, &identity) else { return nil }
            return launcherIdentity(pid: parent.pid, identity: identity)
        } ?? launcherIdentities(for: caller.identity).first
        let launcherFallbackPath = launcherFallbackPath(for: caller.identity) ?? caller.path
        let request = mutation.approvalRequest(callerPath: caller.path, requestCWD: cwd)
        let requestOverride = requiredCredentialParent.map { parent in
            let tool = credentialHelperTool(parent)
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
                tool: tool,
                title: request.title,
                detail: request.detail,
                credentialScope: request.credentialScope,
                credentialParent: parent,
                selectedSecretValues: request.selectedSecretValues
            )
        } ?? request
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
                preflight: requiredCredentialParent.map { parent in
                    {
                        self.credentialHelperParentValid(parent, tool: self.credentialHelperTool(parent))
                            ? nil
                            : "Credential-helper Target changed before the approved mutation"
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
                 .dockerSave(let account, _, _, _),
                 .goatSave(let account, _, _),
                 .ordercliSave(let account, _, _),
                 .openhueSave(let account, _, _),
                 .plumberSave(let account, _, _),
                 .uaaSave(let account, _, _),
                 .railwaySave(let account, _, _),
                 .oxideSave(let account, _, _),
                 .terraformSave(let account, _, _):
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
            case .delete(let account), .dockerDelete(let account, _),
                 .goatDelete(let account, _),
                 .ordercliDelete(let account, _),
                 .uaaDelete(let account, _),
                 .railwayDelete(let account, _),
                 .oxideDelete(let account, _), .terraformDelete(let account, _):
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
        let names = request.keys.filter {
            request.replaceExistingEnv || !conflicts.contains($0)
        }
        return try secretValueCustody.load(
            request.selectedSecretValues,
            names: names,
            allowMissing: request.allowMissingKeys
        )
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
            credentialScope: serverURL,
            credentialParent: parent
        )
    }

    private func dockerCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
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
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func dockerCredentialParentValid(_ parent: CredentialHelperParent) -> Bool {
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

    private func goatCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "goat-get" else { return request }
        guard request.tool == "goat",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty, request.args.isEmpty, request.keys.count == 1,
              !request.replaceExistingEnv, !request.allowMissingKeys,
              request.envConflicts.isEmpty, request.shebangScript == nil, request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "goat_scope"),
              let scope = parseGoatCredentialScope(String(cString: scopePointer)),
              request.keys == [scope.secretName]
        else { throw AppError("invalid goat credential request") }
        let parent = try goatCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op, keys: request.keys, target: parent.target,
            args: Array(parent.arguments.dropFirst()), cwd: request.cwd,
            replaceExistingEnv: false, allowMissingKeys: false, envConflicts: [],
            shebangScript: nil, scriptData: nil, tool: "goat",
            title: "Use goat auth session for \(scope.did)?",
            detail: "The verified goat Target will receive the password and session tokens for \(scope.pds).",
            credentialScope: scope.canonical, credentialParent: parent
        )
    }

    private func goatCredentialParent(for helperIdentity: AVProcessIdentity) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID), !arguments.isEmpty
        else { throw AppError("goat credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard goatTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible goat Target")
        }
        return CredentialHelperParent(
            pid: parentPID, startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid, target: target, arguments: arguments
        )
    }

    private func ordercliCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "ordercli-get" else { return request }
        guard request.tool == "ordercli",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty, request.args.isEmpty,
              request.keys == [ordercliCredentialSecretName],
              !request.replaceExistingEnv, !request.allowMissingKeys,
              request.envConflicts.isEmpty, request.shebangScript == nil, request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "ordercli_scope"),
              let scope = parseOrdercliCredentialScope(String(cString: scopePointer))
        else { throw AppError("invalid ordercli credential request") }
        let parent = try ordercliCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op, keys: request.keys, target: parent.target,
            args: Array(parent.arguments.dropFirst()), cwd: request.cwd,
            replaceExistingEnv: false, allowMissingKeys: false, envConflicts: [],
            shebangScript: nil, scriptData: nil, tool: "ordercli",
            title: "Use ordercli Foodora session?",
            detail: "The verified ordercli Target will receive its reusable Foodora session bundle.",
            credentialScope: scope.canonical, credentialParent: parent
        )
    }

    private func ordercliCredentialParent(for helperIdentity: AVProcessIdentity) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID), !arguments.isEmpty
        else { throw AppError("ordercli credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard ordercliTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible ordercli Target")
        }
        return CredentialHelperParent(
            pid: parentPID, startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid, target: target, arguments: arguments
        )
    }

    private func openhueCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "openhue-get" else { return request }
        guard request.tool == "openhue-cli",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty, request.args.isEmpty,
              request.keys == [openhueCredentialSecretName],
              !request.replaceExistingEnv, !request.allowMissingKeys,
              request.envConflicts.isEmpty, request.shebangScript == nil, request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "openhue_scope"),
              let scope = parseOpenHueCredentialScope(String(cString: scopePointer))
        else { throw AppError("invalid OpenHue credential request") }
        let parent = try openhueCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op, keys: request.keys, target: parent.target,
            args: Array(parent.arguments.dropFirst()), cwd: request.cwd,
            replaceExistingEnv: false, allowMissingKeys: false, envConflicts: [],
            shebangScript: nil, scriptData: nil, tool: "openhue-cli",
            title: "Use Hue application key?",
            detail: "The verified OpenHue Target will authenticate to bridge \(scope.bridge).",
            credentialScope: scope.canonical, credentialParent: parent
        )
    }

    private func openhueCredentialParent(for helperIdentity: AVProcessIdentity) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID), !arguments.isEmpty
        else { throw AppError("OpenHue credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard openhueTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible OpenHue Target")
        }
        return CredentialHelperParent(
            pid: parentPID, startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid, target: target, arguments: arguments
        )
    }

    private func plumberCredentialRequest(
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "plumber-get" else { return request }
        guard request.tool == "plumber",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty, request.args.isEmpty,
              request.keys == [plumberCredentialSecretName],
              !request.replaceExistingEnv, !request.allowMissingKeys,
              request.envConflicts.isEmpty, request.shebangScript == nil, request.scriptData == nil,
              let scope = parsePlumberCredentialScope(plumberCredentialScope)
        else { throw AppError("invalid Plumber config request") }
        let parent = try plumberCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op, keys: request.keys, target: parent.target,
            args: Array(parent.arguments.dropFirst()), cwd: request.cwd,
            replaceExistingEnv: false, allowMissingKeys: false, envConflicts: [],
            shebangScript: nil, scriptData: nil, tool: "plumber",
            title: "Use Plumber local config?",
            detail: "The verified Plumber Target will receive its local config in memory.",
            credentialScope: scope.canonical, credentialParent: parent
        )
    }

    private func plumberCredentialParent(for helperIdentity: AVProcessIdentity) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID), !arguments.isEmpty
        else { throw AppError("Plumber config helper has no live parent") }
        let target = pathString(parentIdentity)
        guard plumberTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible Plumber Target")
        }
        return CredentialHelperParent(
            pid: parentPID, startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid, target: target, arguments: arguments
        )
    }

    private func uaaCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "uaa-get" else { return request }
        guard request.tool == "uaa-cli",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty, request.args.isEmpty,
              request.keys == [uaaCredentialSecretName],
              !request.replaceExistingEnv, !request.allowMissingKeys,
              request.envConflicts.isEmpty, request.shebangScript == nil, request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "uaa_scope"),
              let scope = parseUAACredentialScope(String(cString: scopePointer))
        else { throw AppError("invalid UAA credential request") }
        let parent = try uaaCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op, keys: request.keys, target: parent.target,
            args: Array(parent.arguments.dropFirst()), cwd: request.cwd,
            replaceExistingEnv: false, allowMissingKeys: false, envConflicts: [],
            shebangScript: nil, scriptData: nil, tool: "uaa-cli",
            title: "Use UAA OAuth contexts?",
            detail: "The verified UAA CLI Target will receive its stored OAuth tokens.",
            credentialScope: scope.canonical, credentialParent: parent
        )
    }

    private func uaaCredentialParent(for helperIdentity: AVProcessIdentity) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID), !arguments.isEmpty
        else { throw AppError("UAA credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard uaaTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible UAA CLI Target")
        }
        return CredentialHelperParent(
            pid: parentPID, startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid, target: target, arguments: arguments
        )
    }

    private func railwayCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "railway-get" else { return request }
        guard request.tool == "railway",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty, request.args.isEmpty, request.keys.count == 1,
              !request.replaceExistingEnv, !request.allowMissingKeys,
              request.envConflicts.isEmpty, request.shebangScript == nil, request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "railway_scope"),
              let scope = parseRailwayCredentialScope(String(cString: scopePointer)),
              request.keys == [scope.secretName]
        else { throw AppError("invalid Railway credential request") }
        let parent = try railwayCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op, keys: request.keys, target: parent.target,
            args: Array(parent.arguments.dropFirst()), cwd: request.cwd,
            replaceExistingEnv: false, allowMissingKeys: false, envConflicts: [],
            shebangScript: nil, scriptData: nil, tool: "railway",
            title: "Use Railway credential for \(scope.environment)?",
            detail: "The verified Railway Target will receive its reusable credential for \(scope.host).",
            credentialScope: scope.canonical, credentialParent: parent
        )
    }

    private func railwayCredentialParent(for helperIdentity: AVProcessIdentity) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1, av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID), !arguments.isEmpty
        else { throw AppError("Railway credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard railwayTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible Railway Target")
        }
        return CredentialHelperParent(
            pid: parentPID, startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid, target: target, arguments: arguments
        )
    }

    private func oxideCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "oxide-get" else { return request }
        guard request.tool == "oxide-cli",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys.count == 1,
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "oxide_scope"),
              let scope = parseOxideCredentialScope(String(cString: scopePointer)),
              request.keys == [scope.secretName]
        else { throw AppError("invalid Oxide credential request") }
        let parent = try oxideCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op,
            keys: request.keys,
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: request.cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "oxide-cli",
            title: "Use Oxide credential for profile \(scope.profile)?",
            detail: "The verified Oxide Target will receive this profile token in plaintext for \(scope.host).",
            credentialScope: scope.canonical,
            credentialParent: parent
        )
    }

    private func oxideCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("Oxide credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard oxideTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible Oxide Target")
        }
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func terraformCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "terraform-get" else { return request }
        guard request.tool == "terraform",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys.count == 1,
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil,
              let hostnamePointer = xpc_dictionary_get_string(message, "terraform_hostname")
        else { throw AppError("invalid Terraform credential request") }
        let hostname = String(cString: hostnamePointer)
        guard normalizeTerraformHostname(hostname) == hostname,
              request.keys == [terraformCredentialSecretName(hostname)]
        else { throw AppError("Terraform host Secret Name does not match its hostname") }
        let parent = try terraformCredentialParent(for: helperIdentity)
        let tool = credentialHelperTool(parent)
        return ApprovalRequest(
            op: request.op,
            keys: request.keys,
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: request.cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: tool,
            title: "Use \(tool == "opentofu" ? "OpenTofu" : "Terraform") credential for \(hostname)?",
            detail: "The verified \(tool == "opentofu" ? "OpenTofu" : "Terraform") Target will receive the API token in plaintext, as required by the credential-helper protocol.",
            credentialScope: hostname,
            credentialParent: parent
        )
    }

    private func wakatimeCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "wakatime-get" else { return request }
        guard request.tool == "wakatime-cli",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys == [wakatimeCredentialSecretName],
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil,
              let urlPointer = xpc_dictionary_get_string(message, "wakatime_api_url"),
              String(cString: urlPointer) == wakatimeOfficialAPIURL
        else { throw AppError("invalid WakaTime credential request") }
        let parent = try wakatimeCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op,
            keys: request.keys,
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: request.cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "wakatime-cli",
            title: "Use the WakaTime API key?",
            detail: "The verified WakaTime Target will receive the global API key for WakaTime's official API endpoint.",
            credentialScope: wakatimeOfficialAPIURL,
            credentialParent: parent
        )
    }

    private func wakatimeCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("WakaTime credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard wakatimeTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible WakaTime Target")
        }
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func rclonePasswordRequest(
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "rclone-get" else { return request }
        guard request.tool == "rclone",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys == [rcloneConfigPasswordSecretName],
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil
        else { throw AppError("invalid rclone password request") }
        let parent = try rcloneCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op,
            keys: request.keys,
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: "/",
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "rclone",
            title: "Unlock the rclone configuration?",
            detail: "The verified rclone Target will receive one wrapping password that unlocks every configured remote for this process.",
            credentialScope: rcloneAllRemotesScope,
            credentialParent: parent
        )
    }

    private func rcloneCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("rclone password helper has no live parent") }
        let target = pathString(parentIdentity)
        guard rcloneTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible rclone Target")
        }
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func kubectlCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "kubectl-get" else { return request }
        guard request.tool == "kubectl",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys.count == 1,
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil,
              let scopePointer = xpc_dictionary_get_string(message, "kubectl_scope"),
              let scope = parseKubectlCredentialScope(String(cString: scopePointer)),
              request.keys == [scope.secretName]
        else { throw AppError("invalid kubectl credential request") }
        let parent = try kubectlCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op,
            keys: request.keys,
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: "/",
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "kubectl",
            title: "Use Kubernetes credential for \(scope.user)?",
            detail: "The verified kubectl Target will receive this credential for \(scope.server).",
            credentialScope: scope.canonical,
            credentialParent: parent
        )
    }

    private func kubectlCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("kubectl credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard kubectlTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible kubectl Target")
        }
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func terraformCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("Terraform credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard terraformTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible Terraform or OpenTofu Target")
        }
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func aliyunCredentialRequest(
        from message: xpc_object_t,
        request: ApprovalRequest,
        helperIdentity: AVProcessIdentity,
        helperPath: String,
        helperSigning: SigningInfo
    ) throws -> ApprovalRequest {
        guard request.op == "aliyun-get" else { return request }
        guard request.tool == "aliyun-cli",
              isTrustedAvCaller(path: helperPath, signing: helperSigning),
              request.target.isEmpty,
              request.args.isEmpty,
              request.keys.count == 1,
              !request.replaceExistingEnv,
              !request.allowMissingKeys,
              request.envConflicts.isEmpty,
              request.shebangScript == nil,
              request.scriptData == nil,
              let profilePointer = xpc_dictionary_get_string(message, "aliyun_profile")
        else { throw AppError("invalid Alibaba Cloud credential request") }
        let profile = String(cString: profilePointer)
        guard normalizeAliyunProfile(profile) == profile,
              request.keys == [aliyunCredentialSecretName(profile)]
        else { throw AppError("Alibaba Cloud Secret Name does not match its profile") }
        let parent = try aliyunCredentialParent(for: helperIdentity)
        return ApprovalRequest(
            op: request.op,
            keys: request.keys,
            target: parent.target,
            args: Array(parent.arguments.dropFirst()),
            cwd: request.cwd,
            replaceExistingEnv: false,
            allowMissingKeys: false,
            envConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            tool: "aliyun-cli",
            title: "Use Alibaba Cloud credential for profile \(profile)?",
            detail: "The verified Alibaba Cloud CLI Target will receive the credential in plaintext, as required by the External credential-provider protocol.",
            credentialScope: profile,
            credentialParent: parent
        )
    }

    private func aliyunCredentialParent(
        for helperIdentity: AVProcessIdentity
    ) throws -> CredentialHelperParent {
        let parentPID = helperIdentity.ppid
        var parentIdentity = AVProcessIdentity()
        guard parentPID > 1,
              av_process_identity(parentPID, &parentIdentity),
              parentIdentity.euid == helperIdentity.euid,
              let arguments = processArguments(parentPID),
              !arguments.isEmpty
        else { throw AppError("Alibaba Cloud credential helper has no live parent") }
        let target = pathString(parentIdentity)
        guard aliyunTargetIdentityValid(pid: parentPID, path: target) else {
            throw AppError("credential helper parent is not an eligible Alibaba Cloud CLI Target")
        }
        return CredentialHelperParent(
            pid: parentPID,
            startUsec: parentIdentity.start_usec,
            euid: parentIdentity.euid,
            target: target,
            arguments: arguments
        )
    }

    private func credentialHelperTool(_ parent: CredentialHelperParent) -> String {
        switch URL(fileURLWithPath: parent.target).lastPathComponent {
        case "aliyun": "aliyun-cli"
        case "docker": "docker"
        case "goat": "goat"
        case "openhue": "openhue-cli"
        case "ordercli": "ordercli"
        case "oxide": "oxide-cli"
        case "plumber": "plumber"
        case "railway": "railway"
        case "rclone": "rclone"
        case "kubectl": "kubectl"
        case "tofu": "opentofu"
        case "terraform": "terraform"
        case "uaa": "uaa-cli"
        case "wakatime-cli": "wakatime-cli"
        default: ""
        }
    }

    private func credentialHelperParentValid(
        _ parent: CredentialHelperParent,
        tool: String
    ) -> Bool {
        var identity = AVProcessIdentity()
        guard av_process_identity(parent.pid, &identity),
              identity.start_usec == parent.startUsec,
              identity.euid == parent.euid,
              pathString(identity) == parent.target,
              processArguments(parent.pid) == parent.arguments
        else { return false }
        switch tool {
        case "aliyun-cli":
            return credentialHelperTool(parent) == tool
                && aliyunTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "docker": return dockerTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "goat":
            return credentialHelperTool(parent) == tool
                && goatTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "ordercli":
            return credentialHelperTool(parent) == tool
                && ordercliTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "openhue-cli":
            return credentialHelperTool(parent) == tool
                && openhueTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "plumber":
            return credentialHelperTool(parent) == tool
                && plumberTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "uaa-cli":
            return credentialHelperTool(parent) == tool
                && uaaTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "railway":
            return credentialHelperTool(parent) == tool
                && railwayTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "oxide-cli":
            return credentialHelperTool(parent) == tool
                && oxideTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "terraform", "opentofu":
            return credentialHelperTool(parent) == tool
                && terraformTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "wakatime-cli":
            return credentialHelperTool(parent) == tool
                && wakatimeTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "rclone":
            return credentialHelperTool(parent) == tool
                && rcloneTargetIdentityValid(pid: parent.pid, path: parent.target)
        case "kubectl":
            return credentialHelperTool(parent) == tool
                && kubectlTargetIdentityValid(pid: parent.pid, path: parent.target)
        default: return false
        }
    }

    private func goatTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("goat", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "goat"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func aliyunTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("aliyun-cli", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "aliyun"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func ordercliTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("ordercli", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "ordercli"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func openhueTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("openhue-cli", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "openhue"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func uaaTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("uaa-cli", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "uaa"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func plumberTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("plumber", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "plumber"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func railwayTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("railway", matches: path),
              let signing = liveSigningInfo(pid: pid), signing.mainExecutable == path
        else { return false }
        return signing.identifier == "railway"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func oxideTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("oxide-cli", matches: path),
              let signing = liveSigningInfo(pid: pid),
              signing.mainExecutable == path
        else { return false }
        return signing.identifier == "oxide"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection == .hardened
            && liveProcessHasNoEntitlements(pid: pid)
    }

    private func terraformTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        let expected: (identifier: String, team: String)? = if configuredSecretGateTarget(
            "terraform", matches: path
        ) {
            ("terraform", "D38WU7D763")
        } else if configuredSecretGateTarget("opentofu", matches: path) {
            ("tofu", "ZU76A67LGU")
        } else {
            nil
        }
        guard let expected,
              let signing = liveSigningInfo(pid: pid),
              signing.mainExecutable == path
        else { return false }
        return signing.identifier == expected.identifier
            && signing.teamIdentifier == expected.team
            && signing.isDeveloperID
            && signing.runtimeProtection.allowsSecretGateAccess
    }

    private func wakatimeTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("wakatime-cli", matches: path),
              let signing = liveSigningInfo(pid: pid),
              signing.mainExecutable == path
        else { return false }
        return signing.identifier == "wakatime-cli"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection == .hardened
            && liveProcessHasNoEntitlements(pid: pid)
    }

    private func rcloneTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("rclone", matches: path),
              let signing = liveSigningInfo(pid: pid),
              signing.mainExecutable == path
        else { return false }
        return signing.identifier == "rclone"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection == .hardened
            && liveProcessHasNoEntitlements(pid: pid)
    }

    private func kubectlTargetIdentityValid(pid: pid_t, path: String) -> Bool {
        guard configuredSecretGateTarget("kubectl", matches: path),
              let signing = liveSigningInfo(pid: pid),
              signing.mainExecutable == path
        else { return false }
        return signing.identifier == "kubectl"
            && signing.teamIdentifier == "ZU76A67LGU"
            && signing.isDeveloperID
            && signing.runtimeProtection == .hardened
            && liveProcessHasNoEntitlements(pid: pid)
    }

    private func configuredSecretGateTarget(_ gateID: String, matches path: String) -> Bool {
        secretGateDescriptors.first(where: { $0.id == gateID })?.routes.contains {
            normalizedExecutablePath($0.targetPath) == normalizedExecutablePath(path)
        } == true
    }

    private func prepareApprovedFulfillment(
        for request: ApprovalRequest,
        awsRegistration: AWSRegistrationCandidate?
    ) throws -> AuthorizationFulfillmentTransaction<ApprovedFulfillmentMaterial> {
        let credentialParent: CredentialHelperParent?
        if ["docker-get", "goat-get", "ordercli-get", "openhue-get", "plumber-get", "uaa-get", "railway-get", "oxide-get", "terraform-get", "aliyun-get", "wakatime-get", "rclone-get", "kubectl-get"]
            .contains(request.op)
        {
            guard let scope = request.credentialScope,
                  let parent = request.credentialParent,
                  let tool = request.tool,
                  credentialHelperParentValid(parent, tool: tool),
                  parent.target == request.target,
                  Array(parent.arguments.dropFirst()) == request.args
            else { throw AppError("invalid credential-helper request") }
            let expected: String
            switch request.op {
            case "aliyun-get": expected = aliyunCredentialSecretName(scope)
            case "docker-get": expected = dockerCredentialSecretName(scope)
            case "goat-get":
                guard let goat = parseGoatCredentialScope(scope) else {
                    throw AppError("goat credential scope changed before Secret Application")
                }
                expected = goat.secretName
            case "ordercli-get": expected = ordercliCredentialSecretName
            case "openhue-get": expected = openhueCredentialSecretName
            case "plumber-get": expected = plumberCredentialSecretName
            case "uaa-get": expected = uaaCredentialSecretName
            case "railway-get":
                guard let railway = parseRailwayCredentialScope(scope) else {
                    throw AppError("Railway credential scope changed before Secret Application")
                }
                expected = railway.secretName
            case "oxide-get":
                guard let oxide = parseOxideCredentialScope(scope) else {
                    throw AppError("Oxide credential scope changed before Secret Application")
                }
                expected = oxide.secretName
            case "wakatime-get":
                guard scope == wakatimeOfficialAPIURL else {
                    throw AppError("WakaTime API endpoint changed before Secret Application")
                }
                expected = wakatimeCredentialSecretName
            case "rclone-get":
                guard scope == rcloneAllRemotesScope else {
                    throw AppError("rclone credential scope changed before Secret Application")
                }
                expected = rcloneConfigPasswordSecretName
            case "kubectl-get":
                guard let kubectl = parseKubectlCredentialScope(scope) else {
                    throw AppError("kubectl credential scope changed before Secret Application")
                }
                expected = kubectl.secretName
            default: expected = terraformCredentialSecretName(scope)
            }
            guard request.keys == [expected] else {
                throw AppError("credential-helper Secret Name changed before Secret Application")
            }
            credentialParent = parent
        } else {
            credentialParent = nil
        }
        let secrets = try approvedSecrets(for: request)
        if let credentialParent,
           let scope = request.credentialScope,
           let tool = request.tool
        {
            guard credentialHelperParentValid(credentialParent, tool: tool) else {
                throw AppError("credential-helper Target changed before Secret Application")
            }
            if request.op == "docker-get" {
                guard let value = secrets[dockerCredentialSecretName(scope)],
                      let credential = parseDockerCredential(value),
                      credential.serverURL == scope
                else { throw AppError("Docker credential changed before Secret Application") }
            } else if request.op == "goat-get" {
                guard let scope = parseGoatCredentialScope(scope),
                      let value = secrets[scope.secretName], parseGoatCredential(value) != nil
                else { throw AppError("goat credential changed before Secret Application") }
            } else if request.op == "ordercli-get" {
                guard parseOrdercliCredentialScope(scope) != nil,
                      let value = secrets[ordercliCredentialSecretName],
                      parseOrdercliCredential(value) != nil
                else { throw AppError("ordercli credential changed before Secret Application") }
            } else if request.op == "openhue-get" {
                guard parseOpenHueCredentialScope(scope) != nil,
                      let value = secrets[openhueCredentialSecretName],
                      parseOpenHueCredential(value) != nil
                else { throw AppError("OpenHue credential changed before Secret Application") }
            } else if request.op == "plumber-get" {
                guard parsePlumberCredentialScope(scope) != nil,
                      let value = secrets[plumberCredentialSecretName],
                      parsePlumberCredential(value) != nil
                else { throw AppError("Plumber config changed before Secret Application") }
            } else if request.op == "uaa-get" {
                guard parseUAACredentialScope(scope) != nil,
                      let value = secrets[uaaCredentialSecretName],
                      parseUAACredential(value) != nil
                else { throw AppError("UAA credential changed before Secret Application") }
            } else if request.op == "railway-get" {
                guard let scope = parseRailwayCredentialScope(scope),
                      let value = secrets[scope.secretName], parseRailwayCredential(value) != nil
                else { throw AppError("Railway credential changed before Secret Application") }
            } else if request.op == "oxide-get" {
                guard let scope = parseOxideCredentialScope(scope),
                      let value = secrets[scope.secretName],
                      parseOxideCredential(value) != nil
                else { throw AppError("Oxide credential changed before Secret Application") }
            } else if request.op == "aliyun-get" {
                guard let value = secrets[aliyunCredentialSecretName(scope)],
                      parseAliyunCredential(value)
                else { throw AppError("Alibaba Cloud credential changed before Secret Application") }
            } else if request.op == "wakatime-get" {
                guard scope == wakatimeOfficialAPIURL,
                      let value = secrets[wakatimeCredentialSecretName],
                      validWakaTimeAPIKey(value)
                else { throw AppError("WakaTime credential changed before Secret Application") }
            } else if request.op == "rclone-get" {
                guard scope == rcloneAllRemotesScope,
                      let value = secrets[rcloneConfigPasswordSecretName],
                      validRcloneConfigPassword(value)
                else { throw AppError("rclone config password changed before Secret Application") }
            } else if request.op == "kubectl-get" {
                guard let scope = parseKubectlCredentialScope(scope),
                      let value = secrets[scope.secretName],
                      validKubectlCredential(value, kind: scope.kind)
                else { throw AppError("kubectl credential changed before Secret Application") }
            } else {
                guard let value = secrets[terraformCredentialSecretName(scope)],
                      parseTerraformCredential(value) != nil
                else { throw AppError("Terraform credential changed before Secret Application") }
            }
        }
        guard let awsRegistration else {
            return AuthorizationFulfillmentTransaction(material: ApprovedFulfillmentMaterial(
                payload: ApprovedPayload(secrets: secrets, value: nil),
                awsRegistration: nil
            ))
        }
        let registration = AWSRegistration(
            generation: awsRegistration.generation,
            chain: awsRegistration.chain,
            args: awsRegistration.args,
            target: awsRegistration.target,
            interpreter: awsRegistration.interpreter,
            useLongLivedCredentials: awsRegistration.useLongLivedCredentials,
            secretValues: request.selectedSecretValues,
            credentials: nil
        )
        let section = awsRegistration.chain.selected.name == "default"
            ? "default"
            : "profile \(awsRegistration.chain.selected.name)"
        let config = """
        [\(section)]
        credential_process = /usr/local/bin/av aws-credentials\(awsRegistration.generation == .officialV2 ? " official-v2" : "")
        region = \(awsRegistration.chain.region)

        """
        return AuthorizationFulfillmentTransaction(material: ApprovedFulfillmentMaterial(
            payload: ApprovedPayload(secrets: [:], value: config),
            awsRegistration: registration
        ))
    }

    private func fulfillApprovedRequest(
        request: ApprovalRequest,
        awsRegistration: AWSRegistrationCandidate?,
        pid: pid_t,
        identity: AVProcessIdentity,
        record: AccessRequestRecord,
        launcher: LauncherIdentity?,
        activateAfterRecording: () -> Void = {},
        release: (ApprovedPayload) -> Void
    ) throws -> Bool {
        let transaction = try prepareApprovedFulfillment(
            for: request,
            awsRegistration: awsRegistration
        )
        return transaction.commit(
            record: { onAccessRequest(record) },
            activate: { material in
                if let registration = material.awsRegistration {
                    installAWSRegistration(registration, pid: pid, identity: identity)
                }
                activateAfterRecording()
            },
            observe: { material in
                recordLiveSecretUse(
                    request: request,
                    payload: material.payload,
                    launcher: launcher,
                    pid: pid,
                    identity: identity
                )
            },
            release: { material in release(material.payload) }
        )
    }

    private func installAWSRegistration(
        _ registration: AWSRegistration,
        pid: pid_t,
        identity: AVProcessIdentity
    ) {
        let key = BlessedExecutionKey(pid: pid, startUsec: identity.start_usec)
        awsRegistrationsLock.lock()
        defer { awsRegistrationsLock.unlock() }
        awsRegistrations = awsRegistrations.filter { key, _ in
            var current = AVProcessIdentity()
            return av_process_identity(key.pid, &current) && current.start_usec == key.startUsec
        }
        awsRegistrations[key] = registration
    }

    private func recordLiveSecretUse(
        request: ApprovalRequest,
        payload: ApprovedPayload,
        launcher: LauncherIdentity?,
        pid: pid_t,
        identity: AVProcessIdentity
    ) {
        var secretNames = Set(payload.secrets.keys)
        if request.tool == "aws", payload.value != nil {
            secretNames.formUnion(request.selectedSecretValues.names)
        }
        guard !secretNames.isEmpty else { return }

        let process: LiveSecretUseProcess?
        if let parent = request.credentialParent,
           let tool = request.tool,
           credentialHelperParentValid(parent, tool: tool)
        {
            var parentIdentity = AVProcessIdentity()
            process = av_process_identity(parent.pid, &parentIdentity)
                ? liveSecretUseProcess(pid: parent.pid, identity: parentIdentity)
                : nil
        } else {
            process = liveSecretUseProcess(pid: pid, identity: identity)
        }
        guard let process else { return }

        let launcherName = launcher.map {
            approvalPromptRequester(launcher: $0, fallback: $0.path).name
        }
        liveSecretUses.record(
            process: process,
            launcherDesignatedRequirement: launcher?.designatedRequirement,
            launcherName: launcherName,
            targetPath: request.target,
            processID: process.pid,
            secretNames: secretNames
        )
        Task { @MainActor in self.onLiveSecretUsesChanged() }
    }

    private func recordLiveSecretUse(
        request: ApprovalRequest,
        secretNames: Set<String>,
        launcher: LauncherIdentity,
        execution: RetainedProcessExecution
    ) {
        let process = LiveSecretUseProcess(
            pid: execution.pid,
            startUsec: execution.startUsec,
            effectiveUserID: execution.effectiveUserID,
            auditSessionID: execution.auditSessionID
        )
        guard liveSecretUseProcessIsLive(process) else { return }
        liveSecretUses.record(
            process: process,
            launcherDesignatedRequirement: launcher.designatedRequirement,
            launcherName: approvalPromptRequester(launcher: launcher, fallback: launcher.path).name,
            targetPath: request.target,
            processID: process.pid,
            secretNames: secretNames
        )
        Task { @MainActor in self.onLiveSecretUsesChanged() }
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
        let selectedKeys: [String: String]
        do {
            selectedKeys = try secretValueCustody.load(
                registration.secretValues,
                names: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
            )
        } catch {
            throw AppError("selected AWS access keys are unavailable: \(error.localizedDescription)")
        }
        guard let accessKey = selectedKeys["AWS_ACCESS_KEY_ID"],
              let secretKey = selectedKeys["AWS_SECRET_ACCESS_KEY"]
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
        guard canRequestMacInput() else { throw AppError("AWS MFA unavailable while the user session is inactive") }
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
        guard op == "inject" || op == "keys" || op == "authorize" || op == "gpg-sign"
            || op == "docker-get" || op == "goat-get" || op == "ordercli-get" || op == "openhue-get" || op == "plumber-get" || op == "uaa-get" || op == "railway-get"
            || op == "oxide-get" || op == "terraform-get" || op == "aliyun-get" || op == "wakatime-get"
            || op == "rclone-get" || op == "kubectl-get"
            || op == "proxy-start"
        else { return nil }
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
        protocolVersion: UInt64? = nil,
        proxySession: ProxySessionMaterial? = nil,
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
        if let protocolVersion {
            xpc_dictionary_set_uint64(response, "protocol_version", protocolVersion)
        }
        if let proxySession {
            proxySession.proxyURL.withCString {
                xpc_dictionary_set_string(response, "proxy_url", $0)
            }
            proxySession.caCertificatePath.withCString {
                xpc_dictionary_set_string(response, "ca_certificate_path", $0)
            }
            proxySession.sessionID.uuidString.lowercased().withCString {
                xpc_dictionary_set_string(response, "session_id", $0)
            }
            let values = xpc_dictionary_create_empty()
            for (key, value) in proxySession.references {
                key.withCString { keyPointer in
                    value.withCString { valuePointer in
                        xpc_dictionary_set_string(values, keyPointer, valuePointer)
                    }
                }
            }
            xpc_dictionary_set_value(response, "references", values)
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

private func supportsVarlockProtocol(_ version: UInt64) -> Bool {
    version == varlockProtocolVersion
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
    if isTrustedVarlockPluginHelperCaller(path: path, signing: signing) {
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

private func isTrustedVarlockPluginHelperCaller(path: String, signing: SigningInfo) -> Bool {
    URL(fileURLWithPath: path).lastPathComponent == "AutomicVaultVarlockPlugin"
        && signing.identifier == "com.automicvault.varlock-plugin-helper"
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
    case "gpg-signing":
        return .localWrite
    case "gh":
        return ghRequestClassification(request.args)
    case "docker":
        return dockerRequestClassification(request.args)
    case "goat":
        return goatRequestClassification(request.args)
    case "ordercli":
        return ordercliRequestClassification(request.args)
    case "openhue-cli":
        return openhueRequestClassification(request.args)
    case "plumber":
        return plumberRequestClassification(request.args)
    case "uaa-cli":
        return uaaRequestClassification(request.args)
    case "railway":
        return railwayRequestClassification(request.args)
    case "oxide-cli":
        return oxideRequestClassification(request.args)
    case "terraform", "opentofu":
        return terraformRequestClassification(request.args)
    case "aliyun-cli":
        return aliyunRequestClassification(request.args)
    case "wakatime-cli":
        return wakatimeRequestClassification(request.args)
    case "rclone":
        return .unknown
    case "kubectl":
        return .unknown
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

private func wakatimeRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    if words.contains(where: {
        $0 == "--entity" || $0.hasPrefix("--entity=") || $0 == "--extra-heartbeats"
            || $0 == "--sync-offline-activity" || $0.hasPrefix("--sync-offline-activity=")
            || $0 == "--sync-ai-activity" || $0 == "--sync-ai-heartbeats"
    }) {
        return .mutating
    }
    if words.contains(where: {
        $0 == "--today" || $0 == "--file-experts" || $0 == "--today-goal"
            || $0.hasPrefix("--today-goal=")
    }) {
        return .readOnly
    }
    return .unknown
}

private func goatRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    if ["--version", "-v", "help"].contains(command) { return .readOnly }
    if command == "account" {
        guard let action = words.dropFirst().first else { return .unknown }
        if ["check-auth", "missing-blobs", "status"].contains(action) { return .readOnly }
        return ["login", "logout", "activate", "deactivate", "update-handle", "create"]
            .contains(action) ? .mutating : .unknown
    }
    if command == "record" {
        guard let action = words.dropFirst().first else { return .unknown }
        if ["get", "list"].contains(action) { return .readOnly }
        return ["create", "delete", "update"].contains(action) ? .mutating : .unknown
    }
    if ["resolve", "firehose"].contains(command) { return .readOnly }
    return .unknown
}

private func railwayRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    if ["--version", "-v", "version", "help", "completion", "docs", "list", "status", "whoami",
        "logs", "metrics", "usage", "open"].contains(command)
    {
        return .readOnly
    }
    if ["run", "local", "shell"].contains(command) { return .secretDump }
    if ["variable", "variables", "vars", "var"].contains(command) {
        guard let action = words.dropFirst().first else { return .secretDump }
        if ["list", "ls"].contains(action) { return .secretDump }
        return ["set", "delete", "rm", "remove"].contains(action) ? .mutating : .unknown
    }
    if ["up", "down", "deploy", "redeploy", "restart", "delete", "init", "link", "unlink",
        "login", "logout", "environment", "service", "variable", "domain", "volume", "tcp-proxy",
        "private-network", "outbound-network", "scale", "ssh", "connect"].contains(command)
    {
        return .mutating
    }
    return .unknown
}

private func ordercliRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    guard let provider = words.first else { return .unknown }
    if ["help", "completion", "--help", "-h", "--version", "-v", "version"].contains(provider) {
        return .readOnly
    }
    guard ["foodora", "deliveroo"].contains(provider), let command = words.dropFirst().first
    else { return .unknown }
    if ["history", "orders", "order", "countries"].contains(command) { return .readOnly }
    if command == "config" {
        guard let action = words.dropFirst(2).first else { return .unknown }
        if action == "show" { return .readOnly }
        return action == "set" ? .localWrite : .unknown
    }
    if provider == "foodora",
       ["login", "logout", "session", "cookies", "reorder"].contains(command)
    {
        return .mutating
    }
    return .unknown
}

private func openhueRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    if ["--version", "--help", "-h", "version", "help", "completion", "discover", "get"].contains(command) {
        return .readOnly
    }
    if command == "config" { return .localWrite }
    if ["setup", "set", "mcp"].contains(command) { return .mutating }
    return .unknown
}

private func plumberRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    if ["--version", "help", "--help", "-h"].contains(command) { return .readOnly }
    if ["read", "write", "relay", "tunnel", "server", "manage"].contains(command) {
        return .mutating
    }
    return .unknown
}

private func uaaRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    guard let command = words.first(where: { $0 != "--verbose" && $0 != "-v" }) else {
        return .unknown
    }
    if ["--version", "version", "help", "targets", "contexts", "info", "get-token-key",
        "get-token-keys", "get-client", "get-user", "get-group", "list-clients", "list-users",
        "list-groups", "list-group-mappings", "userinfo"].contains(command)
    {
        return .readOnly
    }
    if ["context", "decode-token"].contains(command) { return .secretDump }
    if ["target", "use-context", "use-target"].contains(command) { return .localWrite }
    if command == "curl" { return .unknown }
    if command.contains("token")
        || ["create", "update", "delete", "add", "remove", "map", "unmap", "activate",
            "deactivate", "unlock", "change", "set"].contains(where: { command.hasPrefix($0) })
    {
        return .mutating
    }
    return .unknown
}

private func oxideRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    var commandIndex = 0
    while commandIndex < args.count {
        let argument = args[commandIndex].lowercased()
        if argument.hasPrefix("--profile=") || argument.hasPrefix("--host=") {
            commandIndex += 1
        } else if argument == "--profile" || argument == "--host" {
            guard commandIndex + 1 < args.count else { return .unknown }
            commandIndex += 2
        } else {
            break
        }
    }
    let words = args.dropFirst(commandIndex).map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    if ["--version", "-v", "version", "help"].contains(command) { return .readOnly }
    if command == "auth" {
        switch words.dropFirst().first {
        case "status", "help": return .readOnly
        case "login", "logout": return .mutating
        default: return .unknown
        }
    }
    let topLevelCommands = [
        "alert", "api", "audit-log", "auth-settings", "bundle", "certificate", "completion",
        "current-user", "der", "disk", "docs", "experimental", "external-subnet", "floating-ip",
        "group", "image", "instance", "internet-gateway", "ip-pool", "pem", "ping", "policy",
        "project", "scim", "silo", "snapshot", "subnet-pool", "system", "user", "utilization",
        "vpc",
    ]
    guard topLevelCommands.contains(command) else { return .unknown }
    guard let action = words.dropFirst().first else { return .unknown }
    if ["list", "view", "get"].contains(action) { return .readOnly }
    if ["create", "delete", "edit", "update", "start", "stop", "reboot"].contains(action) {
        return .mutating
    }
    return .unknown
}

private func terraformRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    if args == ["-version"] || args == ["--version"] { return .readOnly }
    let words = args.drop(while: {
        $0 == "-no-color" || $0 == "-help" || $0.hasPrefix("-chdir=")
    }).map { $0.lowercased() }
    guard let command = words.first else { return .unknown }
    switch command {
    case "version", "help", "validate", "show", "output", "graph":
        return .readOnly
    case "fmt":
        return words.contains("-check") ? .readOnly : .localWrite
    case "providers":
        guard let subcommand = words.dropFirst().first else { return .readOnly }
        return subcommand == "schema" ? .readOnly : .localWrite
    case "init", "plan", "console", "get":
        return .localWrite
    case "apply", "destroy", "import", "refresh", "force-unlock", "login", "logout":
        return .mutating
    case "state":
        guard let subcommand = words.dropFirst().first else { return .unknown }
        return ["list", "show", "pull"].contains(subcommand) ? .readOnly : .mutating
    case "workspace":
        guard let subcommand = words.dropFirst().first else { return .unknown }
        return subcommand == "list" || subcommand == "show" ? .readOnly : .mutating
    default:
        return .unknown
    }
}

private func aliyunRequestClassification(_ args: [String]) -> SecretGateRequestClassification {
    let words = args.map { $0.lowercased() }
    if words == ["--version"] || words == ["version"] || words == ["help"] {
        return .readOnly
    }
    if words.starts(with: ["sts", "getcalleridentity"]) {
        return .readOnly
    }
    return .unknown
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
        selectedSecretValues: request.selectedSecretValues
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

private struct StoredGoatCredentialScope {
    let did: String
    let pds: String
    let canonical: String

    var secretName: String {
        let hash = SHA256.hash(data: Data((did + "\0" + pds).utf8))
            .map { String(format: "%02X", $0) }.joined()
        return "GOAT_AUTH_SESSION_\(hash)"
    }
}

private func parseGoatCredentialScope(_ value: String) -> StoredGoatCredentialScope? {
    guard value.utf8.count <= 4 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["did", "pds"]),
          let did = object["did"] as? String, validGoatDID(did),
          let pds = object["pds"] as? String, normalizeOxideHost(pds) == pds,
          let canonicalData = try? JSONSerialization.data(
              withJSONObject: ["did": did, "pds": pds],
              options: [.sortedKeys, .withoutEscapingSlashes]
          ),
          let canonical = String(data: canonicalData, encoding: .utf8), canonical == value
    else { return nil }
    return StoredGoatCredentialScope(did: did, pds: pds, canonical: canonical)
}

private func validGoatDID(_ did: String) -> Bool {
    let prefixLength = did.hasPrefix("did:plc:") ? "did:plc:".utf8.count
        : did.hasPrefix("did:web:") ? "did:web:".utf8.count : 0
    return prefixLength > 0
        && did.utf8.count > prefixLength
        && did.utf8.count <= 2048
        && did.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (scalar.isASCIIAlpha || scalar.isASCIIDigit || ".:_%~-".contains(Character(scalar)))
        }
}

private func parseGoatCredential(_ value: String) -> String? {
    guard value.utf8.count <= 64 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["password", "access_token", "session_token"]),
          ["password", "access_token", "session_token"].allSatisfy({ key in
              guard let field = object[key] as? String else { return false }
              return !field.isEmpty && field != "@av"
                  && !field.unicodeScalars.contains(where: { $0.value == 0 })
          })
    else { return nil }
    return value
}

private let ordercliCredentialSecretName = "ORDERCLI_FOODORA_SESSION"

private struct StoredOrdercliCredentialScope {
    let canonical: String
    let secretName = ordercliCredentialSecretName
}

private func parseOrdercliCredentialScope(_ value: String) -> StoredOrdercliCredentialScope? {
    guard value == #"{"provider":"foodora"}"# else { return nil }
    return StoredOrdercliCredentialScope(canonical: value)
}

private func parseOrdercliCredential(_ value: String) -> String? {
    guard value.utf8.count <= 256 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set([
              "access_token", "refresh_token", "client_secret", "pending_mfa_token",
              "cookies_by_host",
          ])
    else { return nil }
    let stringKeys = ["access_token", "refresh_token", "client_secret", "pending_mfa_token"]
    guard stringKeys.allSatisfy({ key in
        guard let field = object[key] as? String else { return false }
        return !field.unicodeScalars.contains(where: { $0.value == 0 })
    }) else { return nil }
    let cookies: [String: Any]
    if object["cookies_by_host"] is NSNull {
        cookies = [:]
    } else if let value = object["cookies_by_host"] as? [String: Any] {
        cookies = value
    } else {
        return nil
    }
    guard cookies.count <= 256,
          cookies.allSatisfy({ host, rawCookie in
              guard let cookie = rawCookie as? String else { return false }
              return !host.isEmpty && !cookie.isEmpty
                  && host.utf8.count <= 2048 && cookie.utf8.count <= 64 * 1024
                  && !host.unicodeScalars.contains(where: { $0.value == 0 })
                  && !cookie.unicodeScalars.contains(where: { $0.value == 0 })
          }),
          stringKeys.contains(where: { (object[$0] as? String)?.isEmpty == false })
              || !cookies.isEmpty
    else { return nil }
    return value
}

private let openhueCredentialSecretName = "OPENHUE_APPLICATION_KEY"

private struct StoredOpenHueCredentialScope {
    let bridge: String
    let canonical: String
    let secretName = openhueCredentialSecretName
}

private func parseOpenHueCredentialScope(_ value: String) -> StoredOpenHueCredentialScope? {
    guard value.utf8.count <= 512,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["bridge"]),
          let bridge = object["bridge"] as? String,
          !bridge.isEmpty, bridge.utf8.count <= 255,
          !bridge.unicodeScalars.contains(where: { $0.value == 0 }),
          let canonicalData = try? JSONSerialization.data(withJSONObject: ["bridge": bridge], options: [.sortedKeys]),
          String(data: canonicalData, encoding: .utf8) == value
    else { return nil }
    return StoredOpenHueCredentialScope(bridge: bridge, canonical: value)
}

private func parseOpenHueCredential(_ value: String) -> String? {
    guard !value.isEmpty, value != "@av", value.utf8.count <= 64 * 1024,
          !value.unicodeScalars.contains(where: { $0.value == 0 })
    else { return nil }
    return value
}

private let plumberCredentialSecretName = "PLUMBER_LOCAL_CONFIG"
private let plumberCredentialScope = #"{"store":"local-config"}"#

private struct StoredPlumberCredentialScope {
    let canonical: String
    let secretName = plumberCredentialSecretName
}

private func parsePlumberCredentialScope(_ value: String) -> StoredPlumberCredentialScope? {
    guard value == plumberCredentialScope else { return nil }
    return StoredPlumberCredentialScope(canonical: value)
}

private func parsePlumberCredential(_ value: String) -> String? {
    guard !value.isEmpty, value.utf8.count <= 1024 * 1024,
          !value.unicodeScalars.contains(where: { $0.value == 0 }),
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          !(Set(object.keys) == Set(["automic_vault"])
              && object["automic_vault"] as? String == "plumber-config-v1")
    else { return nil }
    return value
}

private let uaaCredentialSecretName = "UAA_OAUTH_TOKENS"

private struct StoredUAACredentialScope {
    let canonical: String
    let secretName = uaaCredentialSecretName
}

private func parseUAACredentialScope(_ value: String) -> StoredUAACredentialScope? {
    guard value == #"{"store":"contexts"}"# else { return nil }
    return StoredUAACredentialScope(canonical: value)
}

private func parseUAACredential(_ value: String) -> String? {
    guard value.utf8.count <= 1024 * 1024,
          let data = value.data(using: .utf8),
          let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(root.keys) == Set(["targets"]),
          let targets = root["targets"] as? [String: Any],
          !targets.isEmpty, targets.count <= 128
    else { return nil }
    let validKey: (String) -> Bool = { key in
        !key.isEmpty && key.utf8.count <= 4096
            && !key.unicodeScalars.contains(where: { $0.value == 0 })
    }
    guard targets.allSatisfy({ target, rawContexts in
        guard validKey(target), let contexts = rawContexts as? [String: Any],
              !contexts.isEmpty, contexts.count <= 256
        else { return false }
        return contexts.allSatisfy({ context, rawToken in
            guard validKey(context), let token = rawToken as? [String: Any],
                  !token.isEmpty,
                  Set(token.keys).isSubset(of: Set(["access_token", "refresh_token"]))
            else { return false }
            return token.values.allSatisfy({ rawValue in
                guard let secret = rawValue as? String else { return false }
                return !secret.isEmpty && secret != "@av" && secret.utf8.count <= 512 * 1024
                    && !secret.unicodeScalars.contains(where: { $0.value == 0 })
            })
        })
    }) else { return nil }
    return value
}

private struct StoredRailwayCredentialScope {
    let environment: String
    let host: String
    let canonical: String

    var secretName: String {
        let hash = SHA256.hash(data: Data((environment + "\0" + host).utf8))
            .map { String(format: "%02X", $0) }.joined()
        return "RAILWAY_AUTH_\(hash)"
    }
}

private func parseRailwayCredentialScope(_ value: String) -> StoredRailwayCredentialScope? {
    let expectedHosts = [
        "production": "railway.com",
        "staging": "railway-staging.com",
        "dev": "railway-develop.com",
    ]
    guard value.utf8.count <= 4 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["environment", "host"]),
          let environment = object["environment"] as? String,
          let host = object["host"] as? String,
          expectedHosts[environment] == host,
          let canonicalData = try? JSONSerialization.data(
              withJSONObject: ["environment": environment, "host": host],
              options: [.sortedKeys, .withoutEscapingSlashes]
          ),
          let canonical = String(data: canonicalData, encoding: .utf8), canonical == value
    else { return nil }
    return StoredRailwayCredentialScope(environment: environment, host: host, canonical: canonical)
}

private func parseRailwayCredential(_ value: String) -> String? {
    guard value.utf8.count <= 64 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["token", "accessToken", "refreshToken"])
    else { return nil }
    func string(_ key: String) -> String? {
        guard let field = object[key] as? String, !field.isEmpty,
              !field.unicodeScalars.contains(where: { $0.value == 0 })
        else { return nil }
        return field
    }
    func absent(_ key: String) -> Bool { object[key] is NSNull }
    let legacy = string("token") != nil && absent("accessToken") && absent("refreshToken")
    let oauth = absent("token") && string("accessToken") != nil
        && (absent("refreshToken") || string("refreshToken") != nil)
    return legacy || oauth ? value : nil
}

private struct StoredOxideCredentialScope {
    let profile: String
    let host: String
    let canonical: String

    var secretName: String {
        let data = Data((profile + "\0" + host).utf8)
        let hash = SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined()
        return "OXIDE_PROFILE_TOKEN_\(hash)"
    }
}

private func parseOxideCredentialScope(_ value: String) -> StoredOxideCredentialScope? {
    guard value.utf8.count <= 4 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["host", "profile"]),
          let profile = object["profile"] as? String,
          let host = object["host"] as? String,
          validOxideProfile(profile),
          normalizeOxideHost(host) == host,
          let canonicalData = try? JSONSerialization.data(
              withJSONObject: ["host": host, "profile": profile],
              options: [.sortedKeys, .withoutEscapingSlashes]
          ),
          let canonical = String(data: canonicalData, encoding: .utf8),
          canonical == value
    else { return nil }
    return StoredOxideCredentialScope(profile: profile, host: host, canonical: canonical)
}

private func validOxideProfile(_ profile: String) -> Bool {
    !profile.isEmpty
        && profile.utf8.count <= 128
        && profile == profile.trimmingCharacters(in: .whitespacesAndNewlines)
        && profile.unicodeScalars.allSatisfy { $0.isASCII && $0.value > 31 && $0.value != 127 }
}

private func normalizeOxideHost(_ host: String) -> String? {
    guard let input = URLComponents(string: host),
          let scheme = input.scheme?.lowercased(),
          scheme == "http" || scheme == "https",
          let hostname = input.host?.lowercased(),
          !hostname.isEmpty,
          input.user == nil,
          input.password == nil,
          input.path.isEmpty || input.path == "/",
          input.query == nil,
          input.fragment == nil
    else { return nil }
    var output = URLComponents()
    output.scheme = scheme
    output.host = hostname
    if input.port != (scheme == "https" ? 443 : 80) { output.port = input.port }
    return output.string
}

private func parseOxideCredential(_ value: String) -> String? {
    guard !value.isEmpty,
          value.utf8.count <= 64 * 1024,
          !value.unicodeScalars.contains(where: { [0, 10, 13].contains($0.value) })
    else { return nil }
    return value
}

private func normalizeTerraformHostname(_ hostname: String) -> String? {
    guard !hostname.isEmpty,
          hostname.utf8.count <= 253,
          hostname.unicodeScalars.allSatisfy(\.isASCII),
          !hostname.hasPrefix("."),
          !hostname.hasSuffix(".")
    else { return nil }
    let normalized = hostname.lowercased()
    guard normalized.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ label in
        !label.isEmpty
            && label.utf8.count <= 63
            && label.first != "-"
            && label.last != "-"
            && label.unicodeScalars.allSatisfy { $0.isASCIIAlpha || $0.isASCIIDigit || $0 == "-" }
    }) else { return nil }
    return normalized
}

private func terraformCredentialSecretName(_ hostname: String) -> String {
    let hash = SHA256.hash(data: Data(hostname.utf8)).map { String(format: "%02X", $0) }.joined()
    return "TERRAFORM_HOST_CREDENTIAL_\(hash)"
}

private func normalizeAliyunProfile(_ profile: String) -> String? {
    guard !profile.isEmpty,
          profile.utf8.count <= 128,
          profile.unicodeScalars.allSatisfy({
              $0.isASCII && !((0...31).contains($0.value) || $0.value == 127)
          })
    else { return nil }
    return profile.trimmingCharacters(in: .whitespacesAndNewlines) == profile ? profile : nil
}

private func aliyunCredentialSecretName(_ profile: String) -> String {
    let hash = SHA256.hash(data: Data(profile.utf8)).map { String(format: "%02X", $0) }.joined()
    return "ALIYUN_PROFILE_CREDENTIAL_\(hash)"
}

private func parseAliyunCredential(_ value: String) -> Bool {
    guard value.utf8.count <= 64 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let mode = object["mode"] as? String,
          let accessKeyID = object["access_key_id"] as? String,
          let accessKeySecret = object["access_key_secret"] as? String,
          validAliyunCredentialValue(accessKeyID),
          validAliyunCredentialValue(accessKeySecret)
    else { return false }
    if mode == "AK" {
        return Set(object.keys) == Set(["mode", "access_key_id", "access_key_secret"])
    }
    guard mode == "StsToken", let token = object["sts_token"] as? String,
          validAliyunCredentialValue(token)
    else { return false }
    return Set(object.keys) == Set(["mode", "access_key_id", "access_key_secret", "sts_token"])
}

private func validAliyunCredentialValue(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 64 * 1024
        && !value.unicodeScalars.contains(where: { [0, 10, 13].contains($0.value) })
}

private func parseTerraformCredential(_ value: String) -> String? {
    guard value.utf8.count <= 64 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["token"]),
          let token = object["token"] as? String,
          !token.isEmpty,
          !token.unicodeScalars.contains(where: { $0.value == 0 })
    else { return nil }
    return token
}

private let wakatimeCredentialSecretName = "WAKATIME_API_KEY"
private let wakatimeOfficialAPIURL = "https://api.wakatime.com/api/v1"

private func validWakaTimeAPIKey(_ value: String) -> Bool {
    let key = value.hasPrefix("waka_") ? String(value.dropFirst(5)) : value
    let bytes = Array(key.utf8)
    let hyphens = Set([8, 13, 18, 23])
    guard bytes.count == 36, bytes[14] == 52, [56, 57, 97, 98].contains(bytes[19]) else {
        return false
    }
    return bytes.enumerated().allSatisfy { index, byte in
        hyphens.contains(index)
            ? byte == 45
            : (48...57).contains(byte) || (97...102).contains(byte)
    }
}

private let rcloneConfigPasswordSecretName = "RCLONE_CONFIG_PASSWORD"
private let rcloneAllRemotesScope = "all-remotes"

private func validRcloneConfigPassword(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 1024
        && !value.unicodeScalars.contains(where: { [0, 10, 13].contains($0.value) })
}

private struct StoredKubectlCredentialScope {
    let kind: String
    let server: String
    let user: String
    let canonical: String

    var secretName: String {
        let hash = SHA256.hash(data: Data(user.utf8)).map { String(format: "%02X", $0) }.joined()
        return "KUBECTL_USER_CREDENTIAL_\(hash)"
    }
}

private func parseKubectlCredentialScope(_ value: String) -> StoredKubectlCredentialScope? {
    guard value.utf8.count <= 8 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set(["kind", "server", "user"]),
          let kind = object["kind"] as? String,
          kind == "token" || kind == "client-certificate",
          let server = object["server"] as? String,
          server.utf8.count <= 4096,
          server.unicodeScalars.allSatisfy(\.isASCII),
          let components = URLComponents(string: server),
          components.scheme == "https",
          components.host?.isEmpty == false,
          components.user == nil,
          components.password == nil,
          components.query == nil,
          components.fragment == nil,
          let user = object["user"] as? String,
          !user.isEmpty,
          user.utf8.count <= 1024,
          user == user.trimmingCharacters(in: .whitespacesAndNewlines),
          !user.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
          let canonicalData = try? JSONSerialization.data(
              withJSONObject: ["kind": kind, "server": server, "user": user],
              options: [.sortedKeys, .withoutEscapingSlashes]
          ),
          let canonical = String(data: canonicalData, encoding: .utf8),
          canonical == value
    else { return nil }
    return StoredKubectlCredentialScope(
        kind: kind,
        server: server,
        user: user,
        canonical: canonical
    )
}

private func validKubectlCredential(_ value: String, kind: String) -> Bool {
    guard value.utf8.count <= 4 * 1024 * 1024,
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return false }
    if kind == "token" {
        guard Set(object.keys) == Set(["token"]), let token = object["token"] as? String else {
            return false
        }
        return !token.isEmpty && token.utf8.count <= 1024 * 1024
            && !token.unicodeScalars.contains(where: { $0.value == 0 })
    }
    guard kind == "client-certificate",
          Set(object.keys) == Set(["clientCertificateData", "clientKeyData"]),
          let certificate = object["clientCertificateData"] as? String,
          let key = object["clientKeyData"] as? String
    else { return false }
    return certificate.contains("-----BEGIN CERTIFICATE-----")
        && key.contains("-----BEGIN")
        && key.contains("PRIVATE KEY-----")
        && !certificate.unicodeScalars.contains(where: { $0.value == 0 })
        && !key.unicodeScalars.contains(where: { $0.value == 0 })
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

private func sameProcessIdentity(
    _ expected: AVProcessIdentity,
    _ current: AVProcessIdentity
) -> Bool {
    expected.pid == current.pid
        && expected.pidversion == current.pidversion
        && expected.start_usec == current.start_usec
        && expected.euid == current.euid
        && expected.audit_session_id == current.audit_session_id
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

func selfTeamIdentifier() -> String? {
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
    guard identity.euid == geteuid(),
          identity.pidversion > 0,
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

private func approvalProcessExecution(
    pid: pid_t,
    identity: AVProcessIdentity
) -> ApprovalProcessExecution? {
    guard let codeIdentity = liveCodeIdentity(pid: pid) else { return nil }
    // Setuid Gate Clients may deny task-port access. This evidence is diagnostic only,
    // so bind audit-token fields when available and always bind live process identity.
    let hasAuditToken = identity.pidversion > 0
    let execution = ApprovalProcessExecution(
        pid: pid,
        pidVersion: hasAuditToken ? identity.pidversion : nil,
        startUsec: identity.start_usec,
        effectiveUserID: identity.euid,
        auditSessionID: hasAuditToken ? identity.audit_session_id : nil,
        codeIdentity: codeIdentity
    )
    var current = AVProcessIdentity()
    return av_process_identity(pid, &current) && approvalProcessExecutionMatches(execution, current)
        ? execution
        : nil
}

private func approvalProcessExecutionMatches(
    _ execution: ApprovalProcessExecution,
    _ identity: AVProcessIdentity
) -> Bool {
    execution.startUsec == identity.start_usec
        && execution.effectiveUserID == identity.euid
        && execution.pidVersion.map { $0 == identity.pidversion } ?? true
        && execution.auditSessionID.map { $0 == identity.audit_session_id } ?? true
}

private func approvalProcessExecutionIsLive(_ execution: ApprovalProcessExecution) -> Bool {
    var before = AVProcessIdentity()
    guard av_process_identity(execution.pid, &before),
          approvalProcessExecutionMatches(execution, before),
          liveCodeIdentity(pid: execution.pid) == execution.codeIdentity
    else { return false }
    var after = AVProcessIdentity()
    return av_process_identity(execution.pid, &after)
        && approvalProcessExecutionMatches(execution, after)
}

private func liveSecretUseProcess(
    pid: pid_t,
    identity: AVProcessIdentity
) -> LiveSecretUseProcess? {
    guard identity.pid == pid, identity.euid == geteuid() else { return nil }
    let process = LiveSecretUseProcess(
        pid: pid,
        startUsec: identity.start_usec,
        effectiveUserID: identity.euid,
        auditSessionID: identity.audit_session_id
    )
    return liveSecretUseProcessIsLive(process) ? process : nil
}

private func liveSecretUseProcessIsLive(_ process: LiveSecretUseProcess) -> Bool {
    func matches(_ identity: AVProcessIdentity) -> Bool {
        identity.start_usec == process.startUsec
            && identity.euid == process.effectiveUserID
            && identity.audit_session_id == process.auditSessionID
    }
    var before = AVProcessIdentity()
    guard av_process_identity(process.pid, &before), matches(before) else { return false }
    var after = AVProcessIdentity()
    return av_process_identity(process.pid, &after) && matches(after)
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

private struct ApprovalProcessIdentity {
    let pid: pid_t
    let path: String
    let execution: ApprovalProcessExecution?
}

private enum ApprovalProcessPosture: Equatable {
    case meetsRequirements
    case needsAttention
    case doesNotMeetRequirements
}

private struct ApprovalProcessSecurityNode: Identifiable {
    let pid: pid_t?
    let path: String
    let roles: [String]
    let posture: ApprovalProcessPosture
    let explanation: String
    let isAutomicVaultSigned: Bool

    var id: String { "\(pid ?? -1):\(path)" }
    var name: String { URL(fileURLWithPath: path).lastPathComponent }
}

private struct ApprovalProcessSecurity {
    let nodes: [ApprovalProcessSecurityNode]
}

private func isAutomicVaultSigned(
    _ signing: LiveSigningInfo?,
    teamIdentifier: String?
) -> Bool {
    signing?.isDeveloperID == true && signing?.teamIdentifier == teamIdentifier
}

private func approvalProcessIdentities(
    gateClientPID: pid_t,
    launcherPID: pid_t?
) -> [ApprovalProcessIdentity] {
    var caller = AVProcessIdentity()
    guard av_process_identity(gateClientPID, &caller) else { return [] }
    let callerNode = ApprovalProcessIdentity(
        pid: gateClientPID,
        path: pathString(caller),
        execution: approvalProcessExecution(pid: gateClientPID, identity: caller)
    )
    var chains: [[ApprovalProcessIdentity]] = []
    for startPID in launcherAncestorStartPIDs(caller) {
        var currentPID = startPID
        var seen = Set<pid_t>()
        var nodes = [callerNode]
        for _ in 0..<32 {
            guard currentPID > 1, seen.insert(currentPID).inserted else { break }
            var identity = AVProcessIdentity()
            guard av_process_identity(currentPID, &identity) else { break }
            let path = pathString(identity)
            if !path.isEmpty {
                nodes.append(ApprovalProcessIdentity(
                    pid: currentPID,
                    path: path,
                    execution: approvalProcessExecution(pid: currentPID, identity: identity)
                ))
            }
            currentPID = identity.ppid
        }
        chains.append(nodes)
    }
    let chain = launcherPID.flatMap { launcherPID in
        chains.first { $0.contains(where: { $0.pid == launcherPID }) }
    } ?? chains.max(by: { $0.count < $1.count }) ?? [callerNode]
    let bounded = launcherPID.flatMap { launcherPID in
        chain.firstIndex(where: { $0.pid == launcherPID }).map { Array(chain[...$0]) }
    } ?? chain
    return bounded
}

private func mutableCodeExplanation(path: String) -> String? {
    let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
    if ["node", "nodejs", "deno", "bun"].contains(name) {
        return "Executes mutable JavaScript and dependencies"
    }
    if name == "python" || name.hasPrefix("python3") || ["ruby", "perl", "php"].contains(name) {
        return "Executes mutable source code and dependencies"
    }
    if ["sh", "bash", "zsh", "fish"].contains(name) {
        return "Executes mutable shell code"
    }
    if name == "java" {
        return "Loads mutable bytecode and dependencies"
    }
    return nil
}

private func approvalProcessPosture(
    signing: LiveSigningInfo?,
    runtimeProtection: LauncherRuntimeProtection? = nil,
    identityVerified: Bool = false,
    mutableCode: String?
) -> (ApprovalProcessPosture, String) {
    guard let signing else {
        return (
            .doesNotMeetRequirements,
            ["Code signature could not be verified", mutableCode].compactMap(\.self).joined(separator: "; ")
        )
    }
    let runtimeProtection = runtimeProtection ?? signing.runtimeProtection
    var findings: [String] = []
    var posture = ApprovalProcessPosture.meetsRequirements
    if signing.isAdHoc && !identityVerified {
        posture = .doesNotMeetRequirements
        findings.append("Ad hoc signature does not authenticate a publisher")
    } else {
        findings.append(identityVerified ? "Verified Launcher identity" : "Valid code signature")
    }
    switch runtimeProtection {
    case .hardened:
        findings.append("Hardened Runtime")
    case .hardenedWithLibraryValidationDisabled:
        if posture == .meetsRequirements { posture = .needsAttention }
        findings.append("Library validation is disabled")
    case .hardenedRuntimeMissing:
        posture = .doesNotMeetRequirements
        findings.append("Hardened Runtime is not enabled")
    case .unsafeEntitlements(let entitlements):
        posture = .doesNotMeetRequirements
        findings.append("Unsafe entitlements: \(entitlements.joined(separator: ", "))")
    }
    if let mutableCode {
        if posture == .meetsRequirements { posture = .needsAttention }
        findings.append(mutableCode)
    }
    return (posture, findings.joined(separator: "; "))
}

private func approvalTargetPID(
    explicitPID: pid_t?,
    dockerPID: pid_t?,
    targetPath: String,
    identities: [ApprovalProcessIdentity]
) -> pid_t? {
    explicitPID ?? dockerPID ?? identities.first(where: {
        !targetPath.isEmpty && normalizedExecutablePath($0.path) == targetPath
    })?.pid
}

private func approvalProcessSecurity(
    request: ApprovalRequest,
    gateClientPID: pid_t,
    gateClientPath: String,
    targetPID: pid_t? = nil,
    launcher: LauncherIdentity?
) -> ApprovalProcessSecurity {
    let automicVaultTeamIdentifier = selfTeamIdentifier()
    var identities = approvalProcessIdentities(
        gateClientPID: gateClientPID,
        launcherPID: launcher?.pid
    )
    if let launcher,
       !identities.contains(where: { $0.pid == launcher.pid })
    {
        var identity = AVProcessIdentity()
        let execution = av_process_identity(launcher.pid, &identity)
            ? approvalProcessExecution(pid: launcher.pid, identity: identity)
            : nil
        identities.append(ApprovalProcessIdentity(
            pid: launcher.pid,
            path: launcher.path,
            execution: execution
        ))
    }
    if !identities.contains(where: { $0.pid == gateClientPID }) {
        identities.insert(ApprovalProcessIdentity(
            pid: gateClientPID,
            path: gateClientPath,
            execution: nil
        ), at: 0)
    }

    let targetPath = normalizedExecutablePath(request.target)
    let liveTargetPID = approvalTargetPID(
        explicitPID: targetPID,
        dockerPID: request.credentialParent?.pid,
        targetPath: targetPath,
        identities: identities
    )
    var nodes = identities.map { identity -> ApprovalProcessSecurityNode in
        let isLauncher = identity.pid == launcher?.pid
        let isGateClient = identity.pid == gateClientPID
        let isTarget = identity.pid == liveTargetPID
        var roles: [String] = []
        if isLauncher { roles.append("Verified Launcher") }
        if isTarget { roles.append(request.keys.isEmpty ? "Target" : "Secret recipient") }
        if isGateClient { roles.append("Verified Gate Client") }
        if roles.isEmpty { roles.append("Intermediary") }

        let signing = identity.execution.flatMap { execution -> LiveSigningInfo? in
            guard approvalProcessExecutionIsLive(execution) else { return nil }
            let signing = liveSigningInfo(pid: identity.pid)
            return approvalProcessExecutionIsLive(execution) ? signing : nil
        }
        let result = approvalProcessPosture(
            signing: signing,
            runtimeProtection: isLauncher ? launcher?.runtimeProtection : nil,
            identityVerified: isLauncher,
            mutableCode: mutableCodeExplanation(path: identity.path)
        )
        return ApprovalProcessSecurityNode(
            pid: identity.pid,
            path: identity.path,
            roles: roles,
            posture: result.0,
            explanation: result.1,
            isAutomicVaultSigned: isAutomicVaultSigned(
                signing,
                teamIdentifier: automicVaultTeamIdentifier
            )
        )
    }

    if liveTargetPID == nil, !request.target.isEmpty {
        let signing = executableSigningInfo(path: request.target)
        let result = approvalProcessPosture(
            signing: signing,
            mutableCode: mutableCodeExplanation(path: request.target)
        )
        nodes.insert(ApprovalProcessSecurityNode(
            pid: nil,
            path: request.target,
            roles: [request.keys.isEmpty ? "Target (not started)" : "Secret recipient (not started)"],
            posture: result.0,
            explanation: result.1,
            isAutomicVaultSigned: isAutomicVaultSigned(
                signing,
                teamIdentifier: automicVaultTeamIdentifier
            )
        ), at: 0)
    }
    return ApprovalProcessSecurity(nodes: nodes)
}

private func approvalProcessChain(pid: pid_t) -> String? {
    let paths = approvalProcessIdentities(gateClientPID: pid, launcherPID: nil).map(\.path)
    return paths.isEmpty ? nil : processChainLabel(paths: paths)
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
    appSigning: (URL) -> StaticSigningInfo? = staticSigningInfo,
    bundleExecutableURL: (URL) -> URL? = { Bundle(url: $0)?.executableURL }
) -> LauncherIdentity? {
    launcherIdentities(
        pid: pid,
        path: path,
        signing: signing,
        appSigning: appSigning,
        bundleExecutableURL: bundleExecutableURL
    ).first
}

private func launcherIdentities(
    pid: pid_t,
    path: String,
    signing: LiveSigningInfo,
    appSigning: (URL) -> StaticSigningInfo? = staticSigningInfo,
    bundleExecutableURL: (URL) -> URL? = { Bundle(url: $0)?.executableURL },
    allowsStandaloneFallback: Bool = true
) -> [LauncherIdentity] {
    // Gate plumbing is never the operation's Launcher.
    guard signing.identifier != "com.automicvault.av-gpg" else { return [] }
    var seenContainingApps = Set<String>()
    let containingAppURLs = (
        appBundleURLs(containing: path)
        + appBundleURLs(containing: signing.mainExecutable)
    ).filter { seenContainingApps.insert($0.path).inserted }
    var seenApps = Set<String>()
    let appURLs = (
        containingAppURLs.filter {
            appBundleMatchesMainExecutable(
                $0,
                executablePaths: [path, signing.mainExecutable],
                bundleExecutableURL: bundleExecutableURL
            )
        }
        + [associatedAppBundleURL(path: path, signing: signing)].compactMap { $0 }
    ).filter { seenApps.insert($0.path).inserted }
    let helperAssociation = verifiedLauncherHelperAssociation(
        path: path,
        signing: signing,
        containingAppURLs: containingAppURLs
    )
    let claimsLauncherBundleIdentity = signing.identifier.hasPrefix(launcherBundleIdentifierPrefix)
        || containingAppURLs.contains(where: launcherBundleClaimsReservedIdentity)
    if claimsLauncherBundleIdentity {
        guard let appURL = containingAppURLs.first(where: {
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
    var apps: [LauncherIdentity] = appURLs.compactMap { appURL in
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
    if let helperAssociation,
       seenApps.insert(helperAssociation.appURL.path).inserted,
       let app = verifiedLauncherHelperSigningInfo(helperAssociation, pid: pid) {
        apps.append(LauncherIdentity(
            pid: pid,
            path: path,
            identifier: app.identifier,
            teamIdentifier: app.teamIdentifier,
            designatedRequirement: app.designatedRequirement,
            runtimeProtection: signing.runtimeProtection
        ))
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
        case .openWindow, .awsHelperVersion, .dockerHelperVersion, .goatHelperVersion,
             .ordercliHelperVersion, .openhueHelperVersion, .plumberHelperVersion, .uaaHelperVersion,
             .railwayHelperVersion, .oxideHelperVersion, .terraformHelperVersion,
             .aliyunHelperVersion, .wakatimeHelperVersion, .rcloneHelperVersion,
             .kubectlHelperVersion: false
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

private struct VerifiedLauncherHelperAssociation {
    let helper: VerifiedLauncherHelper
    let appURL: URL
    let executableURL: URL
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

private func liveProcessHasNoEntitlements(pid: pid_t) -> Bool {
    var code: SecCode?
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
          let code,
          SecCodeCheckValidity(code, [], nil) == errSecSuccess
    else { return false }
    var info: CFDictionary?
    let inspectableCode = unsafeBitCast(code, to: SecStaticCode.self)
    guard SecCodeCopySigningInformation(
        inspectableCode,
        SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation),
        &info
    ) == errSecSuccess,
        let dictionary = info as? [CFString: Any]
    else { return false }
    return (dictionary[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]).isEmpty
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
          validateAppBundleMainExecutable(staticCode) == errSecSuccess
    else {
        return nil
    }

    return staticSigningInfo(staticCode)
}

private func staticSigningInfo(_ staticCode: SecStaticCode) -> StaticSigningInfo? {
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
                let containingAppURLs = (
                    appBundleURLs(containing: path)
                    + appBundleURLs(containing: signing.mainExecutable)
                )
                let helperAssociation = verifiedLauncherHelperAssociation(
                    path: path,
                    signing: signing,
                    containingAppURLs: containingAppURLs
                )
                if let helperAssociation,
                   checkedApps.insert(helperAssociation.appURL.path).inserted,
                   verifiedLauncherHelperSigningInfo(helperAssociation, pid: pid) == nil {
                    return LauncherAppVerificationFailure(
                        appName: helperAssociation.helper.appName,
                        resourcesUnreadable: false
                    )
                }
                let appURLs = containingAppURLs.filter {
                    $0.path != helperAssociation?.appURL.path
                        && appBundleMatchesMainExecutable(
                            $0,
                            executablePaths: [path, signing.mainExecutable]
                        )
                }
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
    let status = validateAppBundleMainExecutable(staticCode)
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

private func appBundleMatchesMainExecutable(
    _ appURL: URL,
    executablePaths: [String],
    bundleExecutableURL: (URL) -> URL? = { Bundle(url: $0)?.executableURL }
) -> Bool {
    guard let bundleExecutableURL = bundleExecutableURL(appURL) else { return false }
    let bundleExecutablePath = bundleExecutableURL.standardizedFileURL.resolvingSymlinksInPath().path
    return executablePaths.contains {
        URL(fileURLWithPath: $0).standardizedFileURL.resolvingSymlinksInPath().path
            == bundleExecutablePath
    }
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

private func verifiedLauncherHelperAssociation(
    path: String,
    signing: LiveSigningInfo,
    containingAppURLs: [URL]? = nil,
    helpers: [VerifiedLauncherHelper]? = nil,
    configuration: VerifiedLauncherHelperConfiguration? = nil,
    bundleIdentifier: (URL) -> String? = { Bundle(url: $0)?.bundleIdentifier }
) -> VerifiedLauncherHelperAssociation? {
    let configuration = configuration ?? loadVerifiedLauncherHelperConfiguration()
    let helpers = helpers ?? configuration.helpers
    guard signing.isDeveloperID else { return nil }
    let executablePath = signing.mainExecutable.isEmpty ? path : signing.mainExecutable
    let executableURL = URL(fileURLWithPath: executablePath)
        .standardizedFileURL
        .resolvingSymlinksInPath()
    let appURLs = containingAppURLs ?? appBundleURLs(containing: executableURL.path)
    for helper in helpers where configuration.isEnabled(helper)
        && helper.helperSigningIdentifier == signing.identifier
        && helper.helperTeamIdentifier == signing.teamIdentifier
    {
        guard let appURL = appURLs.first(where: {
            bundleIdentifier($0) == helper.appBundleIdentifier
        }) else { continue }
        if let relativePath = helper.relativePath {
            let expectedURL = appURL.appendingPathComponent(relativePath)
                .standardizedFileURL
                .resolvingSymlinksInPath()
            guard expectedURL == executableURL else { continue }
        }
        return VerifiedLauncherHelperAssociation(
            helper: helper,
            appURL: appURL,
            executableURL: executableURL
        )
    }
    return nil
}

private func verifiedLauncherHelperSigningInfo(
    _ association: VerifiedLauncherHelperAssociation,
    pid: pid_t
) -> StaticSigningInfo? {
    guard let liveCodeIdentifier = liveCodeIdentity(pid: pid),
          let fileCodeIdentifier = staticCodeIdentity(association.executableURL),
          liveCodeIdentifier == fileCodeIdentifier
    else { return nil }

    return verifiedLauncherHelperAppSigningInfo(association)
}

private func verifiedLauncherHelperAppSigningInfo(
    _ association: VerifiedLauncherHelperAssociation
) -> StaticSigningInfo? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(
        association.appURL as CFURL,
        [],
        &staticCode
    ) == errSecSuccess,
        let staticCode,
        let requirement = verifiedLauncherHelperAppRequirement(association.helper)
    else { return nil }

    guard validateAppBundleResource(
        staticCode,
        resourceURL: association.executableURL,
        requirement: requirement
    ) == errSecSuccess,
          let app = staticSigningInfo(staticCode),
          app.identifier == association.helper.appBundleIdentifier,
          app.teamIdentifier == association.helper.appTeamIdentifier
    else { return nil }
    return app
}

private func verifiedLauncherHelperAppRequirement(
    _ helper: VerifiedLauncherHelper
) -> SecRequirement? {
    let source = """
    identifier "\(helper.appBundleIdentifier)" and \
    anchor apple generic and \
    certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
    certificate leaf[field.1.2.840.113635.100.6.1.13] exists and \
    certificate leaf[subject.OU] = "\(helper.appTeamIdentifier)"
    """
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(
        source as CFString,
        [],
        &requirement
    ) == errSecSuccess else { return nil }
    return requirement
}

private func staticCodeIdentity(_ url: URL) -> Data? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode,
          SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess
    else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any]
    else { return nil }
    return dictionary[kSecCodeInfoUnique] as? Data
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

private final class ApprovalPanelDragView: NSView {
    override func mouseDown(with event: NSEvent) {
        window?.performDrag(with: event)
    }
}

private struct ApprovalPanelDragRegion: NSViewRepresentable {
    func makeNSView(context: Context) -> ApprovalPanelDragView { ApprovalPanelDragView() }
    func updateNSView(_ nsView: ApprovalPanelDragView, context: Context) {}
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
    targetPID: pid_t? = nil,
    signing: SigningInfo,
    scriptApproval: ScriptApproval?,
    blessing: BlessedScriptPromptContext? = nil,
    launcher: LauncherIdentity?,
    launcherFallbackPath: String,
    automaticApprovalExplanation: String?,
    accessLevel: String? = nil,
    temporaryGrantCandidate: TemporaryAccessGrantCandidate? = nil,
    temporaryGrantUnavailableReason: String? = nil,
    allowsPersistentApproval: Bool = false,
    persistentApprovalLabel: String = "Always Allow",
    classification: SecretGateRequestClassification? = nil,
    cancellation: ApprovalCancellation? = nil,
    compact: Bool = false
) -> ApprovalDecision {
    guard cancellation?.isCanceled != true else { return .canceled }
    let receivedAt = Date()
    let requester = approvalPromptRequester(launcher: launcher, fallback: launcherFallbackPath)
    let processSecurity = approvalProcessSecurity(
        request: request,
        gateClientPID: pid,
        gateClientPath: callerPath,
        targetPID: targetPID,
        launcher: launcher
    )
    let content = ApprovalPromptContent(
        requesterName: requester.name,
        requesterIconPath: requester.iconPath,
        command: approvalPromptCommand(request),
        commandPath: escapedSecurityPath(approvalCommandPath(request)),
        title: request.title,
        detail: request.detail,
        automaticApprovalExplanation: automaticApprovalExplanation,
        operation: classification.map(operationClassificationTitle),
        accessLevel: accessLevel,
        temporaryGrantUnavailableReason: temporaryGrantUnavailableReason,
        cwd: escapedSecurityPath(request.cwd),
        keys: approvalPromptSecretNames(
            requested: request.keys,
            blessed: blessing?.script.keys ?? []
        ),
        blessing: blessing,
        processSecurity: processSecurity,
        sections: approvalPromptSections(
            request: request,
            callerPath: callerPath,
            pid: pid,
            signing: signing,
            scriptApproval: scriptApproval,
            launcher: launcher,
            processSecurity: processSecurity,
            receivedAt: receivedAt
        )
    )
    let usesIPhoneApproval = PhoneApprovalCoordinator.shared.isEnabled
    let usesTouchIDApproval = TouchIDApproval.isEnabled
    var decision = ApprovalDecision.canceled
    var hasDecision = false
    var remoteRequestID: UUID?
    var completedBeforeModal = false
    let maximumHeight = NSScreen.main?.visibleFrame.height ?? 660
    let panel = makeApprovalPanel()
    panel.contentView = NSHostingView(
        rootView: ApprovalPromptView(
            content: content,
            maximumHeight: maximumHeight,
            allowsPersistentApproval: allowsPersistentApproval,
            temporaryGrantCandidate: temporaryGrantCandidate,
            persistentApprovalLabel: persistentApprovalLabel,
            usesIPhoneApproval: usesIPhoneApproval,
            usesTouchIDApproval: usesTouchIDApproval,
            compact: compact,
            decide: {
                guard !hasDecision else { return }
                hasDecision = true
                decision = $0
                if usesIPhoneApproval, let remoteRequestID {
                    PhoneApprovalCoordinator.shared.cancel(remoteRequestID)
                }
                #if !DEBUG
                if decision == .approved || decision == .alwaysApproved {
                    PostHogTelemetry.shared.captureExplicitApproval()
                }
                #endif
                NSApp.stopModal()
            }
        )
    )
    if usesIPhoneApproval {
        do {
            let phoneRequest = try PhoneApprovalRequest(
                macName: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
                launcher: content.requesterName,
                tool: autoApprovalToolName(request),
                command: content.command,
                cwd: content.cwd,
                secretNames: request.keys.sorted(),
                reason: automaticApprovalExplanation
                    ?? request.detail
                    ?? request.title
                    ?? "Human Approval is required.",
                risks: phoneApprovalRisks(
                    request: request,
                    classification: classification,
                    hasSecurityWarning: automaticApprovalExplanation != nil || blessing != nil
                ),
                details: content.sections.map { section in
                    ApprovalDetailSection(
                        title: section.title,
                        rows: section.rows.map { .init(label: $0.label, value: $0.value) }
                    )
                },
                temporaryAccessGrantScope: temporaryGrantCandidate.map { candidate in
                    "\(candidate.launcherName), \(candidate.authorizationGateName), and \(candidate.scope.agentTaskContext.provider.taskLabel) \(candidate.scope.agentTaskContext.abbreviatedID)"
                }
            )
            remoteRequestID = phoneRequest.id
            try PhoneApprovalCoordinator.shared.submit(phoneRequest) { result in
                guard !hasDecision else { return }
                hasDecision = true
                decision = switch result {
                case .approved: .approved
                case .denied: .denied
                case .temporaryWriteAccess: .temporaryWriteAccess
                case .canceled: .canceled
                }
                if NSApp.modalWindow === panel {
                    NSApp.stopModal()
                } else {
                    completedBeforeModal = true
                }
            }
        } catch {
            return .denied
        }
    }
    guard cancellation?.observe({ [weak panel] in
        if let remoteRequestID { PhoneApprovalCoordinator.shared.cancel(remoteRequestID) }
        guard let panel, NSApp.modalWindow === panel else { return }
        NSApp.stopModal()
    }) != false else { return .canceled }
    defer {
        cancellation?.stopObserving()
    }
    fitApprovalPanel(panel, maximumHeight: maximumHeight, animate: false)
    panel.center()
    panel.orderFrontRegardless()
    if !completedBeforeModal { NSApp.runModal(for: panel) }
    panel.orderOut(nil)
    return terminalApprovalDecision(decision, cancellation: cancellation)
}

private func phoneApprovalRisks(
    request: ApprovalRequest,
    classification: SecretGateRequestClassification?,
    hasSecurityWarning: Bool
) -> [ApprovalRisk] {
    if hasSecurityWarning { return [.securityWarning] }
    switch classification {
    case .secretDump: return [.secretDisclosure]
    case .unknown: return [.unknown]
    case .readOnly, .localWrite, .update, .mutating: return [.routine]
    case nil where request.op == "list": return [.secretDisclosure]
    case nil where request.op == "inject": return [.unconstrainedSecretApplication]
    case nil: return [.securityWarning]
    }
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
        return (appDisplayName(appURL), appURL.path)
    }
    return (shortAppName(launcher.identifier), launcher.path)
}

private func temporaryAccessGrantLauncherName(
    _ launcher: LauncherIdentity,
    displayName: (URL) -> String = appDisplayName
) -> String {
    appBundleURLs(containing: launcher.path).last.map(displayName)
        ?? approvalPromptRequester(launcher: launcher, fallback: launcher.path).name
}

private func appDisplayName(_ appURL: URL) -> String {
    let bundle = Bundle(url: appURL)
    return bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
        ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
        ?? appURL.deletingPathExtension().lastPathComponent
}

private func prettyShellCommand(target: String, args: [String]) -> String {
    ([target] + args).map(shellQuote).enumerated().map { index, word in
        if args.isEmpty { return word }
        return index == 0 ? "\(word) \\" : "  \(word)" + (index == args.count ? "" : " \\")
    }.joined(separator: "\n")
}

private func approvalPromptCommand(_ request: ApprovalRequest, scriptPath: String? = nil) -> String {
    let parts = authorizationCommandParts(request, scriptPath: scriptPath)
    let resolvedScript = scriptPath ?? resolvedShebangScriptPath(request)
    let invokedScript = resolvedScript.flatMap { path in
        request.args.first { !$0.hasPrefix("/") && standardizedPath($0, cwd: request.cwd) == path }
    }
    return ([invokedScript ?? parts.tool] + parts.arguments).map(shellQuote).joined(separator: " ")
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
    processSecurity: ApprovalProcessSecurity,
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
                let source = request.selectedSecretValues.source(for: key)
                let display = switch source {
                case .global: "Global Value"
                case .projectDirectory(let path): escapedSecurityPath(path)
                case nil: "(missing)"
                }
                return ApprovalPromptRow(key, display)
            }
        ), at: 1)
    }

    let chain = processSecurity.nodes.isEmpty
        ? approvalProcessChain(pid: pid)
        : processChainLabel(paths: processSecurity.nodes.map(\.path))
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
    let command: String
    let commandPath: String
    let title: String?
    let detail: String?
    let automaticApprovalExplanation: String?
    let operation: String?
    let accessLevel: String?
    let temporaryGrantUnavailableReason: String?
    let cwd: String
    let keys: String
    let blessing: BlessedScriptPromptContext?
    let processSecurity: ApprovalProcessSecurity
    let sections: [ApprovalPromptSection]
}

private extension ApprovalProcessPosture {
    var presentation: (title: String, image: String, color: Color) {
        switch self {
        case .meetsRequirements:
            ("Meets requirements", "checkmark.shield.fill", .green)
        case .needsAttention:
            ("Needs attention", "exclamationmark.shield.fill", .orange)
        case .doesNotMeetRequirements:
            ("Does not meet requirements", "xmark.shield.fill", .red)
        }
    }
}

private extension ApprovalProcessSecurityNode {
    var isLauncher: Bool { roles.contains("Verified Launcher") }
    var isTarget: Bool {
        roles.contains { $0.hasPrefix("Target") || $0.hasPrefix("Secret recipient") }
    }
    var displayRoles: String {
        roles.map { $0 == "Verified Gate Client" ? "Gate Client" : $0 }
            .joined(separator: " • ")
    }
    var details: String {
        [
            "\(displayRoles): \(name.isEmpty ? path : name)",
            "Path: \(escapedSecurityPath(path))",
            pid.map { "PID: \($0)" },
            "Status: \(posture.presentation.title)",
            explanation,
        ]
        .compactMap(\.self)
        .joined(separator: "\n")
    }
}

private extension ApprovalProcessSecurity {
    var launcher: ApprovalProcessSecurityNode? { nodes.first(where: \.isLauncher) }
    var target: ApprovalProcessSecurityNode? { nodes.first(where: \.isTarget) }
    var middleNodes: [ApprovalProcessSecurityNode] {
        Array(nodes.filter { !$0.isLauncher && !$0.isTarget }.reversed())
    }
}

private func approvalPromptDetails(_ sections: [ApprovalPromptSection]) -> String {
    sections.map { section in
        ([section.title] + section.rows.map { "\($0.label): \($0.value)" })
            .joined(separator: "\n")
    }
    .joined(separator: "\n\n")
}

private struct ApprovalPromptInfoButton: View {
    let title: String
    let details: String
    @State private var isPresented = false

    var body: some View {
        Button { isPresented.toggle() } label: {
            Image(systemName: "info.circle")
                .font(.body)
                .frame(width: 24, height: 24)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(details)
        .accessibilityLabel(title)
        .accessibilityHint("Shows \(title.lowercased())")
        .popover(isPresented: $isPresented, arrowEdge: .trailing) {
            ScrollView {
                Text(details)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
            .frame(width: 380, height: 280)
        }
    }
}

private let approvalPromptRoleWidth: CGFloat = 112
private let approvalPromptToolWidth: CGFloat = 170
private let approvalPromptColumnSpacing: CGFloat = 10

private struct ApprovalPromptPathView: View {
    let path: String

    var body: some View {
        Text(path)
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.tertiary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .help(path)
    }
}

private struct ApprovalPromptHeaderView: View {
    let content: ApprovalPromptContent

    private var details: String {
        [content.processSecurity.launcher?.details, approvalPromptDetails(content.sections)]
            .compactMap { $0?.isEmpty == false ? $0 : nil }
            .joined(separator: "\n\n")
    }

    var body: some View {
        let launcher = content.processSecurity.launcher
        VStack(alignment: .leading, spacing: 12) {
            if launcher != nil {
                Label("Verified Launcher", systemImage: "checkmark.shield")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.purple)
                    .textCase(.uppercase)
            }
            HStack(alignment: .top, spacing: approvalPromptColumnSpacing) {
                HStack(spacing: 14) {
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([
                            URL(fileURLWithPath: content.requesterIconPath),
                        ])
                    } label: {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: content.requesterIconPath))
                            .resizable()
                            .interpolation(.high)
                            .frame(width: 56, height: 56)
                            .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Reveal \(content.requesterName) in Finder")
                    .help("Reveal in Finder")
                    VStack(alignment: .leading, spacing: 4) {
                        Text(content.requesterName)
                            .font(.title3.weight(.semibold))
                            .lineLimit(2)
                            .help(content.requesterName)
                        Text(URL(fileURLWithPath: content.requesterIconPath).lastPathComponent)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(
                    width: approvalPromptRoleWidth + approvalPromptColumnSpacing + approvalPromptToolWidth,
                    alignment: .leading
                )
                ApprovalPromptPathView(path: escapedSecurityPath(launcher?.path ?? content.requesterIconPath))
                ApprovalPromptInfoButton(
                    title: "Request details",
                    details: details.isEmpty ? "No additional request details." : details
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ApprovalPromptProcessSecurityView: View {
    let processSecurity: ApprovalProcessSecurity

    private var nodes: [ApprovalProcessSecurityNode] {
        processSecurity.middleNodes + (processSecurity.target.map { [$0] } ?? [])
    }

    private var details: String {
        nodes.map(\.details).joined(separator: "\n\n")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text("Execution Chain")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                ApprovalPromptInfoButton(
                    title: "Execution chain details",
                    details: details.isEmpty ? "No process details available." : details
                )
                .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            ScrollView(.horizontal) {
                HStack(alignment: .top, spacing: 12) {
                    ForEach(Array(nodes.enumerated()), id: \.element.id) { index, node in
                        if index > 0 {
                            Image(systemName: "arrow.right")
                                .foregroundStyle(.secondary)
                                .padding(.top, 9)
                                .accessibilityHidden(true)
                        }
                        ApprovalPromptProcessNodeView(node: node)
                    }
                }
            }
            .scrollIndicators(.hidden)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Process path from Verified Launcher to Target")
    }
}

private struct ApprovalPromptProcessNodeView: View {
    let node: ApprovalProcessSecurityNode

    var body: some View {
        let presentation = node.posture.presentation
        VStack(spacing: 6) {
            HStack(spacing: 8) {
                Text(node.name.isEmpty ? node.path : node.name)
                    .font(.system(.headline, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if node.isAutomicVaultSigned,
                   let imageURL = Bundle.main.url(forResource: "NSMenuItem", withExtension: "png"),
                   let image = NSImage(contentsOf: imageURL)
                {
                    Image(nsImage: image)
                        .renderingMode(.template)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 10, height: 12)
                        .help("Signed by Automic Vault")
                        .accessibilityHidden(true)
                }
                if node.posture != .meetsRequirements {
                    Image(systemName: presentation.image)
                        .font(.body)
                        .foregroundStyle(presentation.color)
                        .accessibilityHidden(true)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .frame(maxWidth: .infinity)
            .background(
                Color(nsColor: .controlBackgroundColor).opacity(0.35),
                in: Capsule()
            )
            .overlay {
                Capsule().stroke(.white.opacity(0.1), lineWidth: 1)
            }
            ApprovalPromptPathView(path: escapedSecurityPath(node.path))
        }
        .frame(width: 150)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(
            "\(node.displayRoles), \(node.name), \(presentation.title)\(node.isAutomicVaultSigned ? ", signed by Automic Vault" : "")"
        )
    }
}

private struct ApprovalPromptRequestView: View {
    let content: ApprovalPromptContent

    var body: some View {
        VStack(spacing: 0) {
            ApprovalPromptCommandView(content: content)
                .padding(18)
            Divider()
            ApprovalPromptHeaderView(content: content)
                .padding(18)
            Divider()
            ApprovalPromptProcessSecurityView(processSecurity: content.processSecurity)
                .padding(18)
        }
    }
}

private struct CompactSecretMutationApprovalView: View {
    let content: ApprovalPromptContent

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(content.title ?? "Add or modify this secret?", systemImage: "key.fill")
                .font(.title3.weight(.semibold))
            if let detail = content.detail, !detail.isEmpty {
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(content.keys)
                .font(.system(.callout, design: .monospaced).weight(.medium))
                .textSelection(.enabled)
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
            HStack(spacing: 8) {
                Text("Requested by \(content.requesterName)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer(minLength: 0)
                ApprovalPromptInfoButton(
                    title: "Request details",
                    details: approvalPromptDetails(content.sections)
                )
                .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ApprovalPromptApprovalMenu: View {
    let allowsPersistentApproval: Bool
    let temporaryGrantCandidate: TemporaryAccessGrantCandidate?
    var title = "Approve Once"
    var systemImage: String?
    var persistentApprovalLabel = "Always Allow"
    let decide: (ApprovalDecision) -> Void

    var body: some View {
        Group {
            if hasAlternateActions {
                Menu {
                    Button("Approve Once") { decide(.approved) }
                    if let candidate = temporaryGrantCandidate {
                        Button { decide(.temporaryWriteAccess) } label: {
                            Label("Allow Write Access for 10 Minutes…", systemImage: "clock.badge.checkmark")
                        }
                        .help(
                            "Limited to \(candidate.launcherName), \(candidate.authorizationGateName), and \(candidate.scope.agentTaskContext.provider.taskLabel) \(candidate.scope.agentTaskContext.abbreviatedID)."
                        )
                        .accessibilityLabel(
                            "Allow Write Access for 10 minutes for \(candidate.scope.agentTaskContext.provider.taskLabel) \(candidate.scope.agentTaskContext.abbreviatedID)"
                        )
                    }
                    if allowsPersistentApproval {
                        Button(persistentApprovalLabel) { decide(.alwaysApproved) }
                    }
                } label: {
                    buttonLabel
                } primaryAction: {
                    decide(.approved)
                }
                .accessibilityLabel("\(title) and more approval options")
                .accessibilityHint("Use the menu for temporary or persistent access options when available")
            } else {
                Button {
                    decide(.approved)
                } label: {
                    buttonLabel
                }
                .accessibilityLabel(title)
            }
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .tint(.blue)
        .frame(maxWidth: .infinity)
        .keyboardShortcut(.defaultAction)
    }

    private var hasAlternateActions: Bool {
        temporaryGrantCandidate != nil || allowsPersistentApproval
    }

    @ViewBuilder private var buttonLabel: some View {
        if let systemImage {
            Label(title, systemImage: systemImage)
                .frame(maxWidth: .infinity)
        } else {
            Text(title)
                .frame(maxWidth: .infinity)
        }
    }
}

private struct ApprovalPromptView: View {
    let content: ApprovalPromptContent
    var maximumHeight: CGFloat? = nil
    var allowsPersistentApproval = false
    let temporaryGrantCandidate: TemporaryAccessGrantCandidate?
    var persistentApprovalLabel = "Always Allow"
    var usesIPhoneApproval = false
    var usesTouchIDApproval = false
    var compact = false
    let decide: (ApprovalDecision) -> Void
    @State private var isAuthenticatingWithTouchID = false

    var body: some View {
        VStack(spacing: 18) {
            ScrollView {
                VStack(spacing: 16) {
                    if compact {
                        CompactSecretMutationApprovalView(content: content)
                    } else {
                        ApprovalPromptRequestView(content: content)
                            .layoutPriority(-1)

                        if content.title?.isEmpty == false || content.detail?.isEmpty == false {
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
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }

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
                }
            }
            .scrollIndicators(.visible)
            .defaultScrollAnchor(.top)
            .layoutPriority(1)

            if let reason = content.temporaryGrantUnavailableReason {
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if usesIPhoneApproval {
                VStack(spacing: 10) {
                    HStack(spacing: 10) {
                        Image(systemName: "iphone")
                            .symbolRenderingMode(.hierarchical)
                            .foregroundStyle(.purple)
                        Text("Waiting for iPhone Approval")
                            .font(.headline)
                    }
                    Text(usesTouchIDApproval
                        ? "Approve on iPhone or with fresh Touch ID on this Mac."
                        : "Approve this request on your iPhone.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            } else if usesTouchIDApproval {
                Text("Fresh Touch ID is required for every Approval on this Mac.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            if usesTouchIDApproval {
                HStack(spacing: 12) {
                    Button(usesIPhoneApproval ? "Cancel Request" : "Deny", role: .cancel) {
                        decide(.denied)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
                    .keyboardShortcut(.cancelAction)
                    ApprovalPromptApprovalMenu(
                        allowsPersistentApproval: allowsPersistentApproval,
                        temporaryGrantCandidate: temporaryGrantCandidate,
                        title: isAuthenticatingWithTouchID ? "Waiting for Touch ID…" : "Approve with Touch ID",
                        systemImage: "touchid",
                        decide: authenticateWithTouchID
                    )
                    .disabled(isAuthenticatingWithTouchID || !TouchIDApproval.isAvailable)
                }
            } else if usesIPhoneApproval {
                Button("Cancel Request", role: .cancel) { decide(.denied) }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .keyboardShortcut(.cancelAction)

                Text("This Mac cannot approve while iPhone Approval is enabled.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                HStack(alignment: .top, spacing: 18) {
                    Button("Deny", role: .cancel) { decide(.denied) }
                        .buttonStyle(.bordered)
                        .controlSize(.large)
                        .frame(maxWidth: .infinity)
                        .keyboardShortcut(.cancelAction)

                    VStack(spacing: 6) {
                        ApprovalPromptApprovalMenu(
                            allowsPersistentApproval: allowsPersistentApproval,
                            temporaryGrantCandidate: temporaryGrantCandidate,
                            persistentApprovalLabel: persistentApprovalLabel,
                            decide: decide
                        )
                        Text(compact
                            ? "This Approval applies only to this secret change."
                            : "Review the request details before allowing access.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            if allowsPersistentApproval {
                Text(persistentApprovalLabel == "Allow for Session"
                    ? "Session approval expires when this Proxy Session ends"
                    : "Manage this Verified Launcher's Access Level in Automic Vault.")
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(22)
        .frame(maxHeight: maximumHeight)
        .frame(width: compact ? 420 : 680)
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
        .overlay(alignment: .top) {
            ApprovalPanelDragRegion()
                .frame(maxWidth: .infinity)
                .frame(height: 18)
                .overlay {
                    Text("AUTOMIC VAULT")
                        .font(.caption2.weight(.semibold))
                        .tracking(1.6)
                        .foregroundStyle(.tertiary)
                        .allowsHitTesting(false)
                }
                .padding(.top, 3)
                .accessibilityHidden(true)
        }
        .contentShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
    }

    private func authenticateWithTouchID(_ decision: ApprovalDecision) {
        isAuthenticatingWithTouchID = true
        TouchIDApproval.authenticate(
            reason: "Approve this exact Automic Vault request"
        ) { approved in
            isAuthenticatingWithTouchID = false
            if approved { decide(decision) }
        }
    }
}

private func approvalPromptCapabilitySummary(_ script: BlessedScript) -> String {
    let summary = script.capabilities.sorted(by: { $0.key < $1.key })
        .map { "\($0.key): \($0.value.title)" }
        .joined(separator: " • ")
    return summary.isEmpty ? "(none)" : summary
}

private func approvalPromptSecretNames(requested: [String], blessed: [String]) -> String {
    Set(requested + blessed).sorted().joined(separator: ", ")
}

private struct ApprovalPromptCommandView: View {
    let content: ApprovalPromptContent

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Authorization Request")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            VStack(alignment: .leading, spacing: 16) {
                Text(content.command)
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .help(content.command)
                if let blessing = content.blessing {
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Label("Blessed script authority", systemImage: "checkmark.seal.fill")
                            .font(.headline)
                            .foregroundStyle(.green)
                        Spacer(minLength: 0)
                        Text(blessing.explanation)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.trailing)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    if let operation = content.operation {
                        ApprovalPromptInlineMeta(
                            label: "Operation",
                            value: operation,
                            systemImage: "list.bullet"
                        )
                    }
                    if let accessLevel = content.accessLevel {
                        ApprovalPromptInlineMeta(
                            label: "Access Level",
                            value: accessLevel,
                            systemImage: "shield.lefthalf.filled"
                        )
                    }
                    ApprovalPromptInlineMeta(
                        label: "Secret Names",
                        value: content.keys,
                        systemImage: "key"
                    )
                    ApprovalPromptInlineMeta(
                        label: "Working Directory",
                        value: content.cwd,
                        systemImage: "folder"
                    )
                    ApprovalPromptInlineMeta(
                        label: "Full Path",
                        value: content.commandPath,
                        systemImage: "terminal"
                    )
                    if let blessing = content.blessing {
                        ApprovalPromptInlineMeta(
                            label: "Capabilities",
                            value: approvalPromptCapabilitySummary(blessing.script),
                            systemImage: "checkmark.seal"
                        )
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                Color(nsColor: .textBackgroundColor).opacity(0.45),
                in: RoundedRectangle(cornerRadius: 10, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(.white.opacity(0.1), lineWidth: 1)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ApprovalPromptInlineMeta: View {
    let label: String
    let value: String
    let systemImage: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: approvalPromptColumnSpacing) {
            Image(systemName: systemImage)
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 125, alignment: .leading)
            Text(value.isEmpty ? "(none)" : value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .help(value.isEmpty ? "(none)" : value)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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

private func temporaryAccessGrantUsageText(_ grant: TemporaryAccessGrantSnapshot) -> String {
    let uses = grant.useCount == 1 ? "1 use" : "\(grant.useCount) uses"
    return "Write Access: \(uses) · Last used \(grant.lastUsedAt.formatted(date: .omitted, time: .standard))"
}

private func temporaryAccessGrantMenuTitle(
    _ grant: TemporaryAccessGrantSnapshot,
    wallNow: Date,
    monotonicNow: TimeInterval
) -> String {
    let remaining = temporaryAccessGrantRemainingText(
        grant.remaining(wallNow: wallNow, monotonicNow: monotonicNow)
    )
    let countdown = grant.isCountdownSuspended ? "\(remaining) suspended" : remaining
    return "\(grant.launcherName) → \(grant.authorizationGateName) · \(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID) · \(countdown) · \(temporaryAccessGrantUsageText(grant)) — End"
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
    let addTenMinutes: (UUID) -> Void
    let end: (UUID) -> Void
    let setCountdownSuspended: (UUID, Bool) -> Void
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Label("TEMPORARY WRITE ACCESS", systemImage: "exclamationmark.shield.fill")
                .font(.caption.weight(.semibold))
                .tracking(1.1)
                .foregroundStyle(.orange)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .accessibilityLabel(grants.allSatisfy { $0.isCountdownSuspended }
                    ? "Temporary Write Access is suspended"
                    : "Warning: Temporary Write Access is active")

            Divider()

            ForEach(Array(grants.enumerated()), id: \.element.id) { index, grant in
                TemporaryAccessGrantRow(
                    grant: grant,
                    remaining: grant.remaining(wallNow: wallNow, monotonicNow: monotonicNow),
                    addTenMinutes: { addTenMinutes(grant.id) },
                    end: { end(grant.id) },
                    setCountdownSuspended: { setCountdownSuspended(grant.id, $0) }
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
    let addTenMinutes: () -> Void
    let end: () -> Void
    let setCountdownSuspended: (Bool) -> Void

    private var countdownStatus: String {
        let remainingText = "\(temporaryAccessGrantRemainingText(remaining)) remaining"
        return grant.isCountdownSuspended
            ? "\(remainingText) · Write Access suspended"
            : remainingText
    }

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
                Text("\(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID) · \(countdownStatus)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                Text(temporaryAccessGrantUsageText(grant))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                "\(grant.launcherName), \(grant.authorizationGateName), \(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID), \(countdownStatus), \(temporaryAccessGrantUsageText(grant))"
            )

            ControlGroup {
                Button("End", action: end)
                    .accessibilityLabel(
                        "End temporary Write Access for \(grant.launcherName), \(grant.scope.agentTaskContext.provider.taskLabel) \(grant.scope.agentTaskContext.abbreviatedID)"
                    )
                Menu {
                    Button("Add 10 Minutes", action: addTenMinutes)
                    Divider()
                    Button(grant.isCountdownSuspended
                        ? "Resume Write Access"
                        : "Pause Write Access"
                    ) {
                        setCountdownSuspended(!grant.isCountdownSuspended)
                    }
                } label: {
                    Label("Temporary Write Access options", systemImage: "chevron.down")
                        .labelStyle(.iconOnly)
                }
                .menuIndicator(.hidden)
                .accessibilityHint("Opens options to add time or pause Write Access")
            }
            .controlSize(.small)
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
    let credentialMutationRequest = SecretMutation.terraformDelete(
        account: terraformCredentialSecretName("registry.example"),
        hostname: "registry.example"
    ).approvalRequest(callerPath: "/usr/local/bin/av", requestCWD: "/tmp/project")
    guard credentialMutationRequest.cwd == "/tmp/project" else { return 1 }

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

private func runKeychainPersistenceSelfCheck() -> Int32 {
    let service = "com.automicvault.self-check.\(UUID().uuidString)"
    let account = "KEYCHAIN_SELF_CHECK"
    let value = UUID().uuidString
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecAttrAccessGroup as String: "ZU76A67LGU.com.automicvault",
        kSecUseDataProtectionKeychain as String: true,
    ]
    defer { SecItemDelete(query as CFDictionary) }

    guard saveStoredSecret(
        account: account,
        value: value,
        accessibility: .afterFirstUnlock,
        service: service
    ) == errSecSuccess,
        loadStoredSecret(account: account, service: service) == value,
        storedSecretExists(account: account, service: service)
    else { return 1 }

    var attributesQuery = query
    attributesQuery[kSecReturnAttributes as String] = true
    attributesQuery[kSecMatchLimit as String] = kSecMatchLimitOne
    var attributesResult: CFTypeRef?
    guard SecItemCopyMatching(attributesQuery as CFDictionary, &attributesResult) == errSecSuccess,
          let attributes = attributesResult as? [String: Any],
          attributes[kSecAttrAccessible as String] as? String
              == kSecAttrAccessibleAfterFirstUnlock as String,
          deleteStoredSecret(account: account, service: service) == errSecSuccess,
          !storedSecretExists(account: account, service: service)
    else { return 1 }
    return 0
}

@MainActor
private func runApprovalSelfCheck() -> Int32 {
    let helperSigning = SigningInfo(identifier: "com.automicvault", teamIdentifier: "TEAM")
    var selfIdentity = AVProcessIdentity()
    guard av_process_identity(getpid(), &selfIdentity), liveSigningInfo(pid: getpid()) != nil else {
        return 1
    }
    var reusedIdentity = selfIdentity
    reusedIdentity.start_usec &+= 1
    guard sameProcessIdentity(selfIdentity, selfIdentity),
          !sameProcessIdentity(selfIdentity, reusedIdentity)
    else { return 1 }
    guard let liveUse = liveSecretUseProcess(pid: getpid(), identity: selfIdentity),
          liveSecretUseProcessIsLive(liveUse),
          !liveSecretUseProcessIsLive(LiveSecretUseProcess(
              pid: liveUse.pid,
              startUsec: liveUse.startUsec &+ 1,
              effectiveUserID: liveUse.effectiveUserID,
              auditSessionID: liveUse.auditSessionID
          ))
    else { return 1 }
    let reusedDockerPID = CredentialHelperParent(
        pid: getpid(),
        startUsec: selfIdentity.start_usec &+ 1,
        euid: selfIdentity.euid,
        target: pathString(selfIdentity),
        arguments: []
    )
    guard liveSigningInfo(for: reusedDockerPID) == nil else { return 1 }
    let targetRuntimeRequest = ApprovalRequest(
        op: "inject",
        keys: ["TEST_SECRET"],
        target: "/bin/zsh",
        args: [],
        cwd: "/tmp",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: nil,
        scriptData: nil,
        tool: nil,
        title: nil,
        detail: nil,
        selectedSecretValues: SelectedSecretValues(values: [
            "TEST_SECRET": StoredSecretValue(
                source: .global,
                keychainAccount: "TEST_SECRET",
                accessibility: .whenUnlocked,
                keychainProperties: []
            ),
        ])
    )
    guard processEnvironmentValueSelfCheck() else {
        print("bounded peer environment self-check failed")
        return 2
    }
    guard automaticTargetRuntimeProtection(
        request: targetRuntimeRequest,
        decision: "Approved",
        approvalSource: "Auto"
    ) != nil,
    automaticTargetRuntimeProtection(
        request: targetRuntimeRequest,
        decision: "Approved",
        approvalSource: "Manual"
    ) == nil,
    !makeApprovalPanel().isMovableByWindowBackground
    else { return 1 }
    guard supportsVarlockProtocol(1),
          !supportsVarlockProtocol(0),
          !supportsVarlockProtocol(2)
    else { return 1 }
    guard isTrustedMenuHelperCaller(
        path: "/Applications/Automic Vault.app/Contents/MacOS/AutomicVaultMenubar",
        signing: helperSigning
    ), !isTrustedMenuHelperCaller(path: "/tmp/av", signing: helperSigning)
    else { return 1 }
    let varlockSigning = SigningInfo(
        identifier: "com.automicvault.varlock-plugin-helper",
        teamIdentifier: "TEAM"
    )
    guard isTrustedVarlockPluginHelperCaller(
        path: "/Applications/Automic Vault.app/Contents/Resources/AutomicVaultVarlockPlugin",
        signing: varlockSigning
    ), !isTrustedVarlockPluginHelperCaller(path: "/tmp/av", signing: varlockSigning)
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
    guard cancellation.isCanceled,
          !cancellation.observe({}),
          terminalApprovalDecision(.canceled, cancellation: nil) == .interrupted,
          terminalApprovalDecision(.canceled, cancellation: cancellation) == .canceled,
          terminalApprovalDecision(.approved, cancellation: nil) == .approved
    else { return 1 }

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
    let promptProcessSecurity = ApprovalProcessSecurity(nodes: [
        ApprovalProcessSecurityNode(
            pid: 40,
            path: "/Applications/Example.app/Contents/MacOS/Example",
            roles: ["Verified Launcher"],
            posture: .meetsRequirements,
            explanation: "Valid code signature; Hardened Runtime",
            isAutomicVaultSigned: false
        ),
        ApprovalProcessSecurityNode(
            pid: 41,
            path: "/opt/homebrew/bin/gh",
            roles: ["Secret recipient", "Verified Gate Client"],
            posture: .meetsRequirements,
            explanation: "Valid code signature; Hardened Runtime",
            isAutomicVaultSigned: true
        ),
    ])
    let promptContent = ApprovalPromptContent(
        requesterName: requester.name,
        requesterIconPath: requester.iconPath,
        command: "gh auth token",
        commandPath: "/opt/homebrew/bin/gh",
        title: "GitHub token requested",
        detail: "gh needs the GitHub token",
        automaticApprovalExplanation: automaticApprovalExplanation,
        operation: operationClassificationTitle(.unknown),
        accessLevel: SecretGateProtection.noAccess.title,
        temporaryGrantUnavailableReason: "10-minute Write Access excludes Unknown operations.",
        cwd: "/tmp",
        keys: "GH_TOKEN_GITHUB_COM",
        blessing: promptBlessing,
        processSecurity: promptProcessSecurity,
        sections: []
    )
    let collapsedPrompt = NSHostingView(
        rootView: ApprovalPromptView(
            content: promptContent,
            temporaryGrantCandidate: nil,
            decide: { _ in }
        )
    )
    collapsedPrompt.layoutSubtreeIfNeeded()
    let collapsedHeight = collapsedPrompt.fittingSize.height
    let compactSize = NSHostingView(
        rootView: ApprovalPromptView(
            content: promptContent,
            temporaryGrantCandidate: nil,
            compact: true,
            decide: { _ in }
        )
    ).fittingSize
    func containsDragRegion(_ view: NSView) -> Bool {
        view is ApprovalPanelDragView || view.subviews.contains(where: containsDragRegion)
    }
    let constrainedHeight = NSHostingView(
        rootView: ApprovalPromptView(
            content: ApprovalPromptContent(
                requesterName: requester.name,
                requesterIconPath: requester.iconPath,
                command: Array(repeating: "  --long-option \\", count: 100).joined(separator: "\n"),
                commandPath: "/opt/homebrew/bin/gh",
                title: nil,
                detail: nil,
                automaticApprovalExplanation: nil,
                operation: nil,
                accessLevel: nil,
                temporaryGrantUnavailableReason: nil,
                cwd: "/tmp",
                keys: "GH_TOKEN_GITHUB_COM",
                blessing: nil,
                processSecurity: promptProcessSecurity,
                sections: []
            ),
            maximumHeight: 500,
            temporaryGrantCandidate: nil,
            decide: { _ in }
        )
    ).fittingSize.height
    guard prettyShellCommand(target: "/bin/echo", args: ["hello world", "it's-ok"]) == """
    /bin/echo \\
      'hello world' \\
      'it'\\''s-ok'
    """,
          prettyShellCommand(target: "/bin/echo", args: []) == "/bin/echo",
          promptProcessSecurity.launcher?.pid == 40,
          promptProcessSecurity.target?.pid == 41,
          promptProcessSecurity.middleNodes.isEmpty,
          promptBlessing.script.capabilities["gh"] == .readOnly,
          approvalPromptCapabilitySummary(promptBlessing.script)
            == "gh: Read Only • stripe: Write Access",
          approvalPromptSecretNames(
              requested: ["PUBLISH_TOKEN", "AWS_ACCESS_KEY_ID"],
              blessed: ["PUBLISH_TOKEN", "AWS_SECRET_ACCESS_KEY"]
          ) == "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, PUBLISH_TOKEN",
          requester.name == "Vaultty",
          requester.iconPath == "/Applications/Vaultty.app",
          unverifiedRequester.name == "vaultty-sessiond",
          unverifiedRequester.iconPath == "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond",
          cliRequester.name == "/opt/homebrew/bin/gh — Team ID: TEAM",
          cliRequester.iconPath == "/opt/homebrew/bin/gh",
          automaticApprovalExplanation.contains("ChatGPT contains signed app resources"),
          automaticApprovalExplanation.contains("Approval is required to fail closed"),
          containsDragRegion(collapsedPrompt),
          collapsedHeight > 0,
          compactSize.width == 420,
          compactSize.height < collapsedHeight,
          SecretMutation.save(
              account: "TEST_SECRET",
              value: "value",
              accessibility: .whenUnlocked
          ).usesCompactApproval,
          !SecretMutation.delete(account: "TEST_SECRET").usesCompactApproval,
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
    let hardenedPosture = approvalProcessPosture(
        signing: unbundledSigning,
        mutableCode: nil
    )
    let nodePosture = approvalProcessPosture(
        signing: unbundledSigning,
        mutableCode: mutableCodeExplanation(path: "/opt/homebrew/bin/node")
    )
    let unsafePosture = approvalProcessPosture(
        signing: pythonSigning,
        mutableCode: mutableCodeExplanation(path: "/opt/homebrew/bin/python3")
    )
    let unsignedPosture = approvalProcessPosture(
        signing: nil,
        mutableCode: mutableCodeExplanation(path: "/opt/homebrew/bin/node")
    )
    let repeatedNodeProcesses = [
        ApprovalProcessIdentity(pid: 41, path: "/opt/homebrew/bin/node", execution: nil),
        ApprovalProcessIdentity(pid: 42, path: "/opt/homebrew/bin/node", execution: nil),
    ]
    let parentlessVaulttyLauncher = launcherIdentity(
        pid: 43,
        path: "/Applications/Vaultty.app/Contents/Helpers/vaultty-sessiond",
        signing: vaulttySigning,
        appSigning: { _ in vaulttyAppSigning },
        bundleExecutableURL: { _ in URL(fileURLWithPath: vaulttySigning.mainExecutable) }
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
        },
        bundleExecutableURL: { _ in URL(fileURLWithPath: nestedMenuSigning.mainExecutable) }
    )
    guard parentlessVaulttyLauncher?.designatedRequirement == vaulttyAppSigning.designatedRequirement,
          vaulttyBridgeLauncher?.designatedRequirement == vaulttyAppSigning.designatedRequirement,
          nestedLaunchers.map(\.identifier) == ["dev.mxcl.pmm.menu", "dev.mxcl.pmm"],
          launcherAncestorStartPIDs(detachedCaller) == [43],
          hardenedPosture.0 == .meetsRequirements,
          isAutomicVaultSigned(unbundledSigning, teamIdentifier: "TEAM"),
          !isAutomicVaultSigned(unbundledSigning, teamIdentifier: "OTHER"),
          !isAutomicVaultSigned(pythonSigning, teamIdentifier: "unknown"),
          nodePosture.0 == .needsAttention,
          nodePosture.1.contains("mutable JavaScript"),
          unsafePosture.0 == .doesNotMeetRequirements,
          unsignedPosture.0 == .doesNotMeetRequirements,
          unsignedPosture.1.contains("Code signature could not be verified"),
          approvalTargetPID(
              explicitPID: 42,
              dockerPID: nil,
              targetPath: "/opt/homebrew/bin/node",
              identities: repeatedNodeProcesses
          ) == 42,
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

private func runApprovalProcessExecutionSelfCheck() -> Int32 {
    var identity = AVProcessIdentity()
    guard av_process_identity(getpid(), &identity) else { return 1 }
    identity.pidversion = 0
    identity.audit_session_id = 0
    var reusedIdentity = identity
    reusedIdentity.start_usec &+= 1
    guard let execution = approvalProcessExecution(pid: getpid(), identity: identity),
          execution.pidVersion == nil,
          execution.auditSessionID == nil,
          approvalProcessExecutionIsLive(execution),
          approvalProcessExecution(pid: getpid(), identity: reusedIdentity) == nil,
          retainedProcessExecution(pid: getpid(), identity: identity) == nil
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
    let bundledCodex = LiveSigningInfo(
        identifier: codexVerifiedLauncherHelper.helperSigningIdentifier,
        teamIdentifier: codexVerifiedLauncherHelper.helperTeamIdentifier,
        designatedRequirement: #"identifier "codex" and anchor apple generic"#,
        mainExecutable: "/Applications/ChatGPT.app/Contents/Resources/codex",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let chatGPTURL = URL(fileURLWithPath: "/Applications/ChatGPT.app")
    let codexAssociation = verifiedLauncherHelperAssociation(
        path: bundledCodex.mainExecutable,
        signing: bundledCodex,
        containingAppURLs: [chatGPTURL],
        configuration: VerifiedLauncherHelperConfiguration(),
        bundleIdentifier: { _ in codexVerifiedLauncherHelper.appBundleIdentifier }
    )
    let disabledCodexAssociation = verifiedLauncherHelperAssociation(
        path: bundledCodex.mainExecutable,
        signing: bundledCodex,
        containingAppURLs: [chatGPTURL],
        configuration: VerifiedLauncherHelperConfiguration(
            disabledHelperIDs: [codexVerifiedLauncherHelper.id]
        ),
        bundleIdentifier: { _ in codexVerifiedLauncherHelper.appBundleIdentifier }
    )
    let wrongPathCodexHelper = VerifiedLauncherHelper(
        id: "wrong-path-codex",
        name: "Wrong Codex",
        appName: "ChatGPT",
        appBundleIdentifier: codexVerifiedLauncherHelper.appBundleIdentifier,
        appTeamIdentifier: codexVerifiedLauncherHelper.appTeamIdentifier,
        helperSigningIdentifier: codexVerifiedLauncherHelper.helperSigningIdentifier,
        helperTeamIdentifier: codexVerifiedLauncherHelper.helperTeamIdentifier,
        relativePath: "Contents/Resources/not-codex"
    )
    let pathBoundCodexHelper = VerifiedLauncherHelper(
        id: "path-bound-codex",
        name: "Codex CLI",
        appName: "ChatGPT",
        appBundleIdentifier: codexVerifiedLauncherHelper.appBundleIdentifier,
        appTeamIdentifier: codexVerifiedLauncherHelper.appTeamIdentifier,
        helperSigningIdentifier: codexVerifiedLauncherHelper.helperSigningIdentifier,
        helperTeamIdentifier: codexVerifiedLauncherHelper.helperTeamIdentifier,
        relativePath: "Contents/Resources/codex"
    )
    let pathBoundCodexAssociation = verifiedLauncherHelperAssociation(
        path: bundledCodex.mainExecutable,
        signing: bundledCodex,
        containingAppURLs: [chatGPTURL],
        helpers: [wrongPathCodexHelper, pathBoundCodexHelper],
        configuration: VerifiedLauncherHelperConfiguration(),
        bundleIdentifier: { _ in codexVerifiedLauncherHelper.appBundleIdentifier }
    )
    let xcodeGit = LiveSigningInfo(
        identifier: "com.apple.git",
        teamIdentifier: "Software Signing",
        designatedRequirement: #"identifier "com.apple.git" and anchor apple"#,
        mainExecutable: "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: false
    )
    let xcodeHelperAssociation = verifiedLauncherHelperAssociation(
        path: xcodeGit.mainExecutable,
        signing: xcodeGit,
        containingAppURLs: [URL(fileURLWithPath: "/Applications/Xcode.app")],
        configuration: VerifiedLauncherHelperConfiguration(),
        bundleIdentifier: { _ in "com.apple.dt.Xcode" }
    )
    let installedCodexValidation: Bool = {
        let executableURL = URL(
            fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex"
        )
        guard FileManager.default.fileExists(atPath: executableURL.path) else { return true }
        guard let signing = executableSigningInfo(path: executableURL.path),
              let association = verifiedLauncherHelperAssociation(
                  path: executableURL.path,
                  signing: signing,
                  helpers: [codexVerifiedLauncherHelper],
                  configuration: VerifiedLauncherHelperConfiguration()
              ),
              verifiedLauncherHelperAppSigningInfo(association) != nil
        else { return false }
        let outsideResource = VerifiedLauncherHelperAssociation(
            helper: codexVerifiedLauncherHelper,
            appURL: association.appURL,
            executableURL: URL(fileURLWithPath: "/bin/ls")
        )
        return verifiedLauncherHelperAppSigningInfo(outsideResource) == nil
    }()
    let installedMainAppValidation = [
        URL(fileURLWithPath: "/Applications/ChatGPT.app"),
        URL(fileURLWithPath: "/Applications/Xcode.app"),
    ].allSatisfy {
        !FileManager.default.fileExists(atPath: $0.path) || staticSigningInfo(url: $0) != nil
    }
    let avGPG = LiveSigningInfo(
        identifier: "com.automicvault.av-gpg",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "com.automicvault.av-gpg" and anchor apple generic"#,
        mainExecutable: "/Applications/Automic Vault.app/Contents/MacOS/av-gpg",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let portalHelper = LiveSigningInfo(
        identifier: "dev.mxcl.portal.sessiond",
        teamIdentifier: "TEAM",
        designatedRequirement: #"identifier "dev.mxcl.portal.sessiond" and anchor apple generic"#,
        mainExecutable: "/Applications/Portal Session Helper.app/Contents/MacOS/portal-sessiond",
        isAdHoc: false,
        runtimeProtection: .hardened,
        isDeveloperID: true
    )
    let portalHelperSigning = StaticSigningInfo(
        identifier: portalHelper.identifier,
        teamIdentifier: portalHelper.teamIdentifier,
        designatedRequirement: portalHelper.designatedRequirement
    )
    let portalGPGLaunchers = launcherIdentities(
        pid: 45,
        path: avGPG.mainExecutable,
        signing: avGPG,
        appSigning: { _ in nil }
    ) + launcherIdentities(
        pid: 44,
        path: portalHelper.mainExecutable,
        signing: portalHelper,
        appSigning: { _ in portalHelperSigning }
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
          targetedAppResourceValidationAvailable,
          codexAssociation?.helper == codexVerifiedLauncherHelper,
          codexAssociation?.appURL == chatGPTURL,
          pathBoundCodexAssociation?.helper == pathBoundCodexHelper,
          disabledCodexAssociation == nil,
          xcodeHelperAssociation == nil,
          installedCodexValidation,
          installedMainAppValidation,
          let liveBundleFallback,
          liveBundleFallback.isStandalone,
          liveBundleFallback.identifier == bundledDeveloperID.identifier,
          temporaryAccessGrantLauncherName(liveBundleFallback) == "Example",
          temporaryAccessGrantLauncherName(
              liveBundleFallback,
              displayName: { _ in "ChatGPT" }
          ) == "ChatGPT",
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
          executionOrigin(
              among: portalGPGLaunchers,
              callerPID: 46,
              ancestorFallbackPath: portalHelper.mainExecutable
          )?.identifier == portalHelper.identifier,
          !appBundleMatchesMainExecutable(
              URL(fileURLWithPath: "/Applications/Xcode.app"),
              executablePaths: ["/Applications/Xcode.app/Contents/Developer/usr/bin/git"],
              bundleExecutableURL: { _ in
                  URL(fileURLWithPath: "/Applications/Xcode.app/Contents/MacOS/Xcode")
              }
          ),
          appBundleMatchesMainExecutable(
              URL(fileURLWithPath: "/Applications/Xcode.app"),
              executablePaths: ["/Applications/Xcode.app/Contents/MacOS/Xcode"],
              bundleExecutableURL: { _ in
                  URL(fileURLWithPath: "/Applications/Xcode.app/Contents/MacOS/Xcode")
              }
          ),
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

private func runTerraformCredentialSelfCheck() -> Int32 {
    guard terraformRequestClassification(["validate"]) == .readOnly,
          terraformRequestClassification(["fmt"]) == .localWrite,
          terraformRequestClassification(["fmt", "-check"]) == .readOnly,
          terraformRequestClassification(["plan"]) == .localWrite,
          terraformRequestClassification(["providers", "mirror", "/tmp/providers"]) == .localWrite,
          terraformRequestClassification(["apply"]) == .mutating,
          terraformRequestClassification(["state", "pull"]) == .readOnly,
          terraformRequestClassification(["state", "push"]) == .mutating,
          terraformRequestClassification(["future-command"]) == .unknown,
          normalizeTerraformHostname("App.Terraform.IO") == "app.terraform.io",
          normalizeTerraformHostname("app.terraform.io:443") == nil,
          terraformCredentialSecretName("app.terraform.io")
              == "TERRAFORM_HOST_CREDENTIAL_E3078C0B1928EE1F19EBBD26404E4C6B5FC1D639629DB0345330C0ECA3FEFC42",
          parseTerraformCredential(#"{"token":"secret"}"#) == "secret",
          parseTerraformCredential(#"{"token":"secret","future":true}"#) == nil
    else { return 1 }
    return 0
}

private func runAliyunCredentialSelfCheck() -> Int32 {
    guard aliyunRequestClassification(["sts", "GetCallerIdentity"]) == .readOnly,
          aliyunRequestClassification(["ecs", "DescribeInstances"]) == .unknown,
          normalizeAliyunProfile("prod") == "prod",
          normalizeAliyunProfile(" prod") == nil,
          normalizeAliyunProfile("prod\n") == nil,
          aliyunCredentialSecretName("prod")
              == "ALIYUN_PROFILE_CREDENTIAL_6754AF9632A2745E85C293E5AAC0863370D9BD3330B9938C00CADFD215227D77",
          parseAliyunCredential(
              #"{"mode":"AK","access_key_id":"id","access_key_secret":"secret"}"#
          ),
          parseAliyunCredential(
              #"{"mode":"StsToken","access_key_id":"id","access_key_secret":"secret","sts_token":"token"}"#
          ),
          !parseAliyunCredential(
              #"{"mode":"AK","access_key_id":"id","access_key_secret":"secret","future":true}"#
          )
    else { return 1 }
    return 0
}

private func runWakaTimeCredentialSelfCheck() -> Int32 {
    let valid = ["waka_01234567", "89ab", "4cde", "8fab", "0123456789ab"].joined(separator: "-")
    let bare = ["01234567", "89ab", "4cde", "bfab", "0123456789ab"].joined(separator: "-")
    let wrongVersion = ["01234567", "89ab", "3cde", "8fab", "0123456789ab"].joined(separator: "-")
    guard wakatimeRequestClassification(["--today"]) == .readOnly,
          wakatimeRequestClassification(["--today-goal=123"]) == .readOnly,
          wakatimeRequestClassification(["--entity", "/tmp/main.rs"]) == .mutating,
          wakatimeRequestClassification(["--sync-offline-activity=100"]) == .mutating,
          wakatimeRequestClassification(["--future-operation"]) == .unknown,
          validWakaTimeAPIKey(valid),
          validWakaTimeAPIKey(bare),
          !validWakaTimeAPIKey(wrongVersion)
    else { return 1 }
    return 0
}

private func runKubectlCredentialSelfCheck() -> Int32 {
    let canonical = #"{"kind":"token","server":"https://example.com/","user":"prod"}"#
    guard let scope = parseKubectlCredentialScope(canonical),
          scope.kind == "token",
          scope.server == "https://example.com/",
          scope.user == "prod",
          scope.secretName
              == "KUBECTL_USER_CREDENTIAL_6754AF9632A2745E85C293E5AAC0863370D9BD3330B9938C00CADFD215227D77",
          validKubectlCredential(#"{"token":"secret"}"#, kind: "token"),
          !validKubectlCredential(#"{"token":"secret","future":true}"#, kind: "token"),
          parseKubectlCredentialScope(
              #"{"kind":"token","server":"https://user@example.com/","user":"prod"}"#
          ) == nil,
          parseKubectlCredentialScope(
              #"{"kind":"token","server":"http://example.com/","user":"prod"}"#
          ) == nil
    else { return 1 }
    return 0
}

private func runOxideCredentialSelfCheck() -> Int32 {
    let canonical = #"{"host":"https://oxide.example","profile":"prod"}"#
    guard oxideRequestClassification(["auth", "status"]) == .readOnly,
          oxideRequestClassification(["auth", "login"]) == .mutating,
          oxideRequestClassification(["auth", "future"]) == .unknown,
          oxideRequestClassification(["--profile", "prod", "project", "list"]) == .readOnly,
          oxideRequestClassification(["project", "list"]) == .readOnly,
          oxideRequestClassification(["project", "create"]) == .mutating,
          oxideRequestClassification(["future-command"]) == .unknown,
          oxideRequestClassification(["future-command", "list"]) == .unknown,
          normalizeOxideHost("https://OXIDE.example/") == "https://oxide.example",
          normalizeOxideHost("https://oxide.example:443/") == "https://oxide.example",
          normalizeOxideHost("https://oxide.example/path") == nil,
          let scope = parseOxideCredentialScope(canonical),
          scope.profile == "prod",
          scope.host == "https://oxide.example",
          scope.secretName
              == "OXIDE_PROFILE_TOKEN_7B278C7242C18FEA05959821606917F993F33A93618CDF5207AD0DCE95F9BCF0",
          parseOxideCredential("secret") == "secret",
          parseOxideCredential("secret\n") == nil,
          parseOxideCredentialScope(#"{"profile":"prod","host":"https://oxide.example"}"#) == nil
    else { return 1 }
    return 0
}

private func runGoatCredentialSelfCheck() -> Int32 {
    let canonical = #"{"did":"did:plc:abc","pds":"https://pds.example"}"#
    guard goatRequestClassification(["account", "check-auth"]) == .readOnly,
          goatRequestClassification(["record", "create"]) == .mutating,
          goatRequestClassification(["future"]) == .unknown,
          let scope = parseGoatCredentialScope(canonical),
          scope.secretName
              == "GOAT_AUTH_SESSION_DA212E2E592DBA2E786AE246CCA580593FCB2A3CFC3641CE1BB9B5D3391963CA",
          parseGoatCredential(
              #"{"password":"pass","access_token":"access","session_token":"refresh"}"#
          ) != nil,
          parseGoatCredential(
              #"{"password":"@av","access_token":"access","session_token":"refresh"}"#
          ) == nil,
          parseGoatCredential(#"{"password":"pass","access_token":"access"}"#) == nil
    else { return 1 }
    return 0
}

private func runRailwayCredentialSelfCheck() -> Int32 {
    let canonical = #"{"environment":"production","host":"railway.com"}"#
    guard railwayRequestClassification(["status"]) == .readOnly,
          railwayRequestClassification(["deploy"]) == .mutating,
          railwayRequestClassification(["run", "env"]) == .secretDump,
          railwayRequestClassification(["variables", "list", "--json"]) == .secretDump,
          railwayRequestClassification(["future"]) == .unknown,
          let scope = parseRailwayCredentialScope(canonical),
          scope.secretName
              == "RAILWAY_AUTH_DC8779025AEA8CB5CBCE119C0F3B0CD38FF99203728B2ED45EAAC18F0F891B1A",
          parseRailwayCredential(
              #"{"token":null,"accessToken":"access","refreshToken":"refresh"}"#
          ) != nil,
          parseRailwayCredential(
              #"{"token":"legacy","accessToken":null,"refreshToken":null}"#
          ) != nil,
          parseRailwayCredential(
              #"{"token":"legacy","accessToken":"access","refreshToken":null}"#
          ) == nil
    else { return 1 }
    return 0
}

private func runOrdercliCredentialSelfCheck() -> Int32 {
    let scope = #"{"provider":"foodora"}"#
    let credential = #"{"access_token":"access","refresh_token":"refresh","client_secret":"","pending_mfa_token":"","cookies_by_host":{"example.com":"cookie"}}"#
    guard ordercliRequestClassification(["foodora", "history"]) == .readOnly,
          ordercliRequestClassification(["--version"]) == .readOnly,
          ordercliRequestClassification(["-v"]) == .readOnly,
          ordercliRequestClassification(["version"]) == .readOnly,
          ordercliRequestClassification(["foodora", "login"]) == .mutating,
          ordercliRequestClassification(["foodora", "future"]) == .unknown,
          parseOrdercliCredentialScope(scope)?.secretName == ordercliCredentialSecretName,
          parseOrdercliCredential(credential) == credential,
          parseOrdercliCredential(
              #"{"access_token":"access","refresh_token":"refresh","client_secret":"","pending_mfa_token":"","cookies_by_host":null,"future":true}"#
          ) == nil
    else { return 1 }
    return 0
}

private func runOpenHueCredentialSelfCheck() -> Int32 {
    let scope = #"{"bridge":"192.0.2.10"}"#
    guard openhueRequestClassification(["get", "light"]) == .readOnly,
          openhueRequestClassification(["--help"]) == .readOnly,
          openhueRequestClassification(["config", "--key", "secret"]) == .localWrite,
          openhueRequestClassification(["set", "light"]) == .mutating,
          openhueRequestClassification(["future"]) == .unknown,
          parseOpenHueCredentialScope(scope)?.bridge == "192.0.2.10",
          parseOpenHueCredential("application-key") == "application-key",
          parseOpenHueCredential("@av") == nil
    else { return 1 }
    return 0
}

private func runPlumberCredentialSelfCheck() -> Int32 {
    let credential = #"{"token":"streamdal-token","connections":{"kafka":{"sasl_password":"password"}}}"#
    guard plumberRequestClassification(["--version"]) == .readOnly,
          plumberRequestClassification(["read", "kafka"]) == .mutating,
          plumberRequestClassification(["future"]) == .unknown,
          parsePlumberCredentialScope(plumberCredentialScope)?.secretName == plumberCredentialSecretName,
          parsePlumberCredential(credential) == credential,
          parsePlumberCredential(#"{"automic_vault":"plumber-config-v1"}"#) == nil
    else { return 1 }
    return 0
}

private func runUAACredentialSelfCheck() -> Int32 {
    let scope = #"{"store":"contexts"}"#
    let credential = #"{"targets":{"url:https://uaa.example":{"context":{"access_token":"access","refresh_token":"refresh"}}}}"#
    guard uaaRequestClassification(["targets"]) == .readOnly,
          uaaRequestClassification(["context"]) == .secretDump,
          uaaRequestClassification(["create-client"]) == .mutating,
          uaaRequestClassification(["curl", "/Users"]) == .unknown,
          parseUAACredentialScope(scope)?.secretName == uaaCredentialSecretName,
          parseUAACredential(credential) == credential,
          parseUAACredential(#"{"targets":{"target":{"context":{"access_token":"@av"}}}}"#) == nil
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
    func request(
        startUsec: UInt64 = 456,
        args: [String] = ["repo", "view"],
        keys: [String] = ["GH_TOKEN_GITHUB_COM"],
        policy: AuthorizationDecisionReusePolicy = .reusable
    ) -> AuthorizationDecisionReuseRequest {
        AuthorizationDecisionReuseRequest(
            client: AuthorizationClientExecution(
                pid: 123,
                pidVersion: 7,
                startUsec: startUsec,
                effectiveUserID: 501,
                auditSessionID: 42
            ),
            callerPath: "/opt/homebrew/bin/gh",
            signingIdentifier: "gh",
            signingTeamIdentifier: "TEAM",
            operation: "keys",
            secretNames: keys,
            target: "/opt/homebrew/Cellar/gh-cli/2.94.0/bin/gh",
            arguments: args,
            workingDirectory: "/tmp",
            replaceExistingEnvironment: true,
            allowMissingSecrets: false,
            environmentConflicts: [],
            shebangScript: nil,
            scriptData: nil,
            snapshotIncompatibleInterpreter: nil,
            tool: "gh",
            title: nil,
            detail: nil,
            credentialScope: nil,
            credentialParent: nil,
            selectedSecretValues: SelectedSecretValues(values: [:]),
            policy: policy
        )
    }
    let approval = request()
    let denial = request(
        args: ["auth", "token"],
        keys: ["GH_TOKEN_GITHUB_COM_MXCL"]
    )
    let temporaryGrant = request(startUsec: 987, args: ["repo", "create"])
    let interrupted = request(startUsec: 988, args: ["repo", "delete"])
    let fallbackAfterDenial = request(args: ["auth", "token"])
    let freshApproval = request(startUsec: 989, policy: .freshApprovalRequired)
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(.approved, for: approval, now: Date(timeIntervalSince1970: 100))
    cache.remember(.approved, for: freshApproval, now: Date(timeIntervalSince1970: 100))
    guard cache.decision(for: approval, now: Date(timeIntervalSince1970: 200)) == .approved,
          cache.decision(for: freshApproval, now: Date(timeIntervalSince1970: 200)) == nil,
          cache.decision(for: fallbackAfterDenial, now: Date(timeIntervalSince1970: 200)) == nil,
          cache.decision(for: request(startUsec: 789), now: Date(timeIntervalSince1970: 200)) == nil
    else {
        return 1
    }
    cache.remember(.denied, for: denial, now: Date(timeIntervalSince1970: 200))
    cache.remember(
        .temporaryAccessGrant,
        for: temporaryGrant,
        now: Date(timeIntervalSince1970: 200)
    )
    cache.remember(.interrupted, for: interrupted, now: Date(timeIntervalSince1970: 200))
    guard cache.decision(for: denial, now: Date(timeIntervalSince1970: 300)) == .denied,
          cache.decision(for: fallbackAfterDenial, now: Date(timeIntervalSince1970: 300)) == .denied,
          cache.decision(for: temporaryGrant, now: Date(timeIntervalSince1970: 300)) == nil,
          cache.decision(for: interrupted, now: Date(timeIntervalSince1970: 300)) == nil,
          cache.decision(for: request(startUsec: 789), now: Date(timeIntervalSince1970: 300)) == nil,
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
        effectiveUserID: geteuid(),
        auditSessionID: 10,
        codeIdentity: Data([1, 2, 3])
    )
    let crossUserHerdr = RetainedProcessExecution(
        pid: herdr.pid,
        pidVersion: herdr.pidVersion,
        startUsec: herdr.startUsec,
        effectiveUserID: geteuid() == 0 ? 1 : 0,
        auditSessionID: herdr.auditSessionID,
        codeIdentity: herdr.codeIdentity
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
        [herdr, crossUserHerdr],
        at: .secretGate("gh"),
        launcher: launcher,
        isLive: { _ in true }
    )
    guard store.match(
        at: .secretGate("gh"),
        in: chains,
        isLive: { _ in true }
    )?.launcher.designatedRequirement == launcher.designatedRequirement,
    store.match(
        at: .secretGate("gh"),
        in: [[RetainedProcessChainNode(
            pid: crossUserHerdr.pid,
            path: "/usr/local/bin/herdr",
            execution: crossUserHerdr
        )]],
        isLive: { _ in true }
    ) == nil,
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
    guard AppDelegate().statusMenuTrackingSelfCheck() else { return 1 }
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
    let relativeScriptRequest = ApprovalRequest(
        op: "inject",
        keys: [],
        target: "/bin/bash",
        args: ["./scripts/publish.sh"],
        cwd: "/Users/mxcl/src/av",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        envConflicts: [],
        shebangScript: "/Users/mxcl/src/av/scripts/publish.sh",
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
        addTenMinutes: { _ in },
        end: { _ in },
        setCountdownSuspended: { _, _ in }
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
          ).contains("Codex → AWS Authorization Gate · Codex task 11111111 · 10:00 · Write Access: 1 use · Last used "),
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
          approvalPromptCommand(relativeScriptRequest) == "./scripts/publish.sh",
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

@MainActor
private final class PasteProbeTextView: NSTextView {
    private(set) var didPaste = false

    override func paste(_ sender: Any?) {
        didPaste = true
        NSApp.stop(nil)
    }
}

@MainActor
private func installTextEditingShortcuts() {
    NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
        let action: Selector? = switch event.charactersIgnoringModifiers?.lowercased() {
        case "c": #selector(NSText.copy(_:))
        case "v": #selector(NSText.paste(_:))
        default: nil
        }
        guard event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
              let responder = event.window?.firstResponder,
              let action,
              NSApp.sendAction(action, to: responder, from: event)
        else { return event }
        return nil
    }
}

@MainActor
private func runTextPasteSelfCheck() -> Int32 {
    _ = NSApplication.shared
    installTextEditingShortcuts()
    let window = NSPanel(
        contentRect: NSRect(x: 0, y: 0, width: 200, height: 100),
        styleMask: .titled,
        backing: .buffered,
        defer: false
    )
    let textView = PasteProbeTextView(frame: window.contentView?.bounds ?? .zero)
    window.contentView?.addSubview(textView)
    window.makeKeyAndOrderFront(nil)

    guard window.makeFirstResponder(textView),
          let event = NSEvent.keyEvent(
              with: .keyDown,
              location: .zero,
              modifierFlags: .command,
              timestamp: 0,
              windowNumber: window.windowNumber,
              context: nil,
              characters: "v",
              charactersIgnoringModifiers: "v",
              isARepeat: false,
              keyCode: 9
          )
    else { return 1 }

    NSApp.setActivationPolicy(.accessory)
    NSApp.activate()
    DispatchQueue.main.async {
        NSApp.postEvent(event, atStart: true)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
        NSApp.stop(nil)
    }
    NSApp.run()
    return textView.didPaste ? 0 : 1
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

if CommandLine.arguments.contains("--self-check-approval-process-execution") {
    exit(runApprovalProcessExecutionSelfCheck())
}

if CommandLine.arguments.contains("--self-check-standalone-launchers") {
    exit(runStandaloneLauncherSelfCheck())
}

if CommandLine.arguments.contains("--self-check-secret-mutations") {
    exit(MainActor.assumeIsolated { runSecretMutationSelfCheck() })
}

if CommandLine.arguments.contains("--self-check-keychain-persistence") {
    exit(runKeychainPersistenceSelfCheck())
}

if CommandLine.arguments.contains("--self-check-gh-read-only") {
    exit(runGhReadOnlySelfCheck())
}

if CommandLine.arguments.contains("--self-check-docker-credentials") {
    exit(runDockerCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-terraform-credentials") {
    exit(runTerraformCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-aliyun-credentials") {
    exit(runAliyunCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-wakatime-credentials") {
    exit(runWakaTimeCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-kubectl-credentials") {
    exit(runKubectlCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-oxide-credentials") {
    exit(runOxideCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-goat-credentials") {
    exit(runGoatCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-railway-credentials") {
    exit(runRailwayCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-ordercli-credentials") {
    exit(runOrdercliCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-openhue-credentials") {
    exit(runOpenHueCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-plumber-credentials") {
    exit(runPlumberCredentialSelfCheck())
}

if CommandLine.arguments.contains("--self-check-uaa-credentials") {
    exit(runUAACredentialSelfCheck())
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

if CommandLine.arguments.contains("--self-check-text-paste") {
    exit(MainActor.assumeIsolated { runTextPasteSelfCheck() })
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
