import AppKit
import ServiceManagement
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let toggleStartAtLoginArgument = "--toggle-start-at-login"
    private static let remoteDatabaseRefreshInterval: TimeInterval = 60 * 60
    private var window: NSWindow?
    private let statusStore = NucleusStatusStore()
    private let vaultApprovalStore = VaultApprovalStore()
    private let containmentLogStore = ContainmentLogStore()
    private let keyTransferApprovalStore = KeyTransferApprovalStore()
    private let isotopeApprovalStore = IsotopeApprovalStore()
    private let gateApprovalStore = GateApprovalStore()
    private let dotenvApprovalStore = DotenvApprovalStore()
    private let helperBridge = NukeHelperBridge()
    private lazy var appUpdateCoordinator = AppUpdateCoordinator(statusStore: statusStore)
    private lazy var dotenvFileWatcher = DotenvFileWatcher { [weak self] result in
        self?.postDotenvAutoEncryptionNotification(result)
    }
    private lazy var userNotificationDelegate = AppUserNotificationDelegate { [weak self] in
        self?.showMainWindow()
    }
    #if !DEBUG
    private let postHogTelemetry = PostHogTelemetry.shared
    #endif
    private var openWindowObserver: NSObjectProtocol?
    private var startAtLoginObserver: NSObjectProtocol?
    private var statusSnapshotObserver: NSObjectProtocol?
    private var containmentLogObserver: NSObjectProtocol?
    private var pendingApprovalObserver: NSObjectProtocol?
    private var pendingKeyTransferApprovalObserver: NSObjectProtocol?
    private var pendingIsotopeApprovalObserver: NSObjectProtocol?
    private var pendingGateApprovalObserver: NSObjectProtocol?
    private var pendingDotenvApprovalObserver: NSObjectProtocol?
    private var activeApprovalID: String?
    private var activeKeyTransferApprovalID: String?
    private var activeIsotopeApprovalID: String?
    private var activeGateApprovalID: String?
    private var activeDotenvApprovalID: String?
    private var containmentWindowControllers: [String: ContainmentLogWindowController] = [:]
    private var remoteDatabaseRefreshTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains(Self.toggleStartAtLoginArgument) {
            toggleStartAtLoginFromHelper()
            NSApp.terminate(nil)
            return
        }

        NSApp.mainMenu = makeMainMenu()
        publishStartAtLoginStatus()
        launchMenuBarHelperIfNeeded()
        configureUserNotifications()
        installOpenWindowObserverIfNeeded()
        installStartAtLoginObserverIfNeeded()
        installStatusSnapshotObserverIfNeeded()
        installContainmentLogObserverIfNeeded()
        installVaultApprovalObserverIfNeeded()
        installKeyTransferApprovalObserverIfNeeded()
        installIsotopeApprovalObserverIfNeeded()
        installGateApprovalObserverIfNeeded()
        installDotenvApprovalObserverIfNeeded()
        startRemoteDatabaseRefreshTimer()
        applyDockBadge(snapshot: statusStore.loadSnapshot())
        if hasPendingApprovalOnLaunch() == false {
            showMainWindow()
        }
        appUpdateCoordinator.startAutomaticChecks()
        presentPendingVaultApprovalIfNeeded()
        presentPendingKeyTransferApprovalIfNeeded()
        presentPendingIsotopeApprovalIfNeeded()
        presentPendingGateApprovalIfNeeded()
        presentPendingDotenvApprovalIfNeeded()
    }

    func applicationWillTerminate(_ notification: Notification) {
        denyPendingDotenvApprovalOnTermination()
        denyPendingKeyTransferApprovalOnTermination()
        if let openWindowObserver {
            DistributedNotificationCenter.default().removeObserver(openWindowObserver)
        }
        if let startAtLoginObserver {
            DistributedNotificationCenter.default().removeObserver(startAtLoginObserver)
        }
        if let statusSnapshotObserver {
            DistributedNotificationCenter.default().removeObserver(statusSnapshotObserver)
        }
        if let containmentLogObserver {
            DistributedNotificationCenter.default().removeObserver(containmentLogObserver)
        }
        if let pendingApprovalObserver {
            DistributedNotificationCenter.default().removeObserver(pendingApprovalObserver)
        }
        if let pendingKeyTransferApprovalObserver {
            DistributedNotificationCenter.default().removeObserver(pendingKeyTransferApprovalObserver)
        }
        if let pendingIsotopeApprovalObserver {
            DistributedNotificationCenter.default().removeObserver(pendingIsotopeApprovalObserver)
        }
        if let pendingGateApprovalObserver {
            DistributedNotificationCenter.default().removeObserver(pendingGateApprovalObserver)
        }
        if let pendingDotenvApprovalObserver {
            DistributedNotificationCenter.default().removeObserver(pendingDotenvApprovalObserver)
        }
        dotenvFileWatcher.stop()
        remoteDatabaseRefreshTimer?.invalidate()
        appUpdateCoordinator.stop()
        (window?.contentViewController as? MainWindowController)?
            .applicationWillTerminate()
    }

    private func denyPendingDotenvApprovalOnTermination() {
        guard let approval = dotenvApprovalStore.loadPendingApproval() else { return }
        try? dotenvApprovalStore.saveDecision(
            DotenvApprovalDecision(
                id: approval.id,
                approvalToken: approval.approvalToken,
                approved: false,
                reason: "Automic Vault quit before dotenv approval"
            )
        )
    }

    private func denyPendingKeyTransferApprovalOnTermination() {
        guard let approval = keyTransferApprovalStore.loadPendingApproval() else { return }
        try? keyTransferApprovalStore.saveDecision(
            KeyTransferApprovalDecision(
                id: approval.id,
                approved: false,
                reason: "Automic Vault quit before key transfer approval"
            )
        )
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        guard !flag else { return true }
        showMainWindow()
        return true
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            handleDeepLink(url)
        }
    }

    private func hasPendingApprovalOnLaunch() -> Bool {
        vaultApprovalStore.loadPendingApproval() != nil
            || keyTransferApprovalStore.loadPendingApproval() != nil
            || isotopeApprovalStore.loadPendingApproval() != nil
            || gateApprovalStore.loadPendingApproval() != nil
            || dotenvApprovalStore.loadPendingApproval() != nil
    }

    private func makeMainMenu() -> NSMenu {
        let menu = NSMenu(title: L10n.string("Main Menu"))
        menu.addItem(makeAppMenuItem())
        menu.addItem(makeEditMenuItem())
        menu.addItem(makeWindowMenuItem())
        return menu
    }

    private func makeAppMenuItem() -> NSMenuItem {
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "Automic Vault")
        let appName = ProcessInfo.processInfo.processName

        appMenu.addItem(
            withTitle: L10n.format("About %@", appName),
            action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
            keyEquivalent: ""
        )
        appMenu.addItem(.separator())
        appMenu.addItem(
            withTitle: L10n.format("Hide %@", appName),
            action: #selector(NSApplication.hide(_:)),
            keyEquivalent: "h"
        )
        let hideOthers = appMenu.addItem(
            withTitle: L10n.string("Hide Others"),
            action: #selector(NSApplication.hideOtherApplications(_:)),
            keyEquivalent: "h"
        )
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(
            withTitle: L10n.string("Show All"),
            action: #selector(NSApplication.unhideAllApplications(_:)),
            keyEquivalent: ""
        )
        appMenu.addItem(.separator())
        appMenu.addItem(
            withTitle: L10n.format("Quit %@", appName),
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )

        appItem.submenu = appMenu
        return appItem
    }

    private func makeEditMenuItem() -> NSMenuItem {
        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: L10n.string("Edit"))

        editMenu.addItem(
            withTitle: L10n.string("Undo"),
            action: Selector(("undo:")),
            keyEquivalent: "z"
        )
        let redoItem = editMenu.addItem(
            withTitle: L10n.string("Redo"),
            action: Selector(("redo:")),
            keyEquivalent: "z"
        )
        redoItem.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(.separator())
        editMenu.addItem(
            withTitle: L10n.string("Cut"),
            action: #selector(NSText.cut(_:)),
            keyEquivalent: "x"
        )
        editMenu.addItem(
            withTitle: L10n.string("Copy"),
            action: #selector(NSText.copy(_:)),
            keyEquivalent: "c"
        )
        editMenu.addItem(
            withTitle: L10n.string("Paste"),
            action: #selector(NSText.paste(_:)),
            keyEquivalent: "v"
        )
        editMenu.addItem(
            withTitle: L10n.string("Select All"),
            action: #selector(NSText.selectAll(_:)),
            keyEquivalent: "a"
        )

        editItem.submenu = editMenu
        return editItem
    }

    private func makeWindowMenuItem() -> NSMenuItem {
        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: L10n.string("Window"))

        let refreshItem = windowMenu.addItem(
            withTitle: L10n.string("Refresh"),
            action: #selector(refreshPackages(_:)),
            keyEquivalent: "r"
        )
        refreshItem.target = self
        #if DEBUG
        let fakeUpdateItem = windowMenu.addItem(
            withTitle: L10n.string("Run Fake Update"),
            action: #selector(runFakeUpdate(_:)),
            keyEquivalent: "u"
        )
        fakeUpdateItem.keyEquivalentModifierMask = [.command, .shift]
        fakeUpdateItem.target = self
        windowMenu.addItem(.separator())
        #endif
        windowMenu.addItem(
            withTitle: L10n.string("Close"),
            action: #selector(NSWindow.performClose(_:)),
            keyEquivalent: "w"
        )
        windowMenu.addItem(
            withTitle: L10n.string("Minimize"),
            action: #selector(NSWindow.performMiniaturize(_:)),
            keyEquivalent: "m"
        )
        windowMenu.addItem(
            withTitle: L10n.string("Zoom"),
            action: #selector(NSWindow.performZoom(_:)),
            keyEquivalent: ""
        )
        windowItem.submenu = windowMenu
        NSApp.windowsMenu = windowMenu
        return windowItem
    }

    private func startRemoteDatabaseRefreshTimer() {
        guard remoteDatabaseRefreshTimer == nil else { return }
        refreshRemoteDatabase()
        let timer = Timer(
            timeInterval: Self.remoteDatabaseRefreshInterval,
            repeats: true
        ) { [weak self] _ in
            Task { @MainActor in
                self?.refreshRemoteDatabase()
            }
        }
        remoteDatabaseRefreshTimer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    private func refreshRemoteDatabase() {
        helperBridge.refreshRemoteDatabase { result in
            switch result {
            case .success(.completed(let updated)):
                try? self.statusStore.saveRemoteDatabaseRefreshState(.normal)
                if updated {
                    self.statusStore.requestRefresh()
                }
            case .success(.pendingHelperInstallation):
                try? self.statusStore.saveRemoteDatabaseRefreshState(.pendingHelperInstallation)
            case .failure(let error):
                NSLog("remote database refresh failed: %@", error.localizedDescription)
            }
        }
    }

    private func showMainWindow() {
        let wasVisible = window?.isVisible ?? false
        let window = makeOrRestoreMainWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        #if !DEBUG
        if wasVisible == false {
            postHogTelemetry.captureMainWindowOpened()
        }
        #endif
    }

    private func installOpenWindowObserverIfNeeded() {
        guard openWindowObserver == nil else { return }
        openWindowObserver = statusStore.observeOpenMainWindowRequests { [weak self] _ in
            self?.showMainWindow()
        }
    }

    private func installStartAtLoginObserverIfNeeded() {
        guard startAtLoginObserver == nil else { return }
        startAtLoginObserver = statusStore.observeStartAtLoginToggleRequests { [weak self] _ in
            self?.toggleStartAtLoginFromHelper()
        }
    }

    private func installStatusSnapshotObserverIfNeeded() {
        guard statusSnapshotObserver == nil else { return }
        statusSnapshotObserver = statusStore.observeSnapshotChanges { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.applyDockBadge(snapshot: self.statusStore.loadSnapshot())
            }
        }
    }

    private func applyDockBadge(snapshot: NucleusStatusSnapshot) {
        let badgeCount = snapshot.appBadgeCount
        NSApp.dockTile.badgeLabel = badgeCount > 0 ? String(badgeCount) : nil
        NSApp.dockTile.display()
    }

    private func installContainmentLogObserverIfNeeded() {
        guard containmentLogObserver == nil else { return }
        containmentLogObserver = containmentLogStore.observeChanges { [weak self] notification in
            guard let self else { return }
            guard let sessionID = notification.userInfo?[ContainmentLogNotification.sessionIDKey]
                as? String else {
                return
            }
            self.showContainmentWindow(sessionID: sessionID)
        }
    }

    private func installVaultApprovalObserverIfNeeded() {
        guard pendingApprovalObserver == nil else { return }
        pendingApprovalObserver = vaultApprovalStore.observePendingApprovalChanges { [weak self] _ in
            self?.presentPendingVaultApprovalIfNeeded()
        }
    }

    private func installKeyTransferApprovalObserverIfNeeded() {
        guard pendingKeyTransferApprovalObserver == nil else { return }
        pendingKeyTransferApprovalObserver = keyTransferApprovalStore.observePendingApprovalChanges { [weak self] _ in
            self?.presentPendingKeyTransferApprovalIfNeeded()
        }
    }

    private func installIsotopeApprovalObserverIfNeeded() {
        guard pendingIsotopeApprovalObserver == nil else { return }
        pendingIsotopeApprovalObserver = isotopeApprovalStore.observePendingApprovalChanges { [weak self] _ in
            self?.presentPendingIsotopeApprovalIfNeeded()
        }
    }

    private func installGateApprovalObserverIfNeeded() {
        guard pendingGateApprovalObserver == nil else { return }
        pendingGateApprovalObserver = gateApprovalStore.observePendingApprovalChanges { [weak self] _ in
            self?.presentPendingGateApprovalIfNeeded()
        }
    }

    private func installDotenvApprovalObserverIfNeeded() {
        guard pendingDotenvApprovalObserver == nil else { return }
        pendingDotenvApprovalObserver = dotenvApprovalStore.observePendingApprovalChanges { [weak self] _ in
            self?.presentPendingDotenvApprovalIfNeeded()
        }
    }

    @objc private func refreshPackages(_ sender: Any?) {
        (window?.contentViewController as? MainWindowController)?.requestRefresh()
    }

    private func handleDeepLink(_ url: URL) {
        guard let deepLink = AutomicVaultDeepLink(url: url) else {
            return
        }

        let window = makeOrRestoreMainWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        switch deepLink.action {
        case .install(let packageNames):
            (window.contentViewController as? MainWindowController)?
                .requestPackageInstall(packageNames: packageNames)
        }
    }

    #if DEBUG
    @objc private func runFakeUpdate(_ sender: Any?) {
        let window = makeOrRestoreMainWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        (window.contentViewController as? MainWindowController)?.runDebugFakeUpdate()
    }
    #endif

    private func toggleStartAtLoginFromHelper() {
        let service = SMAppService.loginItem(identifier: "com.automicvault.menu-helper")

        do {
            if service.status == .enabled {
                try service.unregister()
            } else {
                try service.register()
            }
        } catch {
            publishStartAtLoginStatus(error: error.localizedDescription)
            return
        }

        if service.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
        publishStartAtLoginStatus()
    }

    private func publishStartAtLoginStatus(error: String? = nil) {
        let service = SMAppService.loginItem(identifier: "com.automicvault.menu-helper")
        let status: StartAtLoginSnapshot.Status
        switch service.status {
        case .enabled:
            status = .enabled
        case .requiresApproval:
            status = .requiresApproval
        case .notFound:
            status = .notFound
        case .notRegistered:
            status = .disabled
        @unknown default:
            status = .unavailable
        }

        try? statusStore.saveStartAtLoginSnapshot(
            StartAtLoginSnapshot(
                status: status,
                updatedAt: Date(),
                lastError: error
            )
        )
    }

    private func presentPendingVaultApprovalIfNeeded() {
        guard let approval = vaultApprovalStore.loadPendingApproval() else {
            activeApprovalID = nil
            return
        }
        guard activeApprovalID != approval.id else { return }
        activeApprovalID = approval.id

        let window: NSWindow
        if let containmentWindow = showContainmentWindow(sessionID: approval.intent.agentID) {
            window = containmentWindow
        } else {
            showMainWindow()
            window = makeOrRestoreMainWindow()
        }
        if NSApp.isActive == false || window.isKeyWindow == false {
            _ = NSApp.requestUserAttention(.criticalRequest)
        }

        let alert = NSAlert()
        alert.messageText = L10n.string("Approve Command Execution")
        alert.informativeText = ""
        alert.alertStyle = .warning
        alert.addButton(withTitle: L10n.string("Approve"))
        alert.addButton(withTitle: L10n.string("Deny"))
        alert.accessoryView = approvalAccessoryView(for: approval)
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            try? self.vaultApprovalStore.saveDecision(
                VaultApprovalDecision(
                    id: approval.id,
                    approved: response == .alertFirstButtonReturn,
                    reason: response == .alertFirstButtonReturn ? nil : "Denied by operator"
                )
            )
            self.activeApprovalID = nil
            DispatchQueue.main.async {
                self.presentPendingVaultApprovalIfNeeded()
            }
        }
    }

    private func presentPendingKeyTransferApprovalIfNeeded() {
        guard let approval = keyTransferApprovalStore.loadPendingApproval() else {
            activeKeyTransferApprovalID = nil
            return
        }
        guard activeKeyTransferApprovalID != approval.id else { return }
        activeKeyTransferApprovalID = approval.id

        let window = makeOrRestoreMainWindow()
        if NSApp.isActive == false || window.isKeyWindow == false {
            _ = NSApp.requestUserAttention(.criticalRequest)
        }
        showMainWindow()

        let alert = NSAlert()
        alert.messageText = L10n.string("Approve Key Transfer")
        alert.informativeText = keyTransferApprovalSummary(for: approval)
        alert.alertStyle = .warning
        alert.addButton(withTitle: L10n.string("Allow"))
        alert.addButton(withTitle: L10n.string("Deny"))
        alert.accessoryView = keyTransferApprovalAccessoryView(for: approval)
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            try? self.keyTransferApprovalStore.saveDecision(
                KeyTransferApprovalDecision(
                    id: approval.id,
                    approved: response == .alertFirstButtonReturn,
                    reason: response == .alertFirstButtonReturn ? nil : "Denied by operator"
                )
            )
            self.activeKeyTransferApprovalID = nil
            DispatchQueue.main.async {
                self.presentPendingKeyTransferApprovalIfNeeded()
            }
        }
    }

    private func presentPendingIsotopeApprovalIfNeeded() {
        guard let approval = isotopeApprovalStore.loadPendingApproval() else {
            activeIsotopeApprovalID = nil
            return
        }
        guard activeIsotopeApprovalID != approval.id else { return }
        activeIsotopeApprovalID = approval.id

        let window = makeOrRestoreMainWindow()
        if NSApp.isActive == false || window.isKeyWindow == false {
            _ = NSApp.requestUserAttention(.criticalRequest)
        }
        showMainWindow()

        let alert = NSAlert()
        alert.messageText = L10n.string("Approve Key Injection")
        alert.informativeText = isotopeApprovalSummary(for: approval)
        alert.alertStyle = .warning
        alert.addButton(withTitle: L10n.string("Allow"))
        alert.addButton(withTitle: L10n.string("Deny"))
        if approval.canAlwaysAllow {
            alert.addButton(withTitle: isotopeAlwaysAllowButtonTitle(for: approval))
        }
        alert.accessoryView = isotopeApprovalAccessoryView(for: approval)
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            if response == .alertThirdButtonReturn, approval.canAlwaysAllow {
                self.rememberIsotopeAlwaysAllow(approval)
                return
            }
            self.saveIsotopeDecision(
                approval: approval,
                approved: response == .alertFirstButtonReturn,
                alwaysAllow: false,
                reason: response == .alertFirstButtonReturn ? nil : "Denied by operator"
            )
        }
    }

    private func isotopeAlwaysAllowButtonTitle(for approval: IsotopeApprovalRequestSnapshot) -> String {
        approval.scriptSha256 == nil
            ? L10n.string("Always Allow")
            : L10n.string("Always Allow for Script SHA")
    }

    private func presentPendingGateApprovalIfNeeded() {
        guard let approval = gateApprovalStore.loadPendingApproval() else {
            activeGateApprovalID = nil
            return
        }
        guard activeGateApprovalID != approval.id else { return }
        activeGateApprovalID = approval.id

        let window = makeOrRestoreMainWindow()
        if NSApp.isActive == false || window.isKeyWindow == false {
            _ = NSApp.requestUserAttention(.criticalRequest)
        }
        showMainWindow()

        let alert = NSAlert()
        alert.messageText = L10n.string("Approve Gate")
        alert.informativeText = approval.message
        alert.alertStyle = .warning
        alert.addButton(withTitle: L10n.string("Approve"))
        alert.addButton(withTitle: L10n.string("Deny"))
        alert.accessoryView = gateApprovalAccessoryView(for: approval)
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            try? self.gateApprovalStore.saveDecision(
                GateApprovalDecision(
                    id: approval.id,
                    approved: response == .alertFirstButtonReturn,
                    reason: response == .alertFirstButtonReturn ? nil : "Denied by operator"
                )
            )
            self.activeGateApprovalID = nil
            DispatchQueue.main.async {
                self.presentPendingGateApprovalIfNeeded()
            }
        }
    }

    private func presentPendingDotenvApprovalIfNeeded() {
        guard let approval = dotenvApprovalStore.loadPendingApproval() else {
            activeDotenvApprovalID = nil
            return
        }
        guard activeDotenvApprovalID != approval.id else { return }
        activeDotenvApprovalID = approval.id
        if let sourceName = approval.automaticExportRejectionSourceName {
            saveDotenvDecision(
                approval,
                approved: false,
                reason: dotenvAutomaticExportRejectionReason(sourceName: sourceName)
            )
            dotenvApprovalStore.postAutomaticExportRejected(sourceName: sourceName)
            return
        }

        let window = makeOrRestoreMainWindow()
        if NSApp.isActive == false || window.isKeyWindow == false {
            _ = NSApp.requestUserAttention(.criticalRequest)
        }
        showMainWindow()

        let alert = NSAlert()
        alert.messageText = L10n.string("Approve Dotenv Keys")
        alert.informativeText = dotenvApprovalSummary(for: approval)
        alert.alertStyle = .warning
        alert.addButton(withTitle: L10n.string("Allow"))
        alert.addButton(withTitle: L10n.string("Deny"))
        alert.accessoryView = dotenvApprovalAccessoryView(for: approval)
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            let approved = response == .alertFirstButtonReturn
            self.completeDotenvApproval(approval, approved: approved)
        }
    }

    private func completeDotenvApproval(
        _ approval: DotenvApprovalRequestSnapshot,
        approved: Bool
    ) {
        guard approved else {
            saveDotenvDecision(approval, approved: false)
            return
        }
        saveDotenvDecision(approval, approved: true)
        helperBridge.dotenvApprovalPolicy { [weak self] result in
            guard let self else { return }
            guard case .success(.rememberApproved) = result else {
                return
            }
            self.helperBridge.rememberDotenvApproval(approval) { _ in
            }
        }
    }

    private func saveDotenvDecision(
        _ approval: DotenvApprovalRequestSnapshot,
        approved: Bool,
        reason: String? = nil
    ) {
        try? dotenvApprovalStore.saveDecision(
            DotenvApprovalDecision(
                id: approval.id,
                approvalToken: approval.approvalToken,
                approved: approved,
                reason: approved ? nil : (reason ?? "Denied by operator")
            )
        )
        if approved {
            dotenvFileWatcher.watch(path: approval.envFilePath)
        }
        activeDotenvApprovalID = nil
        DispatchQueue.main.async {
            self.presentPendingDotenvApprovalIfNeeded()
        }
    }

    private func dotenvAutomaticExportRejectionReason(sourceName: String) -> String {
        "av dotenv export was auto-rejected because it was requested by \(sourceName)"
    }

    private func rememberIsotopeAlwaysAllow(_ approval: IsotopeApprovalRequestSnapshot) {
        helperBridge.rememberIsotopeAlwaysAllow(
            executablePath: approval.executablePath,
            scriptPath: approval.scriptPath,
            scriptSha256: approval.scriptSha256,
            keys: approval.keys
        ) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                try? self.statusStore.saveRemoteDatabaseRefreshState(.normal)
                self.saveIsotopeDecision(
                    approval: approval,
                    approved: true,
                    alwaysAllow: true,
                    reason: nil
                )
            case .failure(let error):
                self.presentIsotopeAlwaysAllowError(error)
                self.activeIsotopeApprovalID = nil
                DispatchQueue.main.async {
                    self.presentPendingIsotopeApprovalIfNeeded()
                }
            }
        }
    }

    private func saveIsotopeDecision(
        approval: IsotopeApprovalRequestSnapshot,
        approved: Bool,
        alwaysAllow: Bool,
        reason: String?
    ) {
        try? isotopeApprovalStore.saveDecision(
            IsotopeApprovalDecision(
                id: approval.id,
                approved: approved,
                alwaysAllow: alwaysAllow,
                reason: reason
            )
        )
        activeIsotopeApprovalID = nil
        DispatchQueue.main.async {
            self.presentPendingIsotopeApprovalIfNeeded()
        }
    }

    private func presentIsotopeAlwaysAllowError(_ error: Error) {
        let alert = NSAlert()
        alert.messageText = L10n.string("Could Not Remember Approval")
        alert.informativeText = error.localizedDescription
        alert.alertStyle = .warning
        alert.runModal()
    }

    private func isotopeApprovalSummary(for approval: IsotopeApprovalRequestSnapshot) -> String {
        ""
    }

    private func keyTransferApprovalSummary(
        for approval: KeyTransferApprovalRequestSnapshot
    ) -> String {
        let source = "\(approval.source.user)@\(approval.source.host)"
        if approval.itemCount == 1 {
            return L10n.format("Import %d Automic Vault key from %@.", approval.itemCount, source)
        }
        return L10n.format("Import %d Automic Vault keys from %@.", approval.itemCount, source)
    }

    private func keyTransferApprovalAccessoryView(
        for approval: KeyTransferApprovalRequestSnapshot
    ) -> NSView {
        let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 560, height: 220))
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .bezelBorder

        let textView = NSTextView(frame: scrollView.bounds)
        textView.isEditable = false
        textView.isRichText = false
        textView.font = UIStyle.monoFont(size: 11, weight: .regular)
        textView.string = keyTransferApprovalDetailText(for: approval)
        scrollView.documentView = textView
        return scrollView
    }

    private func keyTransferApprovalDetailText(
        for approval: KeyTransferApprovalRequestSnapshot
    ) -> String {
        var lines = [
            L10n.string("Source"),
            "\(approval.source.user)@\(approval.source.host)",
            "",
            L10n.string("Working Directory"),
            approval.source.cwd
        ]
        if let sshTarget = approval.source.sshTarget {
            lines.append(contentsOf: ["", L10n.string("SSH Target"), sshTarget])
        }
        lines.append(contentsOf: ["", L10n.string("Items")])
        for item in approval.items {
            var line = keyTransferApprovalItemLabel(for: item)
            if let detail = item.detail, detail.isEmpty == false {
                line += " - \(detail)"
            }
            if item.replacingExisting {
                line += " (\(L10n.string("replaces existing")))"
            }
            lines.append(line)
        }
        if approval.items.contains(where: { $0.replacingExisting }) {
            lines.append(contentsOf: ["", L10n.string("Replacing existing keychain values")])
        }
        return lines.joined(separator: "\n")
    }

    private func keyTransferApprovalItemLabel(for item: KeyTransferApprovalItem) -> String {
        if item.kind == "dotenv" {
            return L10n.format("dotenv private key for %@", item.name)
        }
        return "\(item.kind): \(item.name)"
    }

    private func isotopeApprovalAccessoryView(for approval: IsotopeApprovalRequestSnapshot) -> NSView {
        IsotopeApprovalView(approval: approval)
    }

    private func isotopeParentProcessSummary(
        _ parentProcess: IsotopeParentProcessSnapshot
    ) -> String {
        let name = parentProcess.displayName
            ?? parentProcess.executablePath
            ?? L10n.string("unknown")
        return L10n.format("%@ (pid %d)", name, parentProcess.pid)
    }

    private func isotopeParentProcessDetail(
        _ parentProcess: IsotopeParentProcessSnapshot
    ) -> String {
        let executable = parentProcess.executablePath ?? L10n.string("unknown")
        let name = parentProcess.displayName ?? L10n.string("unknown")
        return [
            L10n.format("PID: %d", parentProcess.pid),
            L10n.format("Name: %@", name),
            L10n.format("Executable: %@", executable)
        ].joined(separator: "\n")
    }

    private func gateApprovalAccessoryView(for approval: GateApprovalRequestSnapshot) -> NSView {
        let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 560, height: 180))
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .bezelBorder

        let textView = NSTextView(frame: scrollView.bounds)
        textView.isEditable = false
        textView.isRichText = false
        textView.font = UIStyle.monoFont(size: 11, weight: .regular)
        textView.string = gateApprovalDetailText(for: approval)
        scrollView.documentView = textView
        return scrollView
    }

    private func gateApprovalDetailText(for approval: GateApprovalRequestSnapshot) -> String {
        [
            L10n.string("Message"),
            approval.message,
            "",
            L10n.string("Working Directory"),
            approval.cwd,
            "",
            L10n.string("Invoked By"),
            isotopeParentProcessDetail(approval.parentProcess)
        ].joined(separator: "\n")
    }

    private func dotenvApprovalSummary(for approval: DotenvApprovalRequestSnapshot) -> String {
        switch approval.mode {
        case .export:
            return L10n.string("Export encrypted dotenv keys into this shell.")
        case .run:
            return L10n.string("Run one command with encrypted dotenv keys.")
        }
    }

    private func dotenvApprovalAccessoryView(for approval: DotenvApprovalRequestSnapshot) -> NSView {
        DotenvApprovalView(approval: approval)
    }

    private func configureUserNotifications() {
        let center = UNUserNotificationCenter.current()
        center.delegate = userNotificationDelegate
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in
        }
    }

    private func postDotenvAutoEncryptionNotification(_ result: DotenvAutoEncryptionResult) {
        let filename = URL(fileURLWithPath: result.filePath).lastPathComponent
        let content = UNMutableNotificationContent()
        content.title = L10n.string("Dotenv keys encrypted")
        content.body = L10n.format(
            "New dotenv entries in %@ were encrypted automatically.",
            filename
        )
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "com.automicvault.dotenv.encrypted.\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    private func approvalAccessoryView(for approval: VaultApprovalRequestSnapshot) -> NSView {
        CommandExecutionApprovalView(approval: approval)
    }

    private func launchMenuBarHelperIfNeeded() {
        guard let helperURL = embeddedMenuBarHelperURL() else { return }
        let helperBundleIdentifier = "com.automicvault.menu-helper"

        if NSRunningApplication.runningApplications(
            withBundleIdentifier: helperBundleIdentifier
        ).isEmpty == false {
            return
        }

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        NSWorkspace.shared.openApplication(
            at: helperURL,
            configuration: configuration
        ) { _, _ in
        }
    }

    private func embeddedMenuBarHelperURL() -> URL? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LoginItems", isDirectory: true)
            .appendingPathComponent("Automic Vault Menu.app", isDirectory: true)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        return url
    }

    @discardableResult
    private func showContainmentWindow(sessionID: String?) -> NSWindow? {
        guard let sessionID, sessionID.isEmpty == false else {
            return nil
        }
        guard let snapshot = containmentLogStore.load(sessionID: sessionID) else {
            return nil
        }

        let controller: ContainmentLogWindowController
        if let existing = containmentWindowControllers[sessionID] {
            controller = existing
            controller.apply(snapshot: snapshot)
        } else {
            controller = ContainmentLogWindowController(snapshot: snapshot)
            containmentWindowControllers[sessionID] = controller
        }

        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        return controller.window
    }

    private func makeOrRestoreMainWindow() -> NSWindow {
        if let window {
            return window
        }

        let controller = MainWindowController(appUpdateCoordinator: appUpdateCoordinator)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1380, height: 877),
            styleMask: [
                .titled,
                .closable,
                .miniaturizable,
                .resizable,
                .fullSizeContentView
            ],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Automic Vault"
        window.backgroundColor = .clear
        window.isOpaque = false
        window.appearance = NSAppearance(named: .darkAqua)
        window.isReleasedWhenClosed = false
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.contentViewController = controller
        window.makeFirstResponder(controller.view)
        self.window = window
        return window
    }
}

private final class AppUserNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    private let openMainWindow: @MainActor () -> Void

    init(openMainWindow: @escaping @MainActor () -> Void) {
        self.openMainWindow = openMainWindow
        super.init()
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        Task { @MainActor [openMainWindow] in
            openMainWindow()
            completionHandler()
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
