import AppKit
import Darwin
import MarkdownUI
import MenubarHelperCore
import Security
import SwiftUI
import UniformTypeIdentifiers

let automaticApprovalFeedbackDefaultsKey = "automaticApprovalFeedback"
let compactAutomaticApprovalNotificationsDefaultsKey = "compactAutomaticApprovalNotifications"
let autoCollapseTemporaryAccessGrantStripDefaultsKey = "autoCollapseTemporaryAccessGrantStrip"
let keepLauncherAccessForDetachedProcessesDefaultsKey = "keepLauncherAccessForDetachedProcesses"
let cliInstallationDidFinish = Notification.Name("AutomicVaultCLIInstallationDidFinish")

let temporaryAccessGrantStripPresentationDidChange = Notification.Name(
    "TemporaryAccessGrantStripPresentationDidChange"
)
private let directAccessDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/direct-secret-access.md#safer-alternatives"
)!
private let launcherBundleDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/signed-cli-launchers.md"
)!
private let choosingAMechanismDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/choosing-a-mechanism.md"
)!
private let detectionAndHardeningDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/domain-language.md#detection-and-hardening"
)!
private let toolHardeningDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/architecture.md#tool-hardening"
)!
private let authorizationGatesDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/README.md#authorization-gates"
)!
private let blessedScriptsDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/README.md#blessed-scripts"
)!
private let secretProxyDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/secret-proxy.md"
)!
private let authorizationHistoryDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/domain-language.md#authorization-history"
)!

enum AutomaticApprovalFeedback: String, CaseIterable, Identifiable {
    case notification
    case menuBarFlash
    case none

    var id: Self { self }

    var title: String {
        switch self {
        case .notification: String(localized: "Show Notification")
        case .none: String(localized: "Show Nothing")
        case .menuBarFlash: String(localized: "Flash Menu Bar")
        }
    }
}

private extension SecretGateProtection {
    func addsAuthority(over current: Self) -> Bool {
        SecretGateRequestClassification.allCases.contains {
            allows($0) && !current.allows($0)
        }
    }
}

private func blessedScriptAccessSummary(
    capabilities: [String: SecretGateProtection],
    inheritsCapabilities: Bool
) -> String {
    let summary = capabilities.sorted { $0.key < $1.key }
        .map { "\($0.key): \($0.value.normalized(forGateID: $0.key).title)" }
        .joined(separator: ", ")
    if inheritsCapabilities {
        return summary.isEmpty
            ? "Inherited from execution context"
            : "\(summary); additional authority inherited from execution context"
    }
    return summary.isEmpty ? "None" : summary
}

private func blessedScriptAccessSummary(_ script: BlessedScript) -> String {
    blessedScriptAccessSummary(
        capabilities: script.capabilities,
        inheritsCapabilities: script.usesCapabilityInheritance
    )
}

struct BlessedScriptReviewRequest: Sendable {
    let path: String
    let declaration: BlessedScriptDeclaration
    let scriptData: Data
    let launcher: BlessedScriptLauncher?
    let previousContents: Data?

    init(
        path: String,
        declaration: BlessedScriptDeclaration,
        scriptData: Data,
        launcher: BlessedScriptLauncher?,
        previousContents: Data? = nil
    ) {
        self.path = path
        self.declaration = declaration
        self.scriptData = scriptData
        self.launcher = launcher
        self.previousContents = previousContents
    }
}

enum BlessedScriptReviewOutcome: Sendable {
    case approved
    case denied
    case failed(String)
}

@MainActor
final class AutomicVaultMainWindowController: NSHostingController<DashboardRootView> {
    private let model = DashboardModel()

    init(checkForUpdates: @escaping () -> Void, requestScan: @escaping () -> Void) {
        super.init(rootView: DashboardRootView(
            model: model,
            checkForUpdates: checkForUpdates,
            requestScan: requestScan
        ))
    }

    @MainActor @preconcurrency required dynamic init?(coder: NSCoder) {
        super.init(coder: coder, rootView: DashboardRootView(
            model: model,
            checkForUpdates: {},
            requestScan: {}
        ))
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        model.reload()
    }

    func reload() {
        model.reload()
    }

    func reloadAccessRequests() {
        model.reloadAccessRequests()
    }

    func updateDetectorFindings(_ findings: [DetectorFinding]) {
        model.updateDetectorFindings(findings)
    }

    func setAvailableUpdateVersion(_ version: String?) {
        model.availableUpdateVersion = version
    }

    func showAccessRequest(id: UUID) {
        model.showAccessRequest(id: id)
    }

    func showSection(_ section: DashboardSection) {
        model.searchText = ""
        model.selectSection(section)
    }

    func showSecretGate(id: String) {
        model.showSecretGate(id: id)
    }

    func showSettings() {
        model.showSettings()
    }

    func reviewBlessing(
        _ request: BlessedScriptReviewRequest,
        completion: @escaping (BlessedScriptReviewOutcome) -> Void
    ) {
        model.reviewBlessing(request, completion: completion)
    }

    override func viewDidDisappear() {
        super.viewDidDisappear()
        model.cancelPendingBlessing()
    }
}

final class AutomicVaultWindow: NSWindow {
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        guard event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
              let key = event.charactersIgnoringModifiers?.lowercased()
        else {
            return super.performKeyEquivalent(with: event)
        }

        switch key {
        case "w":
            performClose(nil)
            return true
        case "h":
            NSApp.hide(nil)
            return true
        case ",":
            guard let controller = contentViewController as? AutomicVaultMainWindowController
            else {
                return super.performKeyEquivalent(with: event)
            }
            controller.showSettings()
            return true
        default:
            return super.performKeyEquivalent(with: event)
        }
    }

    override func cancelOperation(_ sender: Any?) {
        makeFirstResponder(nil)
    }

    override func sendEvent(_ event: NSEvent) {
        if event.type == .leftMouseDown, firstResponder is NSText {
            makeFirstResponder(nil)
        }
        super.sendEvent(event)
    }
}

@MainActor
final class DashboardModel: ObservableObject {
    @Published var selectedSection: DashboardSection = .overview
    @Published private(set) var snapshot = DashboardSnapshot.empty
    @Published private(set) var isReloading = false
    @Published var isAddingSecret = false
    @Published var isRenamingSecret = false
    @Published var isCreatingLauncherBundle = false
    @Published private(set) var isBuildingLauncherBundle = false
    @Published var errorMessage: String?
    @Published var selectedItemID: String?
    @Published var searchText = "" {
        didSet {
            if selectedSection == .secretUsage { refreshHistorySearch() }
            normalizeSelection()
        }
    }
    @Published private(set) var historyRows: [DashboardItem] = []
    @Published private(set) var historySections: [HistoryDay] = []
    @Published private(set) var authorizationHistoryDayCount = 0
    @Published private(set) var isSearchingHistory = false
    private var allHistorySections: [HistoryDay] = []
    private var historyRecordsByID: [UUID: AccessRequestRecord] = [:]
    private var historySearchTask: Task<Void, Never>?
    private var historySearchWorker: Task<[HistorySearchDay], Never>?
    private var historySearchGeneration = 0
    @Published private(set) var cliInstallState: CLIInstallState?
    @Published fileprivate var availableUpdateVersion: String?
    @Published private(set) var pendingBlessing: BlessedScriptReviewRequest?
    @Published private(set) var pendingBlessingLaunchers: [BlessedScriptLauncher] = []
    @Published private(set) var launcherBundles: [LauncherBundleEnrollment] = []
    @Published private(set) var pendingLauncherBundle: LauncherBundleCandidate?
    @Published private(set) var isDiscoveringLauncherHelpers = false
    @Published private(set) var pendingLauncherHelperReview: LauncherHelperReview?

    private var reloadTask: Task<Void, Never>?
    @Published private var accessRequestsReloadTask: Task<Void, Never>?
    private var accessRequestsReloadPending = false
    private var accessRequestsGeneration = 0
    @Published private(set) var historyOlderPageCursor: Int64?
    @Published private(set) var isLoadingOlderHistory = false
    @Published private(set) var historyLoadFailed = false
    private var pendingAccessRequestID: UUID?
    private var reloadPending = false
    private var launcherHelperDiscoveryTask: Task<Void, Never>?
    let authorityApproval = AuthorityApprovalState()

    private var blessingCompletion: ((BlessedScriptReviewOutcome) -> Void)?

    init(snapshot: DashboardSnapshot = .empty, cliInstallState: CLIInstallState? = nil) {
        self.snapshot = snapshot
        self.cliInstallState = cliInstallState
        setHistoryRecords(snapshot.accessRequests)
        normalizeSelection()
    }

    var items: [DashboardItem] {
        items(for: selectedSection)
    }

    private var searchQuery: String {
        searchText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var hasSearchQuery: Bool { !searchQuery.isEmpty }
    var isRefreshingHistory: Bool { reloadTask != nil || accessRequestsReloadTask != nil }

    private func setHistoryRecords(_ records: [AccessRequestRecord], storedDayCount: Int? = nil) {
        historyRecordsByID = Dictionary(records.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        allHistorySections = historyDays(records.map(historyRow))
        authorizationHistoryDayCount = storedDayCount ?? allHistorySections.count
        refreshHistorySearch()
    }

    fileprivate func appendHistoryRecords(_ records: [AccessRequestRecord]) {
        for record in records { historyRecordsByID[record.id] = record }
        let added = records.map(historyRow)
        allHistorySections = mergeHistoryDays(allHistorySections, historyDays(added))
        let query = searchQuery
        if query.isEmpty {
            historyRows += added
            historySections = allHistorySections
        } else {
            refreshHistorySearch()
        }
    }

    private func refreshHistorySearch() {
        historySearchTask?.cancel()
        historySearchWorker?.cancel()
        historySearchTask = nil
        historySearchWorker = nil
        historySearchGeneration += 1
        let query = searchQuery
        guard !query.isEmpty else {
            isSearchingHistory = false
            historyRows = allHistorySections.flatMap(\.items)
            historySections = allHistorySections
            return
        }
        let loadedCount = allHistorySections.reduce(0) { $0 + $1.items.count }
        // ponytail: small pages filter inline; offload only when retained history grows large.
        guard loadedCount > 2_000 else {
            isSearchingHistory = false
            let source = allHistorySections.map { HistorySearchDay(day: $0.day, items: $0.items) }
            applyHistorySearch(filterHistoryDays(source, query: query))
            return
        }
        let generation = historySearchGeneration
        let source = allHistorySections.map { HistorySearchDay(day: $0.day, items: $0.items) }
        isSearchingHistory = true
        historyRows = []
        historySections = []
        historySearchTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(150)) }
            catch { return }
            guard let self, generation == self.historySearchGeneration else { return }
            let worker = Task.detached(priority: .userInitiated) {
                filterHistoryDays(source, query: query, shouldCancel: { Task.isCancelled })
            }
            self.historySearchWorker = worker
            let matches = await worker.value
            guard generation == self.historySearchGeneration, !worker.isCancelled else { return }
            self.historySearchWorker = nil
            self.applyHistorySearch(matches)
            self.isSearchingHistory = false
            self.normalizeSelection()
        }
    }

    private func applyHistorySearch(_ groups: [HistorySearchDay]) {
        historyRows = groups.flatMap(\.items)
        historySections = groups.map { HistoryDay(day: $0.day, items: $0.items) }
    }

    private func historyRow(_ record: AccessRequestRecord) -> DashboardItem {
        DashboardItem(
            id: record.id.uuidString,
            title: "\(record.launcher ?? "Launcher unavailable") used \(record.tool)",
            subtitle: record.decision,
            detail: record.reason,
            date: record.date
        )
    }

    private func items(for section: DashboardSection) -> [DashboardItem] {
        let base = switch section {
        case .overview: [DashboardItem]()
        case .detectors:
            detectorItems
        case .doctor:
            snapshot.doctorIssues.map { issue in
                let paths = [
                    issue.stubPath.map { "Stub: \($0)" },
                    issue.targetPath.map { "Target: \($0)" },
                    issue.resolvedPath.map { "Resolved: \($0)" },
                ].compactMap(\.self)
                return DashboardItem(
                    id: issue.id,
                    title: issue.command ?? issue.hardener,
                    kind: issue.command == nil || issue.command == issue.hardener ? nil : issue.hardener,
                    subtitle: issue.message,
                    detail: ([issue.message, "Remediation: \(issue.remediation)"] + paths)
                        .joined(separator: "\n\n")
                )
            }
        case .hardenedTools:
            snapshot.hardenedTools.map {
                DashboardItem(
                    id: $0.stubPath ?? $0.name,
                    title: $0.name,
                    subtitle: $0.targetPath ?? "target unknown",
                    detail: [
                        $0.stubPath.map { "Stub: \($0)" },
                        $0.targetPath.map { "Target: \($0)" },
                    ].compactMap(\.self).joined(separator: "\n"),
                    documentation: $0.documentation
                )
            }
        case .secretGates:
            snapshot.secretGates.map {
                let secrets = $0.keyPatterns.count == 1 ? "1 secret" : "\($0.keyPatterns.count) secrets"
                let launcherRules = $0.appPolicies.count == 1
                    ? "1 Launcher rule"
                    : "\($0.appPolicies.count) Launcher rules"
                return DashboardItem(
                    id: $0.id,
                    title: $0.displayName,
                    subtitle: "\(secrets) • \(launcherRules)",
                    detail: [
                        "Scripts: \($0.scriptPaths.joined(separator: ", "))",
                        "Secrets: \($0.keyPatterns.joined(separator: ", "))",
                        "Targets: \($0.targetPaths.joined(separator: ", "))",
                        "Launcher rules: \($0.appPolicies.map(\.bundleIdentifier).joined(separator: ", "))",
                    ].joined(separator: "\n")
                )
            }
        case .blessedScripts:
            blessedScriptItems(snapshot.blessedScripts, pending: pendingBlessing)
        case .launcherBundles:
            launcherBundles.map {
                DashboardItem(
                    id: $0.generation.uuidString,
                    title: $0.displayName,
                    subtitle: $0.signingKind.title,
                    detail: $0.bundlePath
                )
            }
        case .allSecrets:
            snapshot.secrets.map {
                DashboardItem(id: $0.account, title: $0.account, subtitle: $0.subtitle, detail: "Secret value is hidden.\n\($0.subtitle)")
            }
        case .secretUsage:
            historyRows
        case .proxySessions:
            ProxySessionViewModel.shared.sessions.map {
                DashboardItem(
                    id: $0.id.uuidString,
                    title: URL(fileURLWithPath: $0.target).lastPathComponent,
                    subtitle: "pid \($0.pid) • \($0.authorizedRequestCount) authorized requests",
                    detail: "Secrets: \($0.secretNames.joined(separator: ", "))",
                    date: $0.startedAt
                )
            }
        case .settings:
            [
                DashboardItem(
                    id: String(localized: "touch-id-approval"),
                    title: String(localized: "Touch ID Approval"),
                    subtitle: TouchIDApproval.isEnabled
                        ? String(localized: "Approve on this Mac with Touch ID")
                        : String(localized: "Require biometrics for Mac Approval"),
                    detail: String(localized: "Add an explicit biometric-only Approval surface on this Mac.")
                ),
                DashboardItem(
                    id: String(localized: "iphone-approval"),
                    title: String(localized: "iPhone Approval"),
                    subtitle: PhoneApprovalCoordinator.shared.isEnabled
                        ? String(localized: "All human Approvals use iPhone")
                        : String(localized: "Approve away from agents on this Mac"),
                    detail: String(localized: "Move every human Approval for this Mac to iPhones on your iCloud Keychain account.")
                ),
                DashboardItem(
                    id: String(localized: "automatic-approval-feedback"),
                    title: String(localized: "Automic Authorization"),
                    subtitle: String(localized: "Choose subtle feedback or none"),
                    detail: String(localized: "Control visual feedback after policy authorizes an operation.")
                ),
                DashboardItem(
                    id: String(localized: "detached-process-access"),
                    title: String(localized: "Detached Processes"),
                    subtitle: String(localized: "Keep Launcher attribution after ancestry loss"),
                    detail: String(localized: "Allow an exact live process execution to retain gate-specific Launcher attribution after its parent chain exits.")
                ),
                DashboardItem(
                    id: String(localized: "verified-launcher-helpers"),
                    title: String(localized: "Verified Launcher Helpers"),
                    subtitle: String(localized: "Recognize signed CLIs sealed inside vendor apps"),
                    detail: String(localized: "Manage exact app and helper signing-identity associations.")
                ),
                DashboardItem(
                    id: String(localized: "gpg-signing"),
                    title: String(localized: "GPG Signing"),
                    subtitle: String(localized: "Authorize Git commit signing"),
                    detail: String(localized: "Store GPG signing credentials, configure Git, and select Verified Launchers that use an alternate key.")
                ),
                DashboardItem(
                    id: String(localized: "ssh-agent"),
                    title: String(localized: "SSH Agent"),
                    subtitle: String(localized: "Authorize SSH authentication"),
                    detail: String(localized: "Use one protected SSH credential for every Verified Launcher.")
                ),
                DashboardItem(
                    id: String(localized: "secret-name-access"),
                    title: String(localized: "Secret Name Access"),
                    subtitle: String(localized: "Verified Launchers allowed to run av list"),
                    detail: String(localized: "Manage Verified Launchers that may list saved Secret Names without Approval.")
                ),
                DashboardItem(
                    id: String(localized: "authorization-history-access"),
                    title: String(localized: "Authorization History Access"),
                    subtitle: String(localized: "Verified Launchers allowed to run av history"),
                    detail: String(localized: "Manage Verified Launchers that may read Authorization History without Approval.")
                ),
                DashboardItem(
                    id: String(localized: "about"),
                    title: String(localized: "About"),
                    subtitle: String(localized: "GUI environment details"),
                    detail: String(localized: "View details about the running Automic Vault app.")
                ),
            ]
        }
        if section == .secretUsage { return base }
        let query = searchQuery
        guard !query.isEmpty else { return base }
        return base.filter {
            $0.title.localizedCaseInsensitiveContains(query)
                || $0.kind?.localizedCaseInsensitiveContains(query) == true
                || $0.subtitle.localizedCaseInsensitiveContains(query)
                || $0.blessingStatus?.localizedCaseInsensitiveContains(query) == true
                || $0.detail.localizedCaseInsensitiveContains(query)
        }
    }

    var selectedItem: DashboardItem? {
        let items = items
        if let selectedItemID, let item = items.first(where: { $0.id == selectedItemID }) {
            return item
        }
        return items.first
    }

    var selectedSecretGate: SecretGate? {
        if let selectedItemID, let gate = snapshot.secretGates.first(where: { $0.id == selectedItemID }) {
            return gate
        }
        return snapshot.secretGates.first
    }

    var selectedBlessedScript: BlessedScript? {
        if let selectedItemID,
           let script = snapshot.blessedScripts.first(where: { $0.path == selectedItemID }) {
            return script
        }
        return snapshot.blessedScripts.first
    }

    var selectedStoredSecret: StoredSecret? {
        if let selectedItemID,
           let secret = snapshot.secrets.first(where: { $0.account == selectedItemID }) {
            return secret
        }
        return snapshot.secrets.first
    }

    var selectedLauncherBundle: LauncherBundleEnrollment? {
        if let selectedItemID,
           let enrollment = launcherBundles.first(where: { $0.generation.uuidString == selectedItemID }) {
            return enrollment
        }
        return launcherBundles.first
    }

    func storedSecret(named account: String) -> StoredSecret? {
        snapshot.secrets.first { $0.account == account }
    }

    var selectedAccessRequest: AccessRequestRecord? {
        guard pendingAccessRequestID == nil, let selectedItemID,
              let id = UUID(uuidString: selectedItemID),
              let record = historyRecordsByID[id] else { return nil }
        return searchQuery.isEmpty || historyMatchesSearch(historyRow(record), query: searchQuery)
            ? record : nil
    }

    var pendingAccessRequestStatus: String? {
        guard pendingAccessRequestID != nil else { return nil }
        if reloadTask != nil || accessRequestsReloadTask != nil || isLoadingOlderHistory {
            return String(localized: "Loading Authorization History…")
        }
        if historyLoadFailed {
            return historyOlderPageCursor == nil
                ? String(localized: "Authorization History unavailable")
                : String(localized: "Older Authorization History unavailable")
        }
        if historyOlderPageCursor != nil {
            return String(localized: "Load older records to find this Authorization History record.")
        }
        return String(localized: "Authorization History record unavailable")
    }

    var selectedProxySession: ProxySessionSummary? {
        let sessions = ProxySessionViewModel.shared.sessions
        if let selectedItemID,
           let session = sessions.first(where: { $0.id.uuidString == selectedItemID }) {
            return session
        }
        return sessions.first
    }

    var scriptsNeedingReblessingCount: Int {
        items(for: .blessedScripts).filter { $0.blessingStatus == "Changed" }.count
    }

    func count(for section: DashboardSection) -> Int {
        if section == .secretUsage && selectedSection != .secretUsage {
            return snapshot.accessRequests.count
        }
        guard searchQuery.isEmpty else { return items(for: section).count }
        return switch section {
        case .overview: 0
        case .detectors: snapshot.detectorDisplayCount
        case .doctor: snapshot.doctorIssues.count
        case .hardenedTools: snapshot.hardenedTools.count
        case .secretGates: snapshot.secretGates.count
        case .blessedScripts:
            snapshot.blessedScripts.count
                + (pendingBlessing.map { pending in
                    snapshot.blessedScripts.contains { $0.path == pending.path } ? 0 : 1
                } ?? 0)
        case .launcherBundles: launcherBundles.count
        case .allSecrets: snapshot.secrets.count
        case .secretUsage: snapshot.accessRequests.count
        case .proxySessions: ProxySessionViewModel.shared.sessions.count
        case .settings: 0
        }
    }

    func selectSection(_ section: DashboardSection) {
        pendingAccessRequestID = nil
        selectedSection = section
        selectedItemID = nil
        if section == .secretUsage { refreshHistorySearch() }
        normalizeSelection()
    }

    func select(_ item: DashboardItem) {
        pendingAccessRequestID = nil
        selectedItemID = item.id
    }

    func showAccessRequest(id: UUID, records: [AccessRequestRecord]? = nil) {
        if let records {
            snapshot.accessRequests = records
            setHistoryRecords(records)
        }
        guard snapshot.accessRequests.contains(where: { $0.id == id }) else {
            pendingAccessRequestID = id
            selectedSection = .secretUsage
            searchText = ""
            selectedItemID = nil
            reloadAccessRequests()
            return
        }
        resolvePendingAccessRequest(id)
    }

    private func resolvePendingAccessRequest(_ id: UUID) {
        selectedSection = .secretUsage
        searchText = ""
        pendingAccessRequestID = nil
        selectedItemID = id.uuidString
    }

    func showSecretGate(id: String) {
        selectedSection = .secretGates
        selectedItemID = id
    }

    func showSettings() {
        selectSection(.settings)
    }

    func reviewBlessing(
        _ request: BlessedScriptReviewRequest,
        completion: @escaping (BlessedScriptReviewOutcome) -> Void
    ) {
        guard pendingBlessing == nil else {
            completion(.failed("another script blessing is already awaiting review"))
            return
        }
        let previous = loadBlessedScripts().first { $0.path == request.path }
        pendingBlessing = BlessedScriptReviewRequest(
            path: request.path,
            declaration: request.declaration,
            scriptData: request.scriptData,
            launcher: request.launcher,
            previousContents: request.previousContents ?? previous?.verifiedReviewedContents
        )
        pendingBlessingLaunchers = launcherEndorsementsForReblessing(
            previouslyEndorsed: previous?.launchers ?? [],
            requestedLauncher: request.launcher
        )
        blessingCompletion = completion
    }

    func approvePendingBlessing() {
        guard let request = pendingBlessing, !authorityApproval.isPending("blessing") else { return }
        let declaration = request.declaration
        let script = BlessedScript(
            path: request.path,
            checksum: declaration.checksum,
            keys: declaration.keys,
            target: declaration.target,
            replaceExistingEnv: declaration.replaceExistingEnv,
            allowMissingKeys: declaration.allowMissingKeys,
            allowsCanonicalPathExecution: declaration.snapshotIncompatibleInterpreter != nil,
            inheritsCapabilities: declaration.manifest.inheritsCapabilities,
            capabilities: declaration.manifest.capabilities,
            launchers: pendingBlessingLaunchers,
            reviewedContents: request.scriptData
        )
        approveAuthorityChange(
            action: "blessing",
            "Bless \(URL(fileURLWithPath: script.path).lastPathComponent)",
            detail: [
                "Path: \(script.path)",
                "Checksum: \(script.checksum)",
                "Target: \(script.target)",
                "Secret Names: \(script.keys.joined(separator: ", "))",
                "Access: \(blessedScriptAccessSummary(script))",
                "Launchers: \(script.launchers.map(\.bundleIdentifier).joined(separator: ", "))",
            ].joined(separator: "\n")
        ) { [weak self] in
            guard let self else { return }
            let status = saveBlessedScript(script)
            guard status == errSecSuccess else {
                self.errorMessage = String(localized: "Could not bless script: \(String(status))")
                return
            }
            self.finishPendingBlessing(.approved)
            self.selectedItemID = script.path
            self.reloadAuthorizationState()
        }
    }

    func cancelPendingBlessing() {
        guard pendingBlessing != nil else { return }
        finishPendingBlessing(.denied)
    }

    func reviewChanges(to script: BlessedScript) {
        guard let previousContents = script.verifiedReviewedContents else {
            errorMessage = String(localized: "The original reviewed contents are unavailable. Run `av bless` once to create a new review baseline.")
            return
        }
        do {
            let scriptData = try readBlessedScript(path: script.path)
            let declaration = try blessedScriptDeclaration(data: scriptData)
            guard declaration.checksum != script.checksum else {
                reloadAuthorizationState()
                return
            }
            reviewBlessing(BlessedScriptReviewRequest(
                path: script.path,
                declaration: declaration,
                scriptData: scriptData,
                launcher: nil,
                previousContents: previousContents
            )) { [weak self] outcome in
                if case .failed(let error) = outcome { self?.errorMessage = error }
            }
        } catch {
            errorMessage = String(localized: "Could not review changes: \(error.localizedDescription)")
        }
    }

    func addAppToPendingBlessing() {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher,
                  !self.pendingBlessingLaunchers.contains(where: { $0.requirement == launcher.requirement })
            else { return }
            self.pendingBlessingLaunchers.append(launcher)
        }
    }

    func removePendingBlessingLauncher(_ launcher: BlessedScriptLauncher) {
        pendingBlessingLaunchers.removeAll { $0.requirement == launcher.requirement }
    }

    func addApp(to script: BlessedScript) {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher,
                  !script.launchers.contains(where: { $0.requirement == launcher.requirement })
            else { return }
            let updated = BlessedScript(
                path: script.path,
                checksum: script.checksum,
                keys: script.keys,
                target: script.target,
                replaceExistingEnv: script.replaceExistingEnv,
                allowMissingKeys: script.allowMissingKeys,
                allowsCanonicalPathExecution: script.allowsCanonicalPathExecution == true,
                inheritsCapabilities: script.usesCapabilityInheritance,
                capabilities: script.capabilities,
                launchers: script.launchers + [launcher],
                blessedAt: script.blessedAt,
                reviewedContents: script.reviewedContents
            )
            self.approveAuthorityChange(
                action: "script-launcher:\(script.path)",
                "Add \(launcher.bundleIdentifier) to a Blessing",
                detail: [
                    "Script: \(script.path)",
                    "Checksum: \(script.checksum)",
                    "Secret Names: \(script.keys.joined(separator: ", "))",
                    "Access: \(blessedScriptAccessSummary(script))",
                ].joined(separator: "\n")
            ) {
                self.finishPolicyUpdate(saveBlessedScript(updated), error: "Could not add Verified Launcher")
            }
        }
    }

    func addSecretNameAccessApp() {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher else { return }
            self.approveAuthorityChange(
                action: "secret-name-access",
                "Allow \(launcher.bundleIdentifier) to list Secret Names",
                detail: "The verified Launcher may list every saved Secret Name without future Approval."
            ) {
                self.finishPolicyUpdate(
                    allowSecretNameAccess(launcher),
                    error: "Could not allow \(launcher.bundleIdentifier)"
                )
            }
        }
    }

    func removeSecretNameAccessApp(_ app: BlessedScriptLauncher) {
        finishPolicyUpdate(
            removeSecretNameAccess(app),
            error: "Could not remove \(app.bundleIdentifier)"
        )
    }

    func addAuthorizationHistoryAccessApp() {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher else { return }
            self.approveAuthorityChange(
                action: "authorization-history-access",
                "Allow \(launcher.bundleIdentifier) to read Authorization History",
                detail: "The Verified Launcher may read the bounded local Authorization History, including Secret Names and request metadata, without future Approval."
            ) {
                self.finishPolicyUpdate(
                    allowAuthorizationHistoryAccess(launcher),
                    error: "Could not allow \(launcher.bundleIdentifier)"
                )
            }
        }
    }

    func removeAuthorizationHistoryAccessApp(_ app: BlessedScriptLauncher) {
        finishPolicyUpdate(
            removeAuthorizationHistoryAccess(app),
            error: "Could not remove \(app.bundleIdentifier)"
        )
    }

    func removeLauncher(_ launcher: BlessedScriptLauncher, from script: BlessedScript) {
        let launchers = script.launchers.filter { $0.requirement != launcher.requirement }
        let updated = BlessedScript(
            path: script.path,
            checksum: script.checksum,
            keys: script.keys,
            target: script.target,
            replaceExistingEnv: script.replaceExistingEnv,
            allowMissingKeys: script.allowMissingKeys,
            allowsCanonicalPathExecution: script.allowsCanonicalPathExecution == true,
            inheritsCapabilities: script.usesCapabilityInheritance,
            capabilities: script.capabilities,
            launchers: launchers,
            blessedAt: script.blessedAt,
            reviewedContents: script.reviewedContents
        )
        finishPolicyUpdate(saveBlessedScript(updated), error: "Could not remove Verified Launcher")
    }

    func revoke(_ script: BlessedScript) {
        let status = removeBlessedScript(path: script.path)
        if status == errSecSuccess {
            selectedItemID = nil
            reloadAuthorizationState()
        } else {
            errorMessage = String(localized: "Could not revoke blessing: \(String(status))")
        }
    }

    private func finishPendingBlessing(_ outcome: BlessedScriptReviewOutcome) {
        authorityApproval.cancel("blessing")
        let completion = blessingCompletion
        blessingCompletion = nil
        pendingBlessing = nil
        pendingBlessingLaunchers = []
        completion?(outcome)
    }

    private func chooseLauncherApp(_ completion: @escaping (BlessedScriptLauncher?) -> Void) {
        chooseLauncher { signing in
            guard let signing else {
                completion(nil)
                return
            }
            completion(BlessedScriptLauncher(
                bundleIdentifier: signing.identifier,
                requirement: signing.requirement
            ))
        }
    }

    func accessRequests(for item: DashboardItem) -> [AccessRequestRecord] {
        recentAccessRequests.filter { $0.tool == item.title }
    }

    var recentAccessRequests: [AccessRequestRecord] {
        Array(snapshot.accessRequests.prefix(50))
    }

    func reload() {
        guard reloadTask == nil else {
            reloadPending = true
            return
        }
        accessRequestsGeneration += 1
        isLoadingOlderHistory = false
        let generation = accessRequestsGeneration
        reloadPending = false
        isReloading = true
        reloadTask = Task {
            defer {
                reloadTask = nil
                isReloading = false
                if reloadPending { reload() }
            }
            let cliInstallState = await Task.detached(priority: .background) {
                currentCLIInstallState()
            }.value
            guard !Task.isCancelled else { return }
            self.cliInstallState = cliInstallState

            var (next, launcherBundles) = await Task.detached(priority: .background) {
                (DashboardSnapshot.load(), loadLauncherBundleEnrollments())
            }.value
            guard !Task.isCancelled else { return }
            next.detectorFindings = snapshot.detectorFindings
            let page = await Task.detached(priority: .background) {
                loadAccessRequestRecordsPage()
            }.value
            guard !Task.isCancelled else { return }
            next.accessRequests = generation == accessRequestsGeneration
                ? (page?.records ?? []) : snapshot.accessRequests
            snapshot = next
            setHistoryRecords(next.accessRequests, storedDayCount: page?.storedDayCount)
            if generation == accessRequestsGeneration {
                historyOlderPageCursor = page?.olderPageCursor
                isLoadingOlderHistory = false
                historyLoadFailed = page == nil
            }
            if generation == accessRequestsGeneration, let id = pendingAccessRequestID {
                if next.accessRequests.contains(where: { $0.id == id }) {
                    resolvePendingAccessRequest(id)
                }
            }
            self.launcherBundles = launcherBundles
            normalizeSelection()
        }
    }

    func reloadAccessRequests() {
        accessRequestsGeneration += 1
        isLoadingOlderHistory = false
        guard accessRequestsReloadTask == nil else {
            accessRequestsReloadPending = true
            return
        }
        let generation = accessRequestsGeneration
        accessRequestsReloadTask = Task { [weak self] in
            defer {
                self?.accessRequestsReloadTask = nil
                if self?.accessRequestsReloadPending == true {
                    self?.accessRequestsReloadPending = false
                    self?.reloadAccessRequests()
                }
            }
            let page = await Task.detached(priority: .background) {
                loadAccessRequestRecordsPage()
            }.value
            guard !Task.isCancelled, let self,
                  generation == accessRequestsGeneration else { return }
            if let page {
                snapshot.accessRequests = page.records
                setHistoryRecords(page.records, storedDayCount: page.storedDayCount)
                historyOlderPageCursor = page.olderPageCursor
                historyLoadFailed = false
            } else {
                snapshot.accessRequests = []
                setHistoryRecords([])
                historyOlderPageCursor = nil
                historyLoadFailed = true
            }
            if let id = pendingAccessRequestID {
                if snapshot.accessRequests.contains(where: { $0.id == id }) {
                    resolvePendingAccessRequest(id)
                }
            }
            normalizeSelection()
        }
    }

    func loadMoreHistory(retry: Bool = false) {
        guard let cursor = historyOlderPageCursor, !isLoadingOlderHistory,
              reloadTask == nil, accessRequestsReloadTask == nil,
              !historyLoadFailed || retry else { return }
        isLoadingOlderHistory = true
        historyLoadFailed = false
        let generation = accessRequestsGeneration
        Task { [weak self] in
            let page = await Task.detached(priority: .background) {
                loadAccessRequestRecordsPage(beforeSequence: cursor)
            }.value
            guard let self, generation == accessRequestsGeneration,
                  historyOlderPageCursor == cursor else { return }
            isLoadingOlderHistory = false
            guard let page else {
                historyLoadFailed = true
                return
            }
            snapshot.accessRequests += page.records
            appendHistoryRecords(page.records)
            historyOlderPageCursor = page.olderPageCursor
            if let id = pendingAccessRequestID,
               historyRecordsByID[id] != nil {
                resolvePendingAccessRequest(id)
            }
            normalizeSelection()
        }
    }

    private func invalidateReload() {
        // Cancellation invalidates the result, but synchronous checks still run.
        // Retain the task until they finish so a new reload cannot overlap them.
        reloadTask?.cancel()
        accessRequestsReloadTask?.cancel()
        accessRequestsGeneration += 1
        isLoadingOlderHistory = false
        accessRequestsReloadPending = false
        reloadPending = false
        isReloading = false
    }

    private func reloadAuthorizationState() {
        invalidateReload()
        snapshot = reloadDashboardAuthorizationState(from: snapshot)
        launcherBundles = loadLauncherBundleEnrollments()
        normalizeSelection()
    }

    private func reloadAfterSecretMutation() {
        reloadAuthorizationState()
        reload()
    }

    func createLauncherBundle(_ options: LauncherBundleOptions) {
        guard !isBuildingLauncherBundle else { return }
        isBuildingLauncherBundle = true
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { try prepareLauncherBundleCandidate(options) }
            }.value
            isBuildingLauncherBundle = false
            switch result {
            case .success(let candidate):
                pendingLauncherBundle = candidate
                errorMessage = nil
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
    }

    func installPendingLauncherBundle() {
        guard !isBuildingLauncherBundle, let candidate = pendingLauncherBundle else { return }
        isBuildingLauncherBundle = true
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { try installLauncherBundleCandidate(candidate) }
            }.value
            isBuildingLauncherBundle = false
            pendingLauncherBundle = nil
            switch result {
            case .success(let creation):
                isCreatingLauncherBundle = false
                selectedSection = .launcherBundles
                selectedItemID = creation.enrollment.generation.uuidString
                errorMessage = creation.cleanupWarning
                NSWorkspace.shared.activateFileViewerSelecting([
                    URL(fileURLWithPath: creation.enrollment.bundlePath)
                ])
                reloadAuthorizationState()
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
    }

    func cancelLauncherBundleCreation() {
        if let pendingLauncherBundle { discardLauncherBundleCandidate(pendingLauncherBundle) }
        pendingLauncherBundle = nil
        isCreatingLauncherBundle = false
    }

    func deleteLauncherBundle(_ enrollment: LauncherBundleEnrollment) {
        guard !isBuildingLauncherBundle else { return }
        let status = removeLauncherBundleEnrollment(generation: enrollment.generation)
        guard status == errSecSuccess else {
            errorMessage = String(localized: "Could not revoke Launcher Bundle enrollment: \(String(status))")
            return
        }
        isBuildingLauncherBundle = true
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { () -> OSStatus in
                    let cleanup = removeLauncherBundleAuthorization(
                        requirement: enrollment.launcherRequirement
                    )
                    try removeInstalledLauncherBundle(enrollment)
                    return cleanup
                }
            }.value
            isBuildingLauncherBundle = false
            switch result {
            case .success(let cleanup):
                errorMessage = cleanup == errSecSuccess
                    ? nil
                    : "The bundle was revoked, but old authorization rules could not be removed: \(cleanup)"
            case .failure(let error):
                errorMessage = String(localized: "The bundle was revoked, but could not be moved to Trash: \(error.localizedDescription)")
            }
            selectedItemID = nil
            reloadAuthorizationState()
        }
    }

    func updateDetectorFindings(_ findings: [DetectorFinding]) {
        snapshot.detectorFindings = findings
        normalizeSelection()
    }

    private func normalizeSelection() {
        if selectedSection == .secretUsage {
            if pendingAccessRequestID != nil {
                selectedItemID = nil
            } else if selectedAccessRequest == nil {
                selectedItemID = historySections.first?.items.first?.id
            }
            return
        }
        let items = items
        guard selectedItemID.map({ id in items.contains { $0.id == id } }) != true else { return }
        selectedItemID = items.first?.id
    }

    func addSecret(
        account: String,
        value: String,
        accessibility: StoredSecretAccessibility = .whenUnlocked
    ) -> Bool {
        let account = account.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !account.isEmpty, !value.isEmpty else { return false }
        let result = performInAppSecretMutation(
            .save(account: account, value: value, accessibility: accessibility)
        )
        guard let status = result.status else {
            errorMessage = result.error
            return false
        }
        if status == errSecSuccess {
            errorMessage = nil
            selectedSection = .allSecrets
            selectedItemID = account
            reloadAfterSecretMutation()
            return true
        } else {
            errorMessage = String(localized: "Could not save \(account): \(String(status))")
            return false
        }
    }

    func setAccessibility(_ accessibility: StoredSecretAccessibility, for secret: StoredSecret) -> Bool {
        let result = performInAppSecretMutation(
            .setAccessibility(account: secret.account, accessibility: accessibility)
        )
        guard let status = result.status else {
            errorMessage = result.error
            return false
        }
        if status == errSecSuccess {
            errorMessage = nil
            reloadAfterSecretMutation()
            return true
        }
        errorMessage = String(localized: "Could not update \(secret.account): \(String(status))")
        return false
    }

    func chooseDirectAccessLauncher(_ completion: @escaping (DirectAccessLauncherSelection?) -> Void) {
        pickLauncher { signing in
            guard let signing else { return }
            guard let runtimeRequirement = signing.runtimeProtection.secretGateAdmissionRequirement else {
                showLauncherCannotBeAllowed(secretGateAdmissionError(
                    appName: signing.identifier,
                    protection: signing.runtimeProtection
                ))
                return
            }
            completion(DirectAccessLauncherSelection(
                launcher: BlessedScriptLauncher(
                    bundleIdentifier: signing.identifier,
                    requirement: signing.requirement
                ),
                runtimeRequirement: runtimeRequirement
            ))
        }
    }

    func addDirectAccessLauncher(
        _ selection: DirectAccessLauncherSelection,
        to secret: StoredSecret,
        completion: @escaping () -> Void
    ) {
        approveAuthorityChange(
            action: "direct-access:\(secret.account)",
            "Allow direct access to \(secret.account)",
            detail: "\(selection.launcher.bundleIdentifier) may use this Secret without future Approval.",
            completion: completion
        ) { [weak self] in
            self?.finishPolicyUpdate(
                allowDirectAccess(
                    to: secret.account,
                    for: selection.launcher,
                    runtimeRequirement: selection.runtimeRequirement
                ),
                error: "Could not allow \(selection.launcher.bundleIdentifier) to use \(secret.account)"
            )
        }
    }

    func removeDirectAccessLauncher(_ launcher: BlessedScriptLauncher, from secret: StoredSecret) {
        finishPolicyUpdate(
            removeDirectAccess(to: secret.account, for: launcher),
            error: "Could not remove \(launcher.bundleIdentifier) from \(secret.account)"
        )
    }

    func deleteSecret(account: String) {
        let result = performInAppSecretMutation(.delete(account: account))
        guard let status = result.status else {
            errorMessage = result.error
            return
        }
        if status == errSecSuccess || status == errSecItemNotFound {
            selectedItemID = nil
            reloadAfterSecretMutation()
        } else {
            errorMessage = String(localized: "Could not delete \(account): \(String(status))")
        }
    }

    func replaceSecretValue(_ storedValue: StoredSecretValue, in secret: StoredSecret, with value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let mutation: SecretMutation = switch storedValue.source {
        case .global:
            .save(account: secret.account, value: value, accessibility: secret.accessibility)
        case .projectDirectory(let directory):
            .saveProject(
                account: secret.account,
                value: value,
                directory: directory,
                accessibility: secret.accessibility,
                warning: ""
            )
        }
        let result = performInAppSecretMutation(mutation)
        guard result.status == errSecSuccess else {
            errorMessage = result.error ?? "Could not replace \(secret.account): \(result.status ?? errSecInternalError)"
            return false
        }
        errorMessage = nil
        reloadAfterSecretMutation()
        return true
    }

    func deleteSecretValue(_ value: StoredSecretValue, from secret: StoredSecret) {
        let result = performInAppSecretMutation(
            .deleteValue(account: secret.account, source: value.source)
        )
        guard let status = result.status else {
            errorMessage = result.error
            return
        }
        if status == errSecSuccess || status == errSecItemNotFound {
            if secret.values.count == 1 { selectedItemID = nil }
            errorMessage = nil
            reloadAfterSecretMutation()
        } else {
            errorMessage = String(localized: "Could not delete \(secret.account) Value: \(String(status))")
        }
    }

    func renameSelectedSecret(to newAccount: String) -> Bool {
        guard selectedSection == .allSecrets, let account = selectedItem?.id else { return false }
        let newAccount = newAccount.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !newAccount.isEmpty, newAccount != account else { return false }
        let result = performInAppSecretMutation(
            .rename(account: account, newAccount: newAccount)
        )
        guard let status = result.status else {
            errorMessage = result.error
            return false
        }
        if status == errSecSuccess {
            errorMessage = nil
            selectedItemID = newAccount
            reloadAfterSecretMutation()
            return true
        } else {
            errorMessage = String(localized: "Could not rename \(account): \(String(status))")
            return false
        }
    }

    func installCLI() {
        Task {
            do {
                if try await installBundledCLI() {
                    errorMessage = nil
                    reload()
                }
            } catch {
                errorMessage = String(localized: "Could not install av CLI: \(error.localizedDescription)")
            }
        }
    }

    func addApp(to gate: SecretGate) {
        guard !isDiscoveringLauncherHelpers, pendingLauncherHelperReview == nil else { return }
        chooseLauncher { [weak self] signing in
            guard let self, let signing else { return }
            guard let runtimeRequirement = signing.runtimeProtection.secretGateAdmissionRequirement else {
                showLauncherCannotBeAllowed(secretGateAdmissionError(
                    appName: signing.identifier,
                    protection: signing.runtimeProtection
                ))
                return
            }
            guard URL(fileURLWithPath: signing.path).pathExtension
                .caseInsensitiveCompare("app") == .orderedSame
            else {
                self.finishAddingLauncher(
                    signing,
                    to: gate,
                    runtimeRequirement: runtimeRequirement,
                    helpers: []
                )
                return
            }
            self.isDiscoveringLauncherHelpers = true
            self.launcherHelperDiscoveryTask = Task { [weak self] in
                let discovered = await discoverVerifiedLauncherHelpers(
                    in: URL(fileURLWithPath: signing.path, isDirectory: true)
                )
                guard let self else { return }
                self.isDiscoveringLauncherHelpers = false
                self.launcherHelperDiscoveryTask = nil
                guard !Task.isCancelled else { return }
                let configuration = loadVerifiedLauncherHelperConfiguration()
                var seen = Set<String>()
                let helpers = discovered.compactMap { discovered -> VerifiedLauncherHelper? in
                    let helper = configuration.catalogHelper(matching: discovered) ?? discovered
                    guard !configuration.isEnabled(helper), seen.insert(helper.id).inserted else {
                        return nil
                    }
                    return helper
                }
                guard !helpers.isEmpty else {
                    self.finishAddingLauncher(
                        signing,
                        to: gate,
                        runtimeRequirement: runtimeRequirement,
                        helpers: []
                    )
                    return
                }
                self.pendingLauncherHelperReview = LauncherHelperReview(
                    signing: signing,
                    gate: gate,
                    runtimeRequirement: runtimeRequirement,
                    helpers: helpers
                )
            }
        }
    }

    func cancelLauncherHelperDiscovery() {
        launcherHelperDiscoveryTask?.cancel()
    }

    func confirmLauncherHelperReview(selectedHelperIDs: Set<String>) {
        guard let review = pendingLauncherHelperReview else { return }
        finishAddingLauncher(
            review.signing,
            to: review.gate,
            runtimeRequirement: review.runtimeRequirement,
            helpers: review.helpers.filter { selectedHelperIDs.contains($0.id) }
        )
    }

    func cancelLauncherHelperReview() {
        if let review = pendingLauncherHelperReview {
            authorityApproval.cancel("gate-launcher:\(review.gate.id)")
        }
        pendingLauncherHelperReview = nil
    }

    private func finishAddingLauncher(
        _ signing: LauncherSigning,
        to gate: SecretGate,
        runtimeRequirement: LauncherRuntimeRequirement,
        helpers: [VerifiedLauncherHelper]
    ) {
        let existingPolicy = gate.appPolicies.contains { $0.requirement == signing.requirement }
        guard !existingPolicy || !helpers.isEmpty else {
            pendingLauncherHelperReview = nil
            return
        }
        let helperList = helpers.map {
            let path = $0.relativePath.map { " at \($0)" } ?? ""
            return "Verified Launcher Helper: \($0.helperSigningIdentifier), "
                + "Team \($0.helperTeamIdentifier)\(path)"
        }.joined(separator: "\n")
        let helperDetail = helpers.isEmpty ? nil : """
        \(helperList)
        Each selected helper will represent \(signing.identifier) at every Authorization Gate where that app has a current or future Launcher-specific rule.
        """
        let detail = [
            existingPolicy ? nil : gate.protectionSubtitle(gate.initialProtection),
            helperDetail,
        ].compactMap(\.self).joined(separator: "\n\n")
        approveAuthorityChange(
            action: "gate-launcher:\(gate.id)",
            existingPolicy
                ? "Add Launcher Helpers for \(signing.identifier)"
                : "Add \(signing.identifier) to \(gate.displayName)",
            detail: detail
        ) { [weak self] in
            guard let self else { return }
            self.pendingLauncherHelperReview = nil
            if !existingPolicy {
                let policyStatus = setSecretGateAppProtection(
                    requirement: signing.requirement,
                    protection: gate.initialProtection,
                    for: gate,
                    runtimeRequirement: runtimeRequirement
                )
                guard policyStatus == errSecSuccess else {
                    self.errorMessage = String(localized: "Could not allow \(signing.identifier): \(String(policyStatus))")
                    return
                }
            }
            guard !helpers.isEmpty else {
                self.errorMessage = nil
                self.reloadAuthorizationState()
                return
            }
            var configuration = loadVerifiedLauncherHelperConfiguration()
            configuration.enable(helpers)
            let helperStatus = saveVerifiedLauncherHelperConfiguration(configuration)
            self.errorMessage = helperStatus == errSecSuccess
                ? nil
                : "The Launcher was added, but its helper associations could not be saved: \(helperStatus)"
            self.reloadAuthorizationState()
        }
    }

    func setDefaultProtection(_ protection: SecretGateProtection, for gate: SecretGate) {
        let update = { [weak self] in
            guard let self else { return }
            self.finishSecretGatePolicyUpdate(
                setSecretGateDefaultProtection(protection, for: gate),
                gate: gate,
                error: "Could not update the default protection"
            )
        }
        guard protection.addsAuthority(over: gate.defaultProtection) else { update(); return }
        approveAuthorityChange(
            action: "gate-default:\(gate.id)",
            "Broaden \(gate.displayName) default to \(protection.title)",
            detail: protection.subtitle,
            perform: update
        )
    }

    func setProtection(_ protection: SecretGateProtection, for app: SecretGatePolicy, in gate: SecretGate) {
        let update = { [weak self] in
            guard let self else { return }
            self.finishSecretGatePolicyUpdate(
                setSecretGateAppProtection(
                    requirement: app.requirement,
                    protection: protection,
                    for: gate,
                    runtimeRequirement: app.runtimeRequirement
                ),
                gate: gate,
                error: "Could not update \(app.bundleIdentifier)"
            )
        }
        guard protection.addsAuthority(over: app.protection) else { update(); return }
        approveAuthorityChange(
            action: "gate-policy:\(gate.id):\(app.requirement)",
            "Broaden \(app.bundleIdentifier) to \(protection.title)",
            detail: protection.subtitle,
            perform: update
        )
    }

    func removeAppPolicy(_ app: SecretGatePolicy, from gate: SecretGate) {
        finishSecretGatePolicyUpdate(
            removeSecretGateAppPolicy(app, from: gate),
            gate: gate,
            error: "Could not delete the Launcher-specific rule for \(app.bundleIdentifier)"
        )
    }

    private func finishSecretGatePolicyUpdate(_ status: OSStatus, gate: SecretGate, error: String) {
        guard status == errSecSuccess else {
            errorMessage = String(localized: "\(error): \(String(status))")
            return
        }
        invalidateReload()
        guard let index = snapshot.secretGates.firstIndex(where: { $0.id == gate.id }) else {
            errorMessage = String(localized: "The policy was saved, but the Authorization Gate is no longer available")
            return
        }
        errorMessage = nil
        var updatedSnapshot = snapshot
        updatedSnapshot.secretGates[index] = reloadSecretGatePolicy(for: snapshot.secretGates[index])
        snapshot = updatedSnapshot
        normalizeSelection()
    }

    private func finishPolicyUpdate(_ status: OSStatus, error: String) {
        if status == errSecSuccess {
            errorMessage = nil
            reloadAuthorizationState()
        } else {
            errorMessage = String(localized: "\(error): \(String(status))")
        }
    }

    private func approveAuthorityChange(
        action: String,
        _ title: String,
        detail: String,
        completion: @escaping () -> Void = {},
        perform: @escaping () -> Void
    ) {
        authorityApproval.request(action, title: title, detail: detail) {
            defer { completion() }
            if $0 { perform() }
        }
    }

    var overviewTools: [DashboardItem] {
        let detected = detectorItems.filter { $0.isTriggered || $0.isHardened }
        let names = Set(detected.map(\.title))
        let hardened = snapshot.hardenedTools.filter { !names.contains($0.name) }.map {
            DashboardItem(id: $0.stubPath ?? $0.name, title: $0.name,
                          subtitle: "Hardened", detail: "", isHardened: true)
        }
        return (detected + hardened)
            .filter { searchQuery.isEmpty || $0.title.localizedCaseInsensitiveContains(searchQuery) }
            .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    func navigateFromOverview(to section: DashboardSection, itemID: String? = nil) {
        searchText = ""
        selectSection(section)
        if let itemID, items.contains(where: { $0.id == itemID }) {
            selectedItemID = itemID
        }
    }

    private var detectorItems: [DashboardItem] {
        let findingsBySource = Dictionary(grouping: snapshot.detectorFindings, by: \.source)
        let hardenersByName = snapshot.hardeners.reduce(into: [String: HardenerMetadata]()) {
            $0[$1.name] = $1
        }
        let detectors = snapshot.detectors.isEmpty
            ? findingsBySource.keys.map { DetectorMetadata(name: $0, homepage: "", docsURL: "") }
            : snapshot.detectors

        return detectors
            .map { detector in
                let displayName = detector.displayName
                let findings = findingsBySource[detector.name] ?? []
                let hardener = hardenerNameReferencedByDocumentation(detector.documentation).flatMap {
                    hardenersByName[$0]
                }
                guard !findings.isEmpty else {
                    let subtitle = if hardener?.hardened == true {
                        "Hardened."
                    } else if hardener == nil {
                        "Detector only."
                    } else {
                        "Hardener available."
                    }
                    return DashboardItem(
                        id: detector.name,
                        title: displayName.packageName,
                        kind: displayName.kind,
                        subtitle: subtitle,
                        detail: "",
                        documentation: detector.documentation,
                        hardenerDocumentation: hardener?.documentation,
                        isHardened: hardener?.hardened == true
                    )
                }
                let severity = detectorSeverityLevel(findings.map(\.severity))
                let affectedCount = findings.flatMap(\.affected).count
                let subtitle = affectedCount == 1 ? "1 trigger tripped" : "\(affectedCount) triggers tripped"
                return DashboardItem(
                    id: detector.name,
                    title: displayName.packageName,
                    kind: displayName.kind,
                    subtitle: subtitle,
                    detail: [
                        findings.first?.explanation ?? "Detector flagged this tool.",
                        findings.first?.solution,
                    ].compactMap(\.self).joined(separator: "\n\n"),
                    documentation: detector.documentation,
                    hardenerDocumentation: hardener?.documentation,
                    severity: severity.title,
                    isTriggered: true
                )
            }
            .sorted(by: detectorItemPrecedes)
    }

}

private func detectorItemPrecedes(_ lhs: DashboardItem, _ rhs: DashboardItem) -> Bool {
    if lhs.isTriggered != rhs.isTriggered { return lhs.isTriggered }
    if lhs.isTriggered {
        let lhsSeverity = detectorSeveritySortPriority(lhs.severity)
        let rhsSeverity = detectorSeveritySortPriority(rhs.severity)
        if lhsSeverity != rhsSeverity { return lhsSeverity < rhsSeverity }
    }
    if lhs.title != rhs.title {
        return lhs.title.localizedStandardCompare(rhs.title) == .orderedAscending
    }
    return (lhs.kind ?? "").localizedStandardCompare(rhs.kind ?? "") == .orderedAscending
}

private func blessedScriptItem(_ script: BlessedScript) -> DashboardItem {
    return DashboardItem(
        id: script.path,
        title: URL(fileURLWithPath: script.path).lastPathComponent,
        subtitle: blessedScriptDirectory(script.path),
        detail: script.path,
        blessingStatus: blessedScriptStatus(script)
    )
}

func blessedScriptStatus(_ script: BlessedScript) -> String {
    var info = stat()
    if script.path.withCString({ lstat($0, &info) != 0 && errno == ENOENT }) { return "Gone" }
    guard let data = try? readBlessedScript(path: script.path),
          let checksum = try? blessedScriptDeclaration(data: data).checksum
    else { return "Changed" }
    return checksum == script.checksum ? "Blessed" : "Changed"
}

private func blessedScriptItems(
    _ blessed: [BlessedScript],
    pending: BlessedScriptReviewRequest?
) -> [DashboardItem] {
    let scripts = blessed.map(blessedScriptItem)
    guard let pending, !scripts.contains(where: { $0.id == pending.path }) else { return scripts }
    return [
        DashboardItem(
            id: pending.path,
            title: URL(fileURLWithPath: pending.path).lastPathComponent,
            subtitle: blessedScriptDirectory(pending.path),
            detail: pending.path,
            blessingStatus: "Pending review"
        )
    ] + scripts
}

private func blessedScriptDirectory(_ path: String) -> String {
    NSString(string: URL(fileURLWithPath: path).deletingLastPathComponent().path).abbreviatingWithTildeInPath
}

private func detectorSeveritySortPriority(_ severity: String?) -> Int {
    severity.map(isMediumDetectorSeverity) == true ? 1 : 0
}

let installedAVCLIPath = "/usr/local/bin/av"

enum CLIInstallState: Sendable, Equatable {
    case missing
    case current
    case outdated

    var actionTitle: String? {
        switch self {
        case .missing: "Install av CLI"
        case .outdated: "Update av CLI"
        case .current: nil
        }
    }
}

private var bundledAVURL: URL? {
    guard let macOSURL = Bundle.main.executableURL?.deletingLastPathComponent() else { return nil }
    let url = macOSURL.appendingPathComponent("av")
    return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
}

func currentCLIInstallState(
    installedURL: URL = URL(fileURLWithPath: installedAVCLIPath),
    bundledURL: URL? = bundledAVURL,
    expectedRevision: Int? = Bundle.main.object(forInfoDictionaryKey: "AVCLIRevision") as? Int
) -> CLIInstallState {
    var metadata = stat()
    guard lstat(installedURL.path, &metadata) == 0 else {
        return errno == ENOENT ? .missing : .outdated
    }
    var parent = installedURL.deletingLastPathComponent()
    while true {
        guard cliInstallDirectoryIsProtected(parent.path) else { return .outdated }
        if parent.path == "/" { break }
        parent.deleteLastPathComponent()
    }
    guard let bundledURL,
          expectedRevision != nil,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == 0,
          metadata.st_mode & 0o7777 == 0o755,
          gitTransportPathHasNoACL(installedURL.path),
          FileManager.default.isExecutableFile(atPath: installedURL.path),
          executable(at: installedURL, satisfiesDesignatedRequirementOf: bundledURL)
    else {
        return .outdated
    }
    return cliInstallState(
        installedExists: true,
        installedTrusted: true,
        expectedRevision: expectedRevision,
        installedRevision: executableRevision(at: installedURL)
    )
}

private func cliInstallState(
    installedExists: Bool,
    installedTrusted: Bool,
    expectedRevision: Int?,
    installedRevision: Int?
) -> CLIInstallState {
    guard installedExists else { return .missing }
    guard installedTrusted,
          let expectedRevision,
          installedRevision == expectedRevision
    else { return .outdated }
    return .current
}

private func executableRevision(at url: URL) -> Int? {
    let process = Process()
    let output = Pipe()
    process.executableURL = url
    process.arguments = ["__version"]
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return nil
    }
    guard process.terminationStatus == 0 else { return nil }
    let value = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    return Int(value)
}

private func executable(at candidate: URL, satisfiesDesignatedRequirementOf trusted: URL) -> Bool {
    var trustedCode: SecStaticCode?
    var candidateCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(trusted as CFURL, [], &trustedCode) == errSecSuccess,
          let trustedCode,
          SecStaticCodeCreateWithPath(candidate as CFURL, [], &candidateCode) == errSecSuccess,
          let candidateCode
    else { return false }

    var information: CFDictionary?
    guard SecCodeCopySigningInformation(trustedCode, SecCSFlags(rawValue: kSecCSRequirementInformation), &information) == errSecSuccess,
          let dictionary = information as? [CFString: Any],
          let requirement = dictionary[kSecCodeInfoDesignatedRequirement] as! SecRequirement?
    else { return false }
    return SecStaticCodeCheckValidity(candidateCode, [], requirement) == errSecSuccess
}

private func cliInstallDirectoryIsProtected(_ path: String) -> Bool {
    var metadata = stat()
    return lstat(path, &metadata) == 0
        && metadata.st_mode & S_IFMT == S_IFDIR
        && metadata.st_uid == 0
        && metadata.st_mode & 0o022 == 0
        && gitTransportPathHasNoACL(path)
}

// Validate ancestors before creating children, inside the privileged transaction.
private func cliInstallerScript(sourcePath: String, requirement: String) -> String {
    let source = "'" + sourcePath.replacingOccurrences(of: "'", with: "'\\''") + "'"
    let requirement = "'=" + requirement.replacingOccurrences(of: "'", with: "'\\''") + "'"
    let command = """
    set -eu
    for directory in / /usr /usr/local /usr/local/bin; do
        if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
            /bin/mkdir -m 0755 "$directory"
        fi
        metadata=$(/usr/bin/stat -f '%u %p' "$directory")
        set -- $metadata
        acl=$(/bin/ls -lde "$directory")
        if [ "$1" != 0 ] || [ "$((0$2 & 0170022))" -ne "$((0040000))" ] || [ "$(printf '%s\\n' "$acl" | /usr/bin/wc -l)" -ne 1 ]; then
            echo "Unsafe CLI installation directory: $directory" >&2
            exit 1
        fi
    done
    if [ -d /usr/local/bin/av ] || [ -L /usr/local/bin/av ]; then
        echo "Unsafe CLI installation destination: /usr/local/bin/av" >&2
        exit 1
    fi
    stage=$(/usr/bin/mktemp -d /usr/local/bin/.av-install.XXXXXXXX)
    trap '/bin/rm -rf "$stage"' EXIT
    /usr/bin/install -S -m 0755 -o root -g wheel \(source) "$stage/av"
    /bin/chmod -N "$stage/av"
    /usr/bin/codesign --verify --strict --all-architectures -R \(requirement) "$stage/av"
    /bin/mv -f "$stage/av" /usr/local/bin/av
    """
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\n", with: "\\n")
    return """
    try
        do shell script "\(command)" with administrator privileges
        return "installed"
    on error errorMessage number errorNumber
        if errorNumber is -128 then return "cancelled"
        error errorMessage number errorNumber
    end try
    """
}

@MainActor private var isInstallingCLI = false

@MainActor
func installBundledCLI() async throws -> Bool {
    guard !isInstallingCLI else { return false }
    isInstallingCLI = true
    defer { isInstallingCLI = false }
    let bundledAVURL = try validatedBundledAVURL(mainExecutableURL: Bundle.main.executableURL)
    guard let teamIdentifier = selfTeamIdentifier() else { throw CLIInstallerError.bundledCLIUnavailable }
    let requirement = "identifier \"com.automicvault.av\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    let installed = try await runCLIInstallerScript(cliInstallerScript(sourcePath: bundledAVURL.path, requirement: requirement))
    if installed { NotificationCenter.default.post(name: cliInstallationDidFinish, object: nil) }
    return installed
}

private func runCLIInstallerScript(_ script: String) async throws -> Bool {
    // Keep both AppleScript execution and the administrator wait outside the app's
    // main actor. No quarantined script document is opened through LaunchServices.
    try await Task.detached(priority: .userInitiated) {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardOutput = output
        process.standardError = output
        try process.run()
        // Drain before waiting so an error cannot fill the pipe and deadlock.
        let message = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        process.waitUntilExit()
        guard process.terminationStatus == 0, message == "installed" || message == "cancelled" else {
            throw CLIInstallerError.commandFailed(message)
        }
        return message == "installed"
    }.value
}

private enum CLIInstallerError: LocalizedError {
    case bundledCLIUnavailable
    case commandFailed(String)

    var errorDescription: String? {
        switch self {
        case .bundledCLIUnavailable: "Bundled av CLI is unavailable."
        case .commandFailed(let message): message.isEmpty ? "Could not install av CLI." : message
        }
    }
}

@MainActor
func runUpdateToolbarSelfCheck() -> Int32 {
    let controller = AutomicVaultMainWindowController(checkForUpdates: {}, requestScan: {})
    controller.setAvailableUpdateVersion("2.8.0")
    return controller.rootView.model.availableUpdateVersion == "2.8.0" ? 0 : 1
}

@MainActor
func runDashboardSearchSelfCheck() -> Int32 {
    let controller = AutomicVaultMainWindowController(checkForUpdates: {}, requestScan: {})
    for section in [DashboardSection.detectors, .doctor, .blessedScripts, .secretUsage] {
        controller.rootView.model.searchText = "previous filter"
        controller.showSection(section)
        guard controller.rootView.model.selectedSection == section,
              controller.rootView.model.searchText.isEmpty else { return 1 }
    }
    guard authorityApprovalStateSelfCheck() else {
        print("authority Approval pending-state self-check failed")
        return 1
    }
    let accessRequest = AccessRequestRecord(
        date: Date(timeIntervalSince1970: 18_900),
        tool: "aws",
        command: "aws s3 ls",
        decision: "Approved",
        reason: "Always allowed from Codex",
        launcher: "Codex",
        callerPath: "/usr/local/bin/av",
        target: "/bin/zsh",
        cwd: "/tmp",
        keys: ["AWS_SECRET_ACCESS_KEY"],
        detail: "List buckets"
    )
    let model = DashboardModel(snapshot: DashboardSnapshot(
        detectors: [
            DetectorMetadata(name: "aws", homepage: "", docsURL: "", documentation: "Run `av harden aws`."),
            DetectorMetadata(name: "gh", homepage: "", docsURL: "", documentation: "Run `av harden gh`."),
            DetectorMetadata(name: "git", homepage: "", docsURL: ""),
        ],
        detectorFindings: [],
        hardenedTools: [
            HardenedTool(name: "aws", stubPath: "/usr/local/bin/aws", targetPath: "/opt/homebrew/bin/aws"),
            HardenedTool(name: "gh", stubPath: "/usr/local/bin/gh", targetPath: "/opt/homebrew/bin/gh"),
        ],
        hardeners: [
            HardenerMetadata(name: "aws", hardened: true),
            HardenerMetadata(name: "gh", hardened: false),
        ],
        secretGates: [SecretGate(
            id: "node",
            keyPatterns: ["NODE_AUTH_TOKEN"],
            routes: [],
            defaultProtection: .readOnly,
            appPolicies: []
        )],
        secrets: [
            StoredSecret(
                account: "AWS_TOKEN",
                accessibility: .afterFirstUnlock,
                directAccessLaunchers: [BlessedScriptLauncher(
                    bundleIdentifier: "com.example.launcher",
                    requirement: #"identifier "com.example.launcher" and anchor apple generic"#
                )]
            ),
            StoredSecret(account: "GITHUB_TOKEN"),
        ],
        accessRequests: [accessRequest],
        doctorIssues: [DoctorIssue(
            hardener: "aws",
            kind: "stub_not_first_on_path",
            command: "aws",
            message: "aws resolves to the unhardened target first",
            remediation: "Put /usr/local/bin first in PATH.",
            stubPath: "/usr/local/bin/aws",
            targetPath: "/opt/homebrew/bin/aws",
            resolvedPath: "/opt/homebrew/bin/aws"
        )]
    ))
    guard model.selectedSection == .overview,
          model.overviewTools.map(\.title) == ["aws", "gh"] else { return 1 }
    model.searchText = "gh"
    guard model.overviewTools.map(\.title) == ["gh"] else { return 1 }
    for section in DashboardSection.allCases {
        model.searchText = "unrelated filter"
        model.navigateFromOverview(to: section)
        guard model.selectedSection == section, model.searchText.isEmpty else { return 1 }
    }
    model.navigateFromOverview(to: .hardenedTools, itemID: "/usr/local/bin/gh")
    guard model.selectedItemID == "/usr/local/bin/gh" else { return 1 }
    model.navigateFromOverview(to: .hardenedTools, itemID: "missing")
    guard model.selectedItemID != "missing" else { return 1 }
    model.navigateFromOverview(to: .overview)
    // Render the actual SwiftUI layout at the minimum detail area and a larger window.
    if let directory = ProcessInfo.processInfo.environment["AV_OVERVIEW_RENDER_DIR"] {
        var renderSnapshot = model.snapshot
        renderSnapshot.hardenedTools += (1...12).map {
            HardenedTool(name: "tool-\($0)", targetPath: "/usr/local/bin/tool-\($0)")
        }
        let renderModel = DashboardModel(snapshot: renderSnapshot)
        for size in [NSSize(width: 590, height: 480), NSSize(width: 590, height: 550), NSSize(width: 980, height: 680)] {
            let host = NSHostingView(rootView: DashboardOverviewView(model: renderModel, checkForUpdates: {}))
            host.frame = NSRect(origin: .zero, size: size)
            host.layoutSubtreeIfNeeded()
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return 1 }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { return 1 }
            do {
                try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("overview-\(Int(size.width))-\(Int(size.height)).png"))
            } catch { return 1 }
        }
    }
    let gate = SecretGate(
        id: "gh",
        keyPatterns: ["GH_TOKEN_*"],
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: [SecretGatePolicy(
            bundleIdentifier: "com.openai.codex",
            requirement: #"identifier "com.openai.codex""#,
            protection: .readOnly
        )]
    )
    let gateHeight = NSHostingView(rootView: SecretGateDetailView(model: model, gate: gate)).fittingSize.height
    let appPolicy = gate.appPolicies[0]
    let launcherBundleRequirement = #"cdhash H"0123456789abcdef0123456789abcdef01234567""#
    let launcherBundle = LauncherBundleEnrollment(
        generation: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        displayName: "herdr",
        commandName: "herdr",
        bundleIdentifier: "com.automicvault.launcher-bundle.test",
        bundlePath: "/Applications/Automic Vault/herdr.app",
        launcherIdentifier: "com.automicvault.launcher-bundle.test.runner",
        launcherRequirement: launcherBundleRequirement,
        bundleCodeIdentifiers: [Data([1])],
        launcherCodeIdentifiers: [Data([2])],
        payloadCodeIdentifiers: [Data([3])],
        sourceSHA256: String(repeating: "1", count: 64),
        payloadSHA256: String(repeating: "2", count: 64),
        payloadEntitlements: [],
        runtimeRequirement: .hardened,
        signingKind: .adHoc,
        signingIdentity: nil
    )
    let launcherBundleDisplay = ApprovedAppDisplay(
        SecretGatePolicy(
            bundleIdentifier: "unknown",
            requirement: launcherBundleRequirement,
            protection: .readOnly
        ),
        launcherBundle: launcherBundle
    )
    let appRowHeight = NSHostingView(rootView: ApprovedAppRow(
        app: appPolicy,
        launcherBundle: nil,
        gate: gate,
        approval: model.authorityApproval,
        setProtection: { _ in },
        remove: {}
    ).frame(width: 500)).fittingSize.height
    let secretDetailHeight = model.selectedStoredSecret.map {
        NSHostingView(rootView: StoredSecretDetailView(model: model, secret: $0)).fittingSize.height
    }
    let aboutHeight = NSHostingView(rootView: AboutSettingsView(guiPath: "/usr/bin:/bin")).fittingSize.height
    let detachedProcessAccessHeight = NSHostingView(
        rootView: DetachedProcessAccessSettingsView()
    ).fittingSize.height
    let verifiedLauncherHelpersHeight = NSHostingView(
        rootView: VerifiedLauncherHelpersSettingsView()
    ).fittingSize.height
    let launcherHelperReviewSize = NSHostingView(rootView: LauncherHelperReviewView(
        model: model,
        review: LauncherHelperReview(
            signing: LauncherSigning(
                identifier: "com.example.app",
                teamIdentifier: "EXAMPLETEAM",
                path: "/Applications/Example.app",
                requirement: #"identifier "com.example.app""#,
                runtimeProtection: .hardened
            ),
            gate: gate,
            runtimeRequirement: .hardened,
            helpers: [VerifiedLauncherHelper(
                id: "example-helper",
                name: "Example Helper",
                appName: "Example",
                appBundleIdentifier: "com.example.app",
                appTeamIdentifier: "EXAMPLETEAM",
                helperSigningIdentifier: "com.example.helper",
                helperTeamIdentifier: "EXAMPLETEAM",
                relativePath: "Contents/Helpers/example-helper"
            )]
        )
    )).fittingSize
    let previousScriptData = Data("#!/usr/local/bin/av inject +TOKEN /bin/sh\necho old\n".utf8)
    let currentScriptData = Data("#!/usr/local/bin/av inject +TOKEN /bin/sh\necho current\n".utf8)
    guard let currentDeclaration = try? blessedScriptDeclaration(data: currentScriptData) else { return 1 }
    let selectedSectionBeforeReview = model.selectedSection
    var canceledBlessing = false
    model.reviewBlessing(BlessedScriptReviewRequest(
        path: "/tmp/av-dashboard-self-check-\(UUID().uuidString)",
        declaration: currentDeclaration,
        scriptData: currentScriptData,
        launcher: nil,
        previousContents: previousScriptData
    )) { outcome in
        if case .denied = outcome { canceledBlessing = true }
    }
    guard let pendingBlessing = model.pendingBlessing else { return 1 }
    let blessingReviewSize = NSHostingView(
        rootView: BlessedScriptReviewView(model: model, request: pendingBlessing)
    ).fittingSize
    model.cancelPendingBlessing()
    guard selectedSectionBeforeReview == model.selectedSection,
          blessingReviewSize.width == 720,
          blessingReviewSize.height == 680,
          canceledBlessing
    else {
        print("blessing modal self-check failed: \(selectedSectionBeforeReview), \(model.selectedSection), \(blessingReviewSize), \(canceledBlessing)")
        return 1
    }
    let changedScriptDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-rebless-self-check-\(UUID().uuidString)", isDirectory: true)
    let changedScriptURL = changedScriptDirectory.appendingPathComponent("script")
    guard (try? FileManager.default.createDirectory(
        at: changedScriptDirectory,
        withIntermediateDirectories: true
    )) != nil,
    (try? currentScriptData.write(to: changedScriptURL)) != nil,
    let previousDeclaration = try? blessedScriptDeclaration(data: previousScriptData)
    else { return 1 }
    defer { try? FileManager.default.removeItem(at: changedScriptDirectory) }
    let changedScript = BlessedScript(
        path: changedScriptURL.resolvingSymlinksInPath().path,
        checksum: previousDeclaration.checksum,
        keys: previousDeclaration.keys,
        target: previousDeclaration.target,
        replaceExistingEnv: previousDeclaration.replaceExistingEnv,
        allowMissingKeys: previousDeclaration.allowMissingKeys,
        capabilities: previousDeclaration.manifest.capabilities,
        launchers: [],
        reviewedContents: previousScriptData
    )
    var changedSnapshot = DashboardSnapshot.empty
    changedSnapshot.blessedScripts = [changedScript]
    let changedModel = DashboardModel(snapshot: changedSnapshot)
    guard model.scriptsNeedingReblessingCount == 0,
          changedModel.scriptsNeedingReblessingCount == 1
    else { return 1 }
    changedModel.searchText = "no matching script"
    guard changedModel.scriptsNeedingReblessingCount == 0 else { return 1 }
    changedModel.searchText = ""
    changedModel.reviewChanges(to: changedScript)
    guard changedModel.pendingBlessing?.scriptData == currentScriptData,
          changedModel.pendingBlessing?.previousContents == previousScriptData,
          blessedScriptDiff(previous: previousScriptData, current: currentScriptData)?.contains("- echo old") == true,
          blessedScriptDiff(previous: previousScriptData, current: currentScriptData)?.contains("+ echo current") == true
    else { return 1 }
    changedModel.cancelPendingBlessing()
    guard (try? previousScriptData.write(to: changedScriptURL)) != nil,
          changedModel.scriptsNeedingReblessingCount == 0,
          (try? FileManager.default.removeItem(at: changedScriptURL)) != nil,
          changedModel.scriptsNeedingReblessingCount == 0
    else { return 1 }
    model.selectSection(.secretGates)
    guard model.items.first?.title == "npm" else { return 1 }
    model.selectSection(.detectors)
    guard DashboardSection.allCases.last == .settings,
          model.count(for: .detectors) == 3,
          model.count(for: .doctor) == 1,
          model.count(for: .hardenedTools) == 2,
          model.count(for: .allSecrets) == 2,
          model.count(for: .secretUsage) == 1,
          model.selectedStoredSecret?.accessibility == .afterFirstUnlock,
          model.selectedStoredSecret?.directAccessLaunchers.count == 1,
          gateHeight > 0,
          secretDetailHeight.map({ $0 > 0 }) == true,
          aboutHeight > 0,
          detachedProcessAccessHeight > 0,
          verifiedLauncherHelpersHeight > 0,
          launcherHelperReviewSize == CGSize(width: 680, height: 520),
          appRowHeight < 140,
          launcherBundleDisplay.name == "herdr",
          launcherBundleDisplay.bundleIdentifier == launcherBundle.bundleIdentifier,
          launcherBundleDisplay.signingSummary == "Ad Hoc"
    else { return 1 }
    guard model.items.first(where: { $0.id == "aws" })?.isHardened == true,
          model.items.first(where: { $0.id == "git" })?.isHardened == false
    else { return 1 }
    guard model.items.first(where: { $0.id == "aws" })?.subtitle == "Hardened.",
          model.items.first(where: { $0.id == "gh" })?.subtitle == "Hardener available.",
          model.items.first(where: { $0.id == "git" })?.subtitle == "Detector only.",
          model.selectedItemID == "aws"
    else { return 1 }
    model.selectedItemID = "git"
    model.searchText = "aws"
    guard model.count(for: .detectors) == 1,
          model.count(for: .doctor) == 1,
          model.count(for: .hardenedTools) == 1,
          model.count(for: .allSecrets) == 1,
          model.selectedItemID == "aws"
    else { return 1 }
    guard cliInstallState(installedExists: false, installedTrusted: false, expectedRevision: 1, installedRevision: nil) == .missing,
          cliInstallState(installedExists: true, installedTrusted: true, expectedRevision: 1, installedRevision: 1) == .current,
          cliInstallState(installedExists: true, installedTrusted: true, expectedRevision: 1, installedRevision: 2) == .outdated,
          cliInstallState(installedExists: true, installedTrusted: true, expectedRevision: 1, installedRevision: nil) == .outdated,
          cliInstallState(installedExists: true, installedTrusted: false, expectedRevision: 1, installedRevision: 1) == .outdated,
          cliInstallState(installedExists: true, installedTrusted: true, expectedRevision: nil, installedRevision: 1) == .outdated,
          CLIInstallState.missing.actionTitle == "Install av CLI",
          CLIInstallState.outdated.actionTitle == "Update av CLI",
          CLIInstallState.current.actionTitle == nil
    else { return 1 }
    guard detectorSeverityLevel(["medium"]) == .medium,
          detectorSeverityLevel(["medium", "mid"]) == .medium,
          detectorSeverityLevel(["medium", "high"]) == .high,
          detectorSeverityLevel([]) == .high
    else { return 1 }
    let severitySortedItems = [
        DashboardItem(id: "medium", title: "alpha", subtitle: "", detail: "", severity: "MEDIUM", isTriggered: true),
        DashboardItem(id: "clean", title: "aardvark", subtitle: "", detail: ""),
        DashboardItem(id: "high", title: "zulu", subtitle: "", detail: "", severity: "HIGH", isTriggered: true),
    ].sorted(by: detectorItemPrecedes)
    guard severitySortedItems.map(\.id) == ["high", "medium", "clean"] else { return 1 }
    let scriptItem = blessedScriptItem(BlessedScript(
        path: "/dev/null/deploy.sh",
        checksum: "checksum",
        keys: [],
        target: "/bin/zsh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: [:],
        launchers: []
    ))
    let goneScriptItem = blessedScriptItem(BlessedScript(
        path: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path,
        checksum: "checksum",
        keys: [],
        target: "/bin/zsh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: [:],
        launchers: []
    ))
    guard scriptItem.title == "deploy.sh",
          scriptItem.subtitle == "/dev/null",
          scriptItem.blessingStatus == "Changed",
          goneScriptItem.blessingStatus == "Gone",
          blessedScriptDirectory("\(NSHomeDirectory())/Scripts/deploy.sh") == "~/Scripts"
    else { return 1 }
    model.searchText = ""
    model.selectSection(.settings)
    guard model.items.map(\.id) == [
        "touch-id-approval",
        "iphone-approval",
        "automatic-approval-feedback",
        "detached-process-access",
        "verified-launcher-helpers",
        "gpg-signing",
        "ssh-agent",
        "secret-name-access",
        "authorization-history-access",
        "about",
    ],
          model.selectedItemID == "touch-id-approval",
          guiPATH(environment: ["PATH": "/usr/bin:/bin"]) == "/usr/bin:/bin",
          guiPATH(environment: [:]) == "<unset>"
    else { return 1 }
    model.selectSection(.doctor)
    guard model.selectedItem?.title == "aws",
          model.selectedItem?.kind == nil,
          model.selectedItem?.detail.contains("Resolved: /opt/homebrew/bin/aws") == true,
          model.selectedItem?.detail.contains("\n\nRemediation:") == true
    else { return 1 }
    model.showAccessRequest(id: accessRequest.id, records: [accessRequest])
    guard model.selectedSection == .secretUsage,
          model.selectedItemID == accessRequest.id.uuidString,
          model.selectedAccessRequest == accessRequest,
          model.historyRows.count == 1,
          model.historySections.count == 1
    else { return 1 }
    let otherAccessRequest = AccessRequestRecord(
        date: accessRequest.date.addingTimeInterval(-60),
        tool: "git", command: "git status", decision: "Approved",
        reason: "Allowed", launcher: "Terminal", callerPath: "/usr/local/bin/av",
        target: "/bin/zsh", cwd: "/tmp", keys: [], detail: nil
    )
    model.showAccessRequest(id: otherAccessRequest.id, records: [accessRequest, otherAccessRequest])
    model.searchText = "Terminal"
    guard model.selectedAccessRequest == otherAccessRequest else { return 1 }
    model.showAccessRequest(id: accessRequest.id)
    guard model.searchText.isEmpty, model.selectedAccessRequest == accessRequest else { return 1 }
    model.searchText = "no matching history"
    guard model.historyRows.isEmpty, model.historySections.isEmpty,
          model.selectedAccessRequest == nil else { return 1 }
    model.searchText = ""
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(secondsFromGMT: 0)!
    let oldDate = Date(timeIntervalSince1970: 1_700_000_000)
    let recentDate = oldDate.addingTimeInterval(86_400)
    let days = historyDays([
        DashboardItem(id: "old", title: "", subtitle: "", detail: "", date: oldDate),
        DashboardItem(id: "recent", title: "recent", subtitle: "", detail: "", date: recentDate),
        DashboardItem(id: "older", title: "", subtitle: "", detail: "", date: oldDate.addingTimeInterval(-60)),
    ], calendar: calendar)
    guard days.count == 2,
          days[0].items.map(\.id) == ["recent"],
          days[1].items.map(\.id) == ["old", "older"]
    else { return 1 }
    let searchedDays = filterHistoryDays(days.map { HistorySearchDay(day: $0.day, items: $0.items) }, query: "recent")
    guard searchedDays.count == 1, searchedDays[0].items.map(\.id) == ["recent"],
          filterHistoryDays(days.map { HistorySearchDay(day: $0.day, items: $0.items) },
                            query: "recent", shouldCancel: { true }).isEmpty
    else { return 1 }
    let merged = mergeHistoryDays(days, historyDays([
        DashboardItem(id: "middle", title: "", subtitle: "", detail: "", date: oldDate.addingTimeInterval(-30)),
        DashboardItem(id: "newest", title: "", subtitle: "", detail: "", date: recentDate.addingTimeInterval(60)),
    ], calendar: calendar))
    guard merged.map(\.day) == days.map(\.day),
          merged[1] === days[1],
          merged[0].items.map(\.id) == ["newest", "recent"],
          merged[1].items.map(\.id) == ["old", "middle", "older"]
    else { return 1 }
    var pageSnapshot = DashboardSnapshot.empty
    pageSnapshot.accessRequests = [accessRequest]
    let pageModel = DashboardModel(snapshot: pageSnapshot)
    pageModel.appendHistoryRecords([otherAccessRequest])
    guard pageModel.historyRows.map(\.id) == [accessRequest.id.uuidString, otherAccessRequest.id.uuidString],
          pageModel.historySections.count == 1 else { return 1 }
    pageModel.searchText = "Terminal"
    let nextPageRecord = AccessRequestRecord(
        date: accessRequest.date.addingTimeInterval(86_400),
        tool: "git", command: "git log", decision: "Approved",
        reason: "Allowed", launcher: "Terminal", callerPath: "/usr/local/bin/av",
        target: "/bin/zsh", cwd: "/tmp", keys: [], detail: nil
    )
    pageModel.appendHistoryRecords([nextPageRecord])
    guard pageModel.historyRows.map(\.id) == [nextPageRecord.id.uuidString, otherAccessRequest.id.uuidString],
          pageModel.historySections.count == 2,
          pageModel.historySections[0].items.map(\.id) == [nextPageRecord.id.uuidString],
          pageModel.historySections[1].items.map(\.id) == [otherAccessRequest.id.uuidString]
    else { return 1 }
    pageModel.selectSection(.secretUsage)
    pageModel.searchText = "no matching history"
    pageModel.searchText = ""
    guard pageModel.selectedItemID == nextPageRecord.id.uuidString else { return 1 }
    pageModel.selectSection(.settings)
    pageModel.searchText = "no matching history"
    guard !pageModel.historyRows.isEmpty,
          pageModel.count(for: .secretUsage) == pageModel.snapshot.accessRequests.count,
          pageModel.authorizationHistoryDayCount == 1
    else { return 1 }
    pageModel.selectSection(.secretUsage)
    guard pageModel.historyRows.isEmpty, pageModel.selectedItemID == nil else { return 1 }
    var boundedSnapshot = DashboardSnapshot.empty
    boundedSnapshot.accessRequests = Array(repeating: accessRequest, count: 51)
    let boundedModel = DashboardModel(snapshot: boundedSnapshot)
    guard boundedModel.recentAccessRequests.count == 50,
          boundedModel.accessRequests(for: DashboardItem(
            id: "aws", title: "aws", subtitle: "", detail: ""
          )).count == 50
    else { return 1 }
    return 0
}

enum DashboardSection: String, CaseIterable, Identifiable {
    case overview
    case detectors
    case hardenedTools
    case secretGates
    case blessedScripts
    case launcherBundles
    case allSecrets
    case proxySessions
    case secretUsage
    case doctor
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: String(localized: "Overview")
        case .detectors: String(localized: "Detectors")
        case .doctor: String(localized: "Doctor")
        case .hardenedTools: String(localized: "Hardened Tools")
        case .secretGates: String(localized: "Authorization Gates")
        case .blessedScripts: String(localized: "Blessed Scripts")
        case .launcherBundles: String(localized: "Launcher Bundles")
        case .allSecrets: String(localized: "Secrets")
        case .proxySessions: String(localized: "Credential Proxies")
        case .secretUsage: String(localized: "Authorization History")
        case .settings: String(localized: "Settings")
        }
    }

    var systemImage: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .detectors: String(localized: "sensor.tag.radiowaves.forward")
        case .doctor: String(localized: "stethoscope")
        case .hardenedTools: String(localized: "hammer")
        case .secretGates: String(localized: "lock.shield")
        case .blessedScripts: String(localized: "checkmark.seal")
        case .launcherBundles: String(localized: "shippingbox")
        case .allSecrets: String(localized: "key")
        case .proxySessions: String(localized: "arrow.left.arrow.right.circle")
        case .secretUsage: String(localized: "clock.arrow.circlepath")
        case .settings: String(localized: "gearshape")
        }
    }
}

struct DashboardItem: Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    let kind: String?
    let subtitle: String
    let detail: String
    let documentation: String
    let hardenerDocumentation: String?
    let severity: String?
    let blessingStatus: String?
    let isTriggered: Bool
    let isHardened: Bool
    let date: Date?

    init(id: String, title: String, kind: String? = nil, subtitle: String, detail: String, documentation: String = "", hardenerDocumentation: String? = nil, severity: String? = nil, blessingStatus: String? = nil, isTriggered: Bool = false, isHardened: Bool = false, date: Date? = nil) {
        self.id = id
        self.title = title
        self.kind = kind
        self.subtitle = subtitle
        self.detail = detail
        self.documentation = documentation
        self.hardenerDocumentation = hardenerDocumentation
        self.severity = severity
        self.blessingStatus = blessingStatus
        self.isTriggered = isTriggered
        self.isHardened = isHardened
        self.date = date
    }
}

struct DashboardRootView: View {
    @ObservedObject var model: DashboardModel
    @ObservedObject private var proxySessions = ProxySessionViewModel.shared
    let checkForUpdates: () -> Void
    let requestScan: () -> Void

    var body: some View {
        Group {
            if model.selectedSection == .overview {
                NavigationSplitView {
                    DashboardSidebarView(model: model)
                        .navigationSplitViewColumnWidth(min: 186, ideal: 227, max: 250)
                } detail: {
                    DashboardOverviewView(model: model, checkForUpdates: checkForUpdates)
                        .toolbar {
                            Button {
                                requestScan()
                                model.reload()
                            } label: {
                                Label("Refresh", systemImage: "arrow.clockwise")
                            }
                            .disabled(model.isReloading)
                        }
                }
            } else {
        NavigationSplitView() {
            DashboardSidebarView(model: model)
                .navigationSplitViewColumnWidth(min: 186, ideal: 227, max: 250)
        } content: {
            DashboardListView(model: model)
                .navigationSplitViewColumnWidth(min: 168, ideal: 255)
                .toolbar {
                    if #available(macOS 27, *),
                       model.selectedSection == .allSecrets || model.selectedSection == .launcherBundles {
                        ToolbarSpacer(.flexible)
                    }
                    if model.selectedSection == .allSecrets {
                        ToolbarItem {
                            Button {
                                model.isAddingSecret = true
                            } label: {
                                Label("Add Secret", systemImage: "plus")
                            }
                            .labelStyle(.iconOnly)
                            .help("Add Secret")
                        }
                    }
                    if model.selectedSection == .launcherBundles {
                        ToolbarItem {
                            Button {
                                model.isCreatingLauncherBundle = true
                            } label: {
                                Label("Create Launcher Bundle", systemImage: "plus")
                            }
                            .labelStyle(.iconOnly)
                            .help("Create Launcher Bundle")
                        }
                    }
                }
        } detail: {
            DashboardDetailView(model: model)
                .navigationSplitViewColumnWidth(min: 320, ideal: 320)
                .toolbar {
                    Spacer()
                    if let version = model.availableUpdateVersion {
                        Button(action: checkForUpdates) {
                            Label("Update to v\(version)", systemImage: "arrow.down.circle")
                        }
                        .labelStyle(.titleAndIcon)
                        .help("Install Automic Vault v\(version)")
                    }
                    if let cliActionTitle = model.cliInstallState?.actionTitle {
                        Button {
                            model.installCLI()
                        } label: {
                            Label(cliActionTitle, systemImage: "terminal")
                        }
                        .labelStyle(.titleAndIcon)
                        .help("\(cliActionTitle) at /usr/local/bin/av")
                    }
                    if model.selectedSection == .secretGates, let gate = model.selectedSecretGate {
                        if model.isDiscoveringLauncherHelpers {
                            ProgressView()
                                .controlSize(.small)
                                .help("Inspecting the selected app for Verified Launcher Helpers")
                                .accessibilityLabel("Inspecting the selected app for Verified Launcher Helpers")
                            Button {
                                model.cancelLauncherHelperDiscovery()
                            } label: {
                                Image(systemName: "xmark")
                            }
                            .help("Cancel App Inspection")
                            .accessibilityLabel("Cancel App Inspection")
                        } else {
                            AuthorityApprovalButton(
                                title: "Add Verified Launcher", approval: model.authorityApproval,
                                action: "gate-launcher:\(gate.id)"
                            ) { model.addApp(to: gate) }
                            .labelStyle(.titleAndIcon)
                            .help("Add Verified Launcher")
                        }
                    }
                    if model.selectedSection == .blessedScripts {
                        if let script = model.selectedBlessedScript {
                            AuthorityApprovalButton(
                                title: "Add Verified Launcher", approval: model.authorityApproval,
                                action: "script-launcher:\(script.path)"
                            ) { model.addApp(to: script) }
                            .labelStyle(.titleAndIcon)
                            .help("Add Verified Launcher")
                        }
                    }
                    if model.selectedSection == .settings,
                       model.selectedItem?.id == "secret-name-access" {
                        AuthorityApprovalButton(
                            title: "Add Verified Launcher",
                            approval: model.authorityApproval, action: "secret-name-access"
                        ) { model.addSecretNameAccessApp() }
                        .labelStyle(.titleAndIcon)
                        .help("Allow Verified Launcher to List Secret Names")
                    }
                    if model.selectedSection == .settings,
                       model.selectedItem?.id == "authorization-history-access" {
                        AuthorityApprovalButton(
                            title: "Add Verified Launcher",
                            approval: model.authorityApproval, action: "authorization-history-access"
                        ) { model.addAuthorizationHistoryAccessApp() }
                        .labelStyle(.titleAndIcon)
                        .help("Allow Verified Launcher to Read Authorization History")
                    }
                    Button {
                        requestScan()
                        model.reload()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(model.isReloading)
                    .help(model.isReloading ? "Refresh in Progress" : "Refresh")
                    .accessibilityLabel("Refresh")
                }
        }
            }
        }
        .searchable(text: $model.searchText, placement: .sidebar, prompt: "Search")
        .onChange(of: proxySessions.historyRevision) { _, _ in
            model.reloadAccessRequests()
        }
        .sheet(isPresented: $model.isCreatingLauncherBundle) {
            CreateLauncherBundleView(model: model)
        }
        .sheet(isPresented: Binding(
            get: { model.pendingBlessing != nil },
            set: { if !$0 { model.cancelPendingBlessing() } }
        )) {
            if let request = model.pendingBlessing {
                BlessedScriptReviewView(model: model, request: request)
            }
        }
        .sheet(item: Binding(
            get: { model.pendingLauncherHelperReview },
            set: { if $0 == nil { model.cancelLauncherHelperReview() } }
        )) { review in
            LauncherHelperReviewView(model: model, review: review)
        }
    }
}

private struct DashboardSidebarView: View {
    @ObservedObject var model: DashboardModel

    var body: some View {
        List(selection: sectionSelection) {
            ForEach(DashboardSection.allCases) { section in
                sidebarRow(section)
                    .tag(section)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: 8) {
                Circle()
                    .fill(.green)
                    .frame(width: 8, height: 8)
                    .shadow(color: .green.opacity(0.55), radius: 2)
                Text("Vulnerability Monitor Active")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
    }

    private var sectionSelection: Binding<DashboardSection?> {
        Binding {
            model.selectedSection
        } set: { section in
            if let section {
                model.selectSection(section)
            }
        }
    }

    private func sidebarRow(_ section: DashboardSection) -> some View {
        HStack(spacing: 8) {
            sidebarIcon(section)
            Text(section.title)
                .font(.system(size: 14, weight: .regular))
                .lineLimit(1)
            Spacer(minLength: 0)
            let count = model.count(for: section)
            let reblessingCount = section == .blessedScripts ? model.scriptsNeedingReblessingCount : 0
            if section == .secretUsage, model.authorizationHistoryDayCount > 0 {
                SidebarCountText(text: "\(model.authorizationHistoryDayCount)d")
                    .fixedSize()
            } else if count > 0 {
                if section == .detectors, model.snapshot.flaggedDetectorCount > 0, model.selectedSection != .detectors {
                    DetectorCountPill(
                        count: count,
                        color: detectorSeverityLevel(model.snapshot.detectorFindings.map(\.severity)).color
                    )
                        .fixedSize()
                } else if section == .doctor, model.selectedSection != .doctor {
                    DetectorCountPill(count: count, color: .red)
                        .fixedSize()
                } else if section == .blessedScripts,
                          model.selectedSection != .blessedScripts,
                          reblessingCount > 0 {
                    DetectorCountPill(count: reblessingCount, color: .orange)
                        .fixedSize()
                        .accessibilityLabel("Scripts needing reblessing: \(reblessingCount)")
                } else {
                    SidebarCountText(text: count.formatted())
                        .fixedSize()
                }
            }
        }
    }

    private func sidebarIcon(_ section: DashboardSection) -> some View {
        Image(systemName: section.systemImage)
            .font(.system(size: 14, weight: .semibold))
            .frame(width: 20, height: 20)
    }
}

private struct DashboardListView: View {
    @ObservedObject var model: DashboardModel

    var body: some View {
        let items = model.items
        Group {
            if items.isEmpty {
                VStack(spacing: 12) {
                    if model.selectedSection == .secretUsage && model.isSearchingHistory {
                        ProgressView()
                            .controlSize(.large)
                    } else if model.selectedSection == .secretUsage && model.isRefreshingHistory {
                        ProgressView("Loading Authorization History…")
                    } else if model.selectedSection == .secretUsage && model.historyLoadFailed,
                       model.historyOlderPageCursor == nil {
                        Text("Authorization History unavailable")
                            .foregroundStyle(.secondary)
                        Button("Retry") { model.reloadAccessRequests() }
                    } else {
                        EmptyListView(section: model.selectedSection)
                    }
                    if model.selectedSection == .secretUsage,
                       !model.isRefreshingHistory,
                       model.historyOlderPageCursor != nil {
                        if model.historyLoadFailed {
                            Text("Older Authorization History unavailable")
                                .foregroundStyle(.secondary)
                        }
                        if model.hasSearchQuery {
                            Text("Search covers loaded records. Load older records to continue searching.")
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        if model.isLoadingOlderHistory {
                            ProgressView("Loading older records…")
                        } else {
                            Button("Load Older Records") { model.loadMoreHistory(retry: true) }
                        }
                    }
                    if model.isReloading && model.selectedSection != .secretUsage {
                        ProgressView()
                            .controlSize(.large)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                itemList(items)
            }
        }
        .sheet(isPresented: $model.isAddingSecret) {
            AddSecretView(model: model)
        }
    }

    private var itemSelection: Binding<String?> {
        Binding {
            model.selectedItemID
        } set: { id in
            model.selectedItemID = id
        }
    }

    private func itemList(_ items: [DashboardItem]) -> some View {
        List(selection: itemSelection) {
            rows(items)
            if model.selectedSection == .secretUsage,
               model.historyOlderPageCursor != nil {
                if model.hasSearchQuery {
                    Text("Search covers loaded records. Load older records to continue searching.")
                        .foregroundStyle(.secondary)
                }
                if model.isRefreshingHistory {
                    ProgressView("Loading Authorization History…")
                } else if model.historyLoadFailed {
                    Button("Retry Loading Older Records") {
                        model.loadMoreHistory(retry: true)
                    }
                } else if model.isLoadingOlderHistory {
                    ProgressView("Loading older records…")
                } else {
                    Button("Load Older Records") { model.loadMoreHistory() }
                        .onAppear {
                            if !model.hasSearchQuery { model.loadMoreHistory() }
                        }
                }
            }
        }
        .listStyle(.inset)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(.bar)
                .mask(LinearGradient(colors: [.black, .clear], startPoint: .top, endPoint: .bottom))
                .frame(height: 52)
                .padding(.leading, -100)
                .offset(y: -52)
                .allowsHitTesting(false)
        }
    }

    @ViewBuilder
    private func rows(_ items: [DashboardItem]) -> some View {
        if model.selectedSection == .secretUsage {
            ForEach(model.historySections, id: \.day) { group in
                Section {
                    ForEach(group.items) { item in
                        DashboardRow(item: item)
                            .tag(item.id)
                    }
                } header: {
                    Text(group.day, format: .dateTime.weekday(.wide).month(.wide).day().year())
                }
            }
        } else {
            ForEach(items) { item in
                DashboardRow(item: item)
                    .tag(item.id)
            }
        }
    }
}

private struct HistorySearchDay: Sendable {
    let day: Date
    let items: [DashboardItem]
}

private func historyMatchesSearch(_ item: DashboardItem, query: String) -> Bool {
    item.title.localizedCaseInsensitiveContains(query)
        || item.subtitle.localizedCaseInsensitiveContains(query)
        || item.detail.localizedCaseInsensitiveContains(query)
}

private func filterHistoryDays(
    _ groups: [HistorySearchDay], query: String, shouldCancel: () -> Bool = { false }
) -> [HistorySearchDay] {
    var result: [HistorySearchDay] = []
    for group in groups {
        if shouldCancel() { return [] }
        var items: [DashboardItem] = []
        for (index, item) in group.items.enumerated() {
            if index.isMultiple(of: 64), shouldCancel() { return [] }
            if historyMatchesSearch(item, query: query) { items.append(item) }
        }
        if !items.isEmpty { result.append(HistorySearchDay(day: group.day, items: items)) }
    }
    return result
}

final class HistoryDay {
    let day: Date
    var items: [DashboardItem]

    init(day: Date, items: [DashboardItem]) {
        self.day = day
        self.items = items
    }
}

private func historyItemPrecedes(_ lhs: DashboardItem, _ rhs: DashboardItem) -> Bool {
    if lhs.date == rhs.date { return lhs.id < rhs.id }
    return (lhs.date ?? .distantPast) > (rhs.date ?? .distantPast)
}

private func historyDays(
    _ items: [DashboardItem], calendar: Calendar = .autoupdatingCurrent
) -> [HistoryDay] {
    Dictionary(grouping: items) { calendar.startOfDay(for: $0.date ?? .distantPast) }
        .map { day, items in
            HistoryDay(day: day, items: items.sorted(by: historyItemPrecedes))
        }
        .sorted { $0.day > $1.day }
}

private func mergeHistoryDays(_ existing: [HistoryDay], _ added: [HistoryDay]) -> [HistoryDay] {
    var result = existing
    for group in added {
        guard let index = result.firstIndex(where: { $0.day == group.day }) else {
            result.append(group)
            continue
        }
        if let last = result[index].items.last, let first = group.items.first,
           historyItemPrecedes(last, first) {
            result[index].items += group.items
        } else {
            result[index].items = (result[index].items + group.items)
                .sorted(by: historyItemPrecedes)
        }
    }
    result.sort { $0.day > $1.day }
    return result
}

private struct DashboardDetailView: View {
    @ObservedObject var model: DashboardModel

    var body: some View {
        ScrollView {
            if model.selectedSection == .secretGates, let gate = model.selectedSecretGate {
                SecretGateDetailView(model: model, gate: gate)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .blessedScripts,
                      let script = model.selectedBlessedScript {
                BlessedScriptDetailView(model: model, script: script)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .secretUsage, let record = model.selectedAccessRequest {
                AuthorizationHistoryDetailView(record: record)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .secretUsage,
                      let status = model.pendingAccessRequestStatus {
                Text(status)
                    .foregroundStyle(.secondary)
                    .padding(22)
            } else if model.selectedSection == .launcherBundles,
                      let enrollment = model.selectedLauncherBundle {
                LauncherBundleDetailView(model: model, enrollment: enrollment)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .proxySessions,
                      let session = model.selectedProxySession {
                ProxySessionDetailView(session: session, history: model.recentAccessRequests)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .settings {
                if model.selectedItem?.id == "touch-id-approval" {
                    TouchIDApprovalSettingsView()
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "iphone-approval" {
                    IPhoneApprovalSettingsView()
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "automatic-approval-feedback" {
                    AutomaticApprovalFeedbackSettingsView()
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "detached-process-access" {
                    DetachedProcessAccessSettingsView()
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "verified-launcher-helpers" {
                    VerifiedLauncherHelpersSettingsView()
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "ssh-agent" {
                    SSHAgentSettingsView(onCredentialSaved: model.reload, onOpenGate: { model.showSecretGate(id: "ssh-agent") })
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "gpg-signing" {
                    GPGSigningSettingsView(onCredentialSaved: model.reload)
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "authorization-history-access" {
                    AuthorizationHistoryAccessSettingsView(model: model)
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "about" {
                    AboutSettingsView()
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    SecretNameAccessSettingsView(model: model)
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else if model.selectedSection == .detectors, let item = model.selectedItem {
                ReferenceDetailView(
                    item: item,
                    summary: detectorSummary(for: item),
                    referenceTitle: "Detector Reference",
                    fallbackDocumentation: "No detector documentation is bundled for this item.",
                    badge: item.isTriggered
                        ? ReferenceBadge(title: "Flagged", color: detectorSeverityColor(item.severity))
                        : ReferenceBadge(title: "✓ Passed", color: .green)
                )
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .hardenedTools, let item = model.selectedItem {
                HardenedToolDetailView(
                    item: item,
                    records: model.accessRequests(for: item)
                )
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .allSecrets, let secret = model.selectedStoredSecret {
                StoredSecretDetailView(model: model, secret: secret)
                    .id(secret.account)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if let item = model.selectedItem {
                VStack(alignment: .leading, spacing: 18) {
                    Text(item.title)
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(3)
                    Text(item.subtitle)
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                    InfoBlock(
                        title: model.selectedSection.title,
                        text: item.detail,
                        rendersMarkdown: model.selectedSection == .doctor
                    )
                    if let error = model.errorMessage {
                        InfoBlock(title: "Error", text: error)
                    }
                }
                .padding(.horizontal, 22)
                .padding(.top, 32)
                .padding(.bottom, 28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .contentMargins(.top, 24, for: .scrollContent)
        .ignoresSafeArea(.container, edges: .top)
        .background(.ultraThinMaterial)
        .sheet(isPresented: $model.isRenamingSecret) {
            if let secret = model.selectedStoredSecret {
                RenameSecretView(model: model, account: secret.account, valueCount: secret.values.count)
            }
        }
    }
}

private struct DashboardRow: View {
    let item: DashboardItem

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(item.title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .layoutPriority(1)
                if let status = item.blessingStatus {
                    BlessingStatusPill(status: status)
                }
                if let kind = item.kind {
                    DetectorKindPill(kind: kind)
                }
                if item.isHardened, !item.isTriggered {
                    HardenedDetectorPill()
                        .fixedSize()
                }
                if let severity = item.severity {
                    Text(severity)
                        .font(.system(size: 10, weight: .bold))
                        .lineLimit(1)
                        .padding(.horizontal, 6)
                        .frame(height: 18)
                        .outlinedPill(detectorSeverityColor(severity))
                        .layoutPriority(1)
                }
            }
            Group {
                if let date = item.date {
                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                        switch item.subtitle {
                        case "Approved":
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .accessibilityLabel("Approved")
                        case "Denied":
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.red)
                                .accessibilityLabel("Denied")
                        default:
                            Text(item.subtitle)
                        }
                        VStack(alignment: .leading, spacing: 0) {
                            Text(date.formatted(.relative(presentation: .named, unitsStyle: .abbreviated)))
                            Text(date.formatted(date: .abbreviated, time: .standard))
                                .foregroundStyle(.tertiary)
                        }
                    }
                } else {
                    Text(item.subtitle)
                }
            }
            .font(.system(size: 12))
            .foregroundStyle(.secondary)
            .lineLimit(2)
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
        .frame(minHeight: 54, alignment: .topLeading)
    }
}

private struct EmptyListView: View {
    let section: DashboardSection

    var body: some View {
        VStack(spacing: 6) {
            Text(emptyText)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
            if let learnMoreURL {
                Link("Learn more", destination: learnMoreURL)
                    .font(.system(size: 12))
            }
        }
        .padding()
    }

    private var emptyText: String {
        switch section {
        case .overview: String(localized: "Review your Tools and configuration")
        case .detectors: String(localized: "Detectors identify developer tool configurations that could expose secrets")
        case .doctor: String(localized: "Doctor identifies problems with your Automic Vault installation and explains how to fix them")
        case .hardenedTools: String(localized: "Hardened Tools secure developer tools with granular access to secrets")
        case .secretGates: String(localized: "Authorization Gates control which operations Verified Launchers may perform through specific Tools")
        case .blessedScripts: String(localized: "Blessed Scripts bind exact scripts to declared Secrets, Targets, and per-Gate capabilities")
        case .launcherBundles: String(localized: "Create a Verified Launcher from one unsigned Mach-O command-line tool")
        case .allSecrets: String(localized: "Secrets are credentials stored securely in the macOS Data Protection Keychain")
        case .proxySessions: String(localized: "Active `av proxy` sessions appear here while their target process is running")
        case .secretUsage: String(localized: "Authorization History records requests and their authorization decisions")
        case .settings: String(localized: "Settings control how Automic Vault behaves")
        }
    }

    private var learnMoreURL: URL? {
        switch section {
        case .overview: nil
        case .detectors: detectionAndHardeningDocumentationURL
        case .doctor: detectionAndHardeningDocumentationURL
        case .hardenedTools: toolHardeningDocumentationURL
        case .secretGates: authorizationGatesDocumentationURL
        case .blessedScripts: blessedScriptsDocumentationURL
        case .launcherBundles: launcherBundleDocumentationURL
        case .allSecrets: choosingAMechanismDocumentationURL
        case .proxySessions: secretProxyDocumentationURL
        case .secretUsage: authorizationHistoryDocumentationURL
        case .settings: nil
        }
    }
}

private struct CreateLauncherBundleView: View {
    @ObservedObject var model: DashboardModel
    @Environment(\.dismiss) private var dismiss
    @State private var sourceURL: URL?
    @State private var displayName = ""
    @State private var commandName = ""
    @State private var allowJIT = false
    @State private var allowUnsignedExecutableMemory = false
    @State private var disableLibraryValidation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Create Launcher Bundle")
                .font(.system(size: 20, weight: .semibold))
            Text("Bundle one Mach-O command-line tool so it can become a Verified Launcher.")
                .foregroundStyle(.secondary)
            if let candidate = model.pendingLauncherBundle {
                review(candidate.enrollment)
            } else {
                configuration
            }

            if let error = model.errorMessage {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") {
                    model.cancelLauncherBundleCreation()
                    dismiss()
                }
                    .disabled(model.isBuildingLauncherBundle)
                Button(actionTitle) {
                    if model.pendingLauncherBundle != nil {
                        model.installPendingLauncherBundle()
                    } else {
                        guard let sourceURL else { return }
                        model.createLauncherBundle(LauncherBundleOptions(
                            sourceURL: sourceURL,
                            displayName: displayName,
                            commandName: commandName,
                            allowJIT: allowJIT,
                            allowUnsignedExecutableMemory: allowUnsignedExecutableMemory,
                            disableLibraryValidation: disableLibraryValidation
                        ))
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(
                    (model.pendingLauncherBundle == nil && !canCreate)
                        || model.isBuildingLauncherBundle
                )
            }
        }
        .padding(22)
        .frame(width: 500)
        .onDisappear {
            if model.pendingLauncherBundle != nil { model.cancelLauncherBundleCreation() }
        }
    }

    private var actionTitle: String {
        if model.isBuildingLauncherBundle { return "Working…" }
        return model.pendingLauncherBundle == nil ? "Prepare" : "Install & Enroll"
    }

    private var configuration: some View {
        Group {
            LabeledContent(
                "Installs in",
                value: NSString(string: launcherBundleManagedDirectory().path).abbreviatingWithTildeInPath + "/"
            )
            LabeledContent("CLI executable") {
                Button(sourceURL?.lastPathComponent ?? "Choose…") { chooseSource() }
            }
            TextField("Name", text: $displayName)
                .textFieldStyle(.roundedBorder)
            TextField("Command", text: $commandName)
                .textFieldStyle(.roundedBorder)
            if let command = launcherBundleCommandName(from: commandName) {
                Text("Runs as \(launcherBundleCommandURL(named: command).path). Installation requests administrator approval.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            DisclosureGroup("Compatibility exceptions") {
                VStack(alignment: .leading, spacing: 10) {
                    Toggle("Allow JIT compilation", isOn: $allowJIT)
                    Toggle("Allow unsigned executable memory", isOn: $allowUnsignedExecutableMemory)
                    Toggle("Disable library validation", isOn: $disableLibraryValidation)
                    if disableLibraryValidation {
                        Text(libraryValidationWarning)
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                .padding(.top, 8)
            }
        }
    }

    private func review(_ enrollment: LauncherBundleEnrollment) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Review the completed bundle before enrolling it.")
                .font(.headline)
            LabeledContent("Name", value: enrollment.displayName)
            if let commandPath = enrollment.commandPath {
                LabeledContent("Command", value: commandPath)
            }
            LabeledContent(
                "Install location",
                value: NSString(string: enrollment.bundlePath).abbreviatingWithTildeInPath
            )
            LabeledContent("Signing", value: enrollment.signingIdentity ?? enrollment.signingKind.title)
            LabeledContent(
                "Runtime",
                value: enrollment.runtimeRequirement == .hardened
                    ? "Hardened Runtime"
                    : "Hardened Runtime; library validation disabled"
            )
            LabeledContent(
                "Entitlements",
                value: enrollment.payloadEntitlements.isEmpty
                    ? "None"
                    : enrollment.payloadEntitlements.joined(separator: ", ")
            )
            Text("Selected source SHA-256\n\(enrollment.sourceSHA256)")
            Text("Final signed payload SHA-256\n\(enrollment.payloadSHA256)")
        }
        .font(.system(.body, design: .monospaced))
        .textSelection(.enabled)
    }

    private var canCreate: Bool {
        sourceURL != nil
            && launcherBundleDisplayName(from: displayName) != nil
            && launcherBundleCommandName(from: commandName) != nil
    }

    private func chooseSource() {
        let panel = NSOpenPanel()
        panel.title = "Choose a Mach-O CLI Executable"
        panel.prompt = "Choose"
        panel.allowedContentTypes = [.data]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        let homebrewBin = URL(fileURLWithPath: "/opt/homebrew/bin", isDirectory: true)
        panel.directoryURL = FileManager.default.fileExists(atPath: homebrewBin.path)
            ? homebrewBin
            : URL(fileURLWithPath: "/usr/local/bin", isDirectory: true)
        guard panel.runModal() == .OK, let selected = panel.url else { return }
        sourceURL = selected.resolvingSymlinksInPath().standardizedFileURL
        if displayName.isEmpty { displayName = selected.lastPathComponent }
        if commandName.isEmpty { commandName = selected.lastPathComponent }
        model.errorMessage = nil
    }
}

private struct LauncherBundleDetailView: View {
    @ObservedObject var model: DashboardModel
    let enrollment: LauncherBundleEnrollment
    @State private var isConfirmingDelete = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(enrollment.displayName)
                .font(.system(size: 24, weight: .semibold))
            Label("Enrolled Launcher Bundle", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
            Group {
                LabeledContent("Signing", value: enrollment.signingKind.title)
                LabeledContent("Location", value: enrollment.bundlePath)
                LabeledContent("Bundle identifier", value: enrollment.bundleIdentifier)
                LabeledContent("Created", value: enrollment.createdAt.formatted())
            }
            .textSelection(.enabled)

            VStack(alignment: .leading, spacing: 6) {
                Text("Command").font(.headline)
                Text(enrollment.commandPath ?? enrollment.bundlePath + "/Contents/MacOS/launcher")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Pinned hashes").font(.headline)
                Text("Selected source: \(enrollment.sourceSHA256)")
                Text("Signed payload: \(enrollment.payloadSHA256)")
                Text("Entitlements: \(enrollment.payloadEntitlements.isEmpty ? "None" : enrollment.payloadEntitlements.joined(separator: ", "))")
            }
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)

            if let warning = launcherRuntimeWarning(enrollment.runtimeRequirement) {
                Label(warning, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            if let error = model.errorMessage {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Button("Show in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([
                        URL(fileURLWithPath: enrollment.bundlePath)
                    ])
                }
                Button("Delete Launcher Bundle", role: .destructive) {
                    isConfirmingDelete = true
                }
            }
        }
        .alert("Delete \(enrollment.displayName)?", isPresented: $isConfirmingDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                model.deleteLauncherBundle(enrollment)
            }
        } message: {
            Text("Its enrollment and Launcher-specific authorization rules will be revoked, then the bundle will be moved to Trash.")
        }
    }
}

private struct ProxySessionDetailView: View {
    let session: ProxySessionSummary
    let history: [AccessRequestRecord]

    private var records: [AccessRequestRecord] {
        let detail = "Proxy Session \(session.id.uuidString.lowercased())"
        return history.filter { $0.detail == detail }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(URL(fileURLWithPath: session.target).lastPathComponent)
                        .font(.system(size: 24, weight: .semibold))
                    Text("Active Proxy Session • pid \(session.pid)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Terminate", role: .destructive) {
                    ProxySessionViewModel.shared.terminate(session.id)
                }
            }
            InfoBlock(
                title: "Authorized Secrets",
                text: session.secretNames.joined(separator: "\n")
            )
            InfoBlock(
                title: "Statistics",
                text: [
                    "Started: \(session.startedAt.formatted(date: .abbreviated, time: .standard))",
                    "Authorized requests: \(session.authorizedRequestCount)",
                    "Origins: \(session.authorizedOrigins.isEmpty ? "(none)" : session.authorizedOrigins.joined(separator: ", "))",
                ].joined(separator: "\n")
            )
            if !records.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Session Requests")
                        .font(.headline)
                    ForEach(records) { record in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(record.displayCommand ?? record.command)
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                            Text("\(record.decision) • \(record.keys.joined(separator: ", "))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
        }
    }
}

private struct AddSecretView: View {
    @ObservedObject var model: DashboardModel
    @State private var account = ""
    @State private var value = ""
    @State private var isAvailableWhileLocked = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add Secret")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(.primary)
            TextField("Name", text: $account)
                .textFieldStyle(.roundedBorder)
            SecureField("Value", text: $value)
                .textFieldStyle(.roundedBorder)
            if let existing = model.storedSecret(
                named: account.trimmingCharacters(in: .whitespacesAndNewlines)
            ), !existing.directAccessLaunchers.isEmpty {
                InfoBlock(
                    title: "Direct Access",
                    text: "Verified Launchers with Direct Access can use this new Value immediately: "
                        + existing.directAccessLaunchers.map(\.bundleIdentifier).joined(separator: ", ")
                )
            }
            if let existing = model.storedSecret(
                named: account.trimmingCharacters(in: .whitespacesAndNewlines)
            ) {
                Text("Availability remains \(existing.accessibility.isAvailableWhileLocked ? "Available While Locked" : "When Unlocked") for all Values.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Toggle("Available While Locked", isOn: $isAvailableWhileLocked)
                    .toggleStyle(.switch)
                Text("Allows an authorized operation to load this Secret while your Mac is locked, after the first unlock following a restart. Authorization is still required.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    if model.addSecret(
                        account: account,
                        value: value,
                        accessibility: isAvailableWhileLocked ? .afterFirstUnlock : .whenUnlocked
                    ) {
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(account.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || value.isEmpty)
            }
        }
        .padding(22)
        .frame(width: 360)
        .background(.ultraThinMaterial)
    }
}

private struct StoredSecretDetailView: View {
    @ObservedObject var model: DashboardModel
    let secret: StoredSecret
    @State private var isAvailableWhileLocked: Bool
    @State private var isConfirmingDelete = false
    @State private var pendingDirectAccessLauncher: DirectAccessLauncherSelection?
    @State private var replacingValue: StoredSecretValue?
    @State private var deletingValue: StoredSecretValue?
    @State private var pendingAccessibility: StoredSecretAccessibility?

    init(model: DashboardModel, secret: StoredSecret) {
        self.model = model
        self.secret = secret
        _isAvailableWhileLocked = State(initialValue: secret.accessibility.isAvailableWhileLocked)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(secret.account)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)
                .lineLimit(3)
            Text(secret.subtitle)
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
            InfoBlock(
                title: "All Secrets",
                text: "Secret Values are hidden.\n\(secret.subtitle)"
            )

            VStack(alignment: .leading, spacing: 10) {
                Text("Values")
                    .font(.headline)
                ForEach(secret.values) { value in
                    HStack(alignment: .center, spacing: 10) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(value.source == .global ? String(localized: "Global Value") : escapedSecurityPath(value.source.displayName))
                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                .textSelection(.enabled)
                            if case .projectDirectory(let path) = value.source,
                               !projectDirectoryExists(path)
                            {
                                Text("Directory Missing")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                        }
                        Spacer()
                        Button("Replace") { replacingValue = value }
                            .accessibilityLabel("Replace \(escapedSecurityPath(value.source.displayName)) for \(secret.account)")
                            .disabled(!storedSecretValueDirectoryExists(value))
                        Button(role: .destructive) { deletingValue = value } label: {
                            Image(systemName: "trash")
                        }
                        .accessibilityLabel("Delete \(escapedSecurityPath(value.source.displayName)) for \(secret.account)")
                    }
                    .padding(10)
                    .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                }
                Text("Create another Project Value with `av save --project-directory=DIR \(secret.account)`." )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            }

            VStack(alignment: .leading, spacing: 8) {
                Toggle("Available While Locked", isOn: availabilityBinding)
                    .toggleStyle(.switch)
                Text("Allows an authorized operation to load this Secret while your Mac is locked, after the first unlock following a restart. Authorization is still required.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            }

            VStack(alignment: .leading, spacing: 10) {
                launcherList(
                    secret.directAccessLaunchers,
                    title: "Direct Secret Access",
                    empty: "No Verified Launchers have Direct Access to this Secret."
                ) {
                    model.removeDirectAccessLauncher($0, from: secret)
                }
                Button {
                    model.chooseDirectAccessLauncher { launcher in
                        guard let launcher else { return }
                        pendingDirectAccessLauncher = launcher
                    }
                } label: {
                    Label("Allow Verified Launcher…", systemImage: "app.badge.checkmark")
                }
                .buttonStyle(.bordered)
                Text("Hardening a Tool or blessing an exact script grants narrower authority.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Link("Read the safer alternatives", destination: directAccessDocumentationURL)
                    .font(.caption)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            }

            HStack {
                Button { model.isRenamingSecret = true } label: {
                    Label("Rename Secret", systemImage: "pencil")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                Button { isConfirmingDelete = true } label: {
                    Label("Delete Secret", systemImage: "trash")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .tint(.red)
            }

            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
        .onChange(of: secret.accessibility) { _, accessibility in
            isAvailableWhileLocked = accessibility.isAvailableWhileLocked
        }
        .alert("Delete \(secret.account)?", isPresented: $isConfirmingDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                model.deleteSecret(account: secret.account)
            }
        } message: {
            Text("This secret will be permanently deleted.")
        }
        .alert("Change availability for all Values?", isPresented: Binding(
            get: { pendingAccessibility != nil },
            set: { if !$0 { pendingAccessibility = nil } }
        )) {
            Button("Cancel", role: .cancel) { pendingAccessibility = nil }
            Button("Change") {
                guard let accessibility = pendingAccessibility else { return }
                pendingAccessibility = nil
                if model.setAccessibility(accessibility, for: secret) {
                    isAvailableWhileLocked = accessibility.isAvailableWhileLocked
                }
            }
        } message: {
            Text("This Secret has \(secret.values.count) Values. The availability setting applies to every Value.")
        }
        .alert("Delete Secret Value?", isPresented: Binding(
            get: { deletingValue != nil },
            set: { if !$0 { deletingValue = nil } }
        )) {
            Button("Cancel", role: .cancel) { deletingValue = nil }
            Button("Delete", role: .destructive) {
                guard let value = deletingValue else { return }
                deletingValue = nil
                model.deleteSecretValue(value, from: secret)
            }
        } message: {
            Text(deletingValue.map(deleteValueMessage) ?? "")
        }
        .sheet(item: $replacingValue) { value in
            ReplaceSecretValueView(model: model, secret: secret, storedValue: value)
        }
        .sheet(item: $pendingDirectAccessLauncher) { selection in
            DirectAccessConfirmationView(
                secretName: secret.account,
                launcherName: selection.launcher.bundleIdentifier,
                runtimeWarning: launcherRuntimeWarning(selection.runtimeRequirement),
                approval: model.authorityApproval, action: "direct-access:\(secret.account)"
            ) {
                model.addDirectAccessLauncher(selection, to: secret) {
                    pendingDirectAccessLauncher = nil
                }
            }
        }
    }

    private var availabilityBinding: Binding<Bool> {
        Binding {
            isAvailableWhileLocked
        } set: { isAvailable in
            let accessibility: StoredSecretAccessibility = isAvailable
                ? .afterFirstUnlock
                : .whenUnlocked
            if secret.values.count > 1 {
                pendingAccessibility = accessibility
                return
            }
            let previous = isAvailableWhileLocked
            isAvailableWhileLocked = isAvailable
            if !model.setAccessibility(accessibility, for: secret) {
                isAvailableWhileLocked = previous
            }
        }
    }

    private func deleteValueMessage(_ value: StoredSecretValue) -> String {
        guard case .projectDirectory(let path) = value.source else {
            return secret.values.count == 1
                ? "This is the last Value. Deleting it also deletes the Secret and revokes its Direct Access Rules."
                : "Project Values remain, but requests outside their directories will have no Global Value."
        }
        let alternatives = secret.values.filter { $0.id != value.id }
        let pathComponents = URL(fileURLWithPath: path).pathComponents
        let inherited = alternatives.compactMap { candidate -> (Int, StoredSecretValue)? in
            guard case .projectDirectory(let candidatePath) = candidate.source else { return nil }
            let candidateComponents = URL(fileURLWithPath: candidatePath).pathComponents
            guard candidateComponents.count < pathComponents.count,
                  pathComponents.starts(with: candidateComponents)
            else { return nil }
            return (candidateComponents.count, candidate)
        }.max { $0.0 < $1.0 }?.1 ?? alternatives.first { $0.source == .global }
        if let inherited {
            return "Requests under \(escapedSecurityPath(path)) will fall back to \(escapedSecurityPath(inherited.source.displayName))."
        }
        return "Requests under \(escapedSecurityPath(path)) will have no Value for this Secret."
    }
}

private func projectDirectoryExists(_ path: String) -> Bool {
    var isDirectory: ObjCBool = false
    return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
        && isDirectory.boolValue
}

private func storedSecretValueDirectoryExists(_ value: StoredSecretValue) -> Bool {
    guard case .projectDirectory(let path) = value.source else { return true }
    return projectDirectoryExists(path)
}

private struct ReplaceSecretValueView: View {
    @ObservedObject var model: DashboardModel
    let secret: StoredSecret
    let storedValue: StoredSecretValue
    @State private var value = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Replace Secret Value")
                .font(.system(size: 18, weight: .semibold))
            Text(escapedSecurityPath(storedValue.source.displayName))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            SecureField("New Value", text: $value)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("New Value for \(secret.account)")
            if !secret.directAccessLaunchers.isEmpty {
                InfoBlock(
                    title: "Direct Access",
                    text: "Verified Launchers with Direct Access can use this replacement immediately: "
                        + secret.directAccessLaunchers.map(\.bundleIdentifier).joined(separator: ", ")
                )
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Replace") {
                    if model.replaceSecretValue(storedValue, in: secret, with: value) {
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(value.isEmpty)
            }
        }
        .padding(22)
        .frame(width: 420)
        .background(.ultraThinMaterial)
    }
}

private struct DirectAccessConfirmationView: View {
    let secretName: String
    let launcherName: String
    let runtimeWarning: String?
    @ObservedObject var approval: AuthorityApprovalState
    let action: String
    let confirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Label("This grants broad authority", systemImage: "exclamationmark.shield.fill")
                    .font(.headline)
                    .foregroundStyle(.orange)
                Text("The Verified Launcher “\(launcherName)” will be able to apply \(secretName) to any Target and arguments it chooses through direct av inject requests.")
                    .fixedSize(horizontal: false, vertical: true)
                if let runtimeWarning {
                    InfoBlock(title: "Warning", text: runtimeWarning)
                }
                Link("Read the safer alternatives", destination: directAccessDocumentationURL)
                    .font(.callout)
                Spacer(minLength: 0)
            }
            .padding(22)
            .frame(width: 470, height: runtimeWarning == nil ? 180 : 260, alignment: .topLeading)
            .navigationTitle("Allow Direct Secret Access?")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { approval.cancel(action); dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    AuthorityApprovalButton(title: "Continue", approval: approval, action: action, perform: confirm)
                }
            }
        }
        .onDisappear { approval.cancel(action) }
    }
}

private struct RenameSecretView: View {
    @ObservedObject var model: DashboardModel
    @State private var account: String
    let valueCount: Int
    @Environment(\.dismiss) private var dismiss

    init(model: DashboardModel, account: String, valueCount: Int) {
        self.model = model
        _account = State(initialValue: account)
        self.valueCount = valueCount
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Rename Secret")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(.primary)
            TextField("Name", text: $account)
                .textFieldStyle(.roundedBorder)
            if valueCount > 1 {
                Text("All \(valueCount) Values will be renamed together.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Rename") {
                    if model.renameSelectedSecret(to: account) {
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(account.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(22)
        .frame(width: 360)
        .background(.ultraThinMaterial)
    }
}

private enum SidebarCountMetrics {
    static let columnWidth: CGFloat = 18
    static let pillHorizontalPadding: CGFloat = 8
}

private struct SidebarCountText: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .regular))
            .foregroundStyle(.secondary)
            .monospacedDigit()
            .lineLimit(1)
    }
}

private struct DetectorCountPill: View {
    let count: Int
    let color: Color

    var body: some View {
        Text(count.formatted())
            .font(.system(size: 11, weight: .bold))
            .monospacedDigit()
            .padding(.horizontal, 8)
            .frame(height: 20)
            .outlinedPill(color)
            .padding(.trailing, -SidebarCountMetrics.pillHorizontalPadding)
    }
}

private struct DetectorKindPill: View {
    let kind: String

    var body: some View {
        Text(kind.uppercased())
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(.primary)
            .tracking(0.4)
            .lineLimit(1)
            .padding(.horizontal, 7)
            .frame(height: 18)
            .background(Color.gray.opacity(0.18), in: Capsule())
    }
}

private struct BlessingStatusPill: View {
    let status: String

    var body: some View {
        Group {
            if status == "Blessed" {
                Image(systemName: "checkmark")
                    .accessibilityLabel("Blessed")
            } else {
                Text(status)
            }
        }
        .font(.system(size: 9, weight: .semibold))
        .lineLimit(1)
        .padding(.horizontal, 7)
        .frame(height: 18)
        .outlinedPill(color)
    }

    private var color: Color {
        switch status {
        case "Blessed": .green
        case "Pending review": .blue
        default: .orange
        }
    }
}

private struct HardenedDetectorPill: View {
    var body: some View {
        Image(systemName: "shield.lefthalf.filled")
            .font(.system(size: 9, weight: .semibold))
            .frame(width: 22, height: 18)
            .outlinedPill(.blue)
            .accessibilityLabel("Hardened")
    }
}

private func detectorSeverityColor(_ severity: String?) -> Color {
    detectorSeverityLevel(severity.map { [$0] } ?? []).color
}

private func detectorSummary(for item: DashboardItem) -> String {
    switch item.kind?.lowercased() {
    case "auth token", "hosts token":
        String(localized: "Auth tokens grant API access without a password. If they leak, another process can act as you until the token is revoked.")
    case "credential fill", "credential oauth", "credential helpers":
        String(localized: "Credential helpers can expose reusable Git credentials. A compromised helper or config can capture tokens and push or pull as you.")
    case "credentials file":
        String(localized: "Credentials files keep reusable keys on disk. Any process that can read them can authenticate to the linked service.")
    case "legacy plugins":
        String(localized: "Legacy plugins run code inside the tool. Old or writable plugins widen the path for unreviewed code execution.")
    case "login cache":
        String(localized: "Login caches store session material after sign-in. A readable cache can let another process reuse your cloud session.")
    case "minimum release age":
        String(localized: "Missing release-age protection allows brand-new packages immediately. That raises exposure to dependency hijacks and rushed malicious releases.")
    case "mutable":
        String(localized: "Mutable installs can be changed after installation. If an attacker edits them, future commands may run code you did not approve.")
    case "persisted output", "persisted report":
        String(localized: "Persisted output can leave discovered secrets in report files. Anyone with file access can recover those secrets later.")
    case "plaintext secret":
        String(localized: "Plaintext secrets are stored without OS-backed protection. Any local process with file access can copy and reuse them.")
    case "registry credentials":
        String(localized: "Registry credentials allow image pulls, pushes, or private registry access. If exposed, they can leak images or poison deployments.")
    case "root access":
        String(localized: "Root-equivalent access can modify system files and privileged workloads. Misuse can turn a local compromise into full host control.")
    case "shell history":
        String(localized: "Shell history can preserve secrets typed into commands. Those values remain readable long after the command finishes.")
    case "system integrity":
        String(localized: "System integrity controls protect privileged operations and trusted macOS components. Strong authentication and built-in macOS protections reduce opportunities for compromised code to gain root access or tamper with the system.")
    default:
        String(localized: "Sensitive local files can expose credentials or weaken a trust boundary. If another process can read or change them, it may impersonate you or run untrusted code.")
    }
}

private enum DetectorSeverityLevel {
    case medium
    case high

    var title: String {
        switch self {
        case .medium: "MEDIUM"
        case .high: "HIGH"
        }
    }

    var color: Color {
        switch self {
        case .medium: .orange
        case .high: .red
        }
    }
}

private func detectorSeverityLevel(_ severities: [String]) -> DetectorSeverityLevel {
    !severities.isEmpty && severities.allSatisfy(isMediumDetectorSeverity) ? .medium : .high
}

private func isMediumDetectorSeverity(_ severity: String) -> Bool {
    switch severity.lowercased() {
    case "medium", "mid":
        true
    default:
        false
    }
}

private struct InfoBlock: View {
    let title: String
    let text: String
    var rendersMarkdown = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(localizedUIString(title).uppercased())
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
                .tracking(0.7)
            Group {
                if rendersMarkdown {
                    RenderedMarkdown(markdown: text)
                        .markdownSoftBreakMode(.lineBreak)
                } else {
                    Text(text)
                }
            }
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }
}

private struct ReferenceBadge {
    let title: String
    let color: Color
}

private struct ReferenceDetailView: View {
    let item: DashboardItem
    let summary: String
    let referenceTitle: String
    let fallbackDocumentation: String
    let badge: ReferenceBadge

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(item.title)
                        .font(.system(size: 26, weight: .semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    referenceBadge
                    if item.id == "homebrew" {
                        Label("Experimental", systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 11, weight: .semibold))
                            .padding(.horizontal, 8)
                            .frame(height: 20)
                            .outlinedPill(.orange)
                    }
                }
                Text(summary)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            if !item.detail.isEmpty {
                InfoBlock(title: "Current Result", text: item.detail)
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Color(nsColor: .controlBackgroundColor))
                    }
            }

            VStack(alignment: .leading, spacing: 14) {
                Text(localizedUIString(referenceTitle))
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(.secondary)
                    .tracking(0.7)
                RenderedMarkdown(markdown: item.documentation.isEmpty ? fallbackDocumentation : item.documentation)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            }
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(Color(nsColor: .separatorColor))
            }

            if let hardenerDocumentation = item.hardenerDocumentation, !hardenerDocumentation.isEmpty {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Hardener Reference")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(.secondary)
                        .tracking(0.7)
                    RenderedMarkdown(markdown: hardenerDocumentation)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor))
                }
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(Color(nsColor: .separatorColor))
                }
            }
        }
    }

    private var referenceBadge: some View {
        Text(localizedUIString(badge.title))
            .font(.system(size: 11, weight: .semibold))
            .padding(.horizontal, 8)
            .frame(height: 20)
            .outlinedPill(badge.color)
    }
}

private struct HardenedToolDetailView: View {
    let item: DashboardItem
    let records: [AccessRequestRecord]

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ReferenceDetailView(
                item: item,
                summary: "Installed hardening behavior and caveats for this tool.",
                referenceTitle: "Hardener Reference",
                fallbackDocumentation: "No hardener documentation is bundled for this item.",
                badge: ReferenceBadge(title: "Hardened", color: .blue)
            )
            AccessHistoryView(records: records)
        }
    }
}

private struct AccessHistoryView: View {
    let records: [AccessRequestRecord]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "clock.arrow.circlepath")
                    .foregroundStyle(.blue)
                Text("Access Requests")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(.secondary)
                    .tracking(0.7)
                Spacer()
                Text("LAST \(records.count)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }

            if records.isEmpty {
                Text("No authorization requests recorded for this tool.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(records) { record in
                        AccessRequestRow(record: record)
                        if record.id != records.last?.id {
                            hairline
                        }
                    }
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        }
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(Color(nsColor: .separatorColor))
        }
    }
}

private struct AuthorizationHistoryDetailView: View {
    let record: AccessRequestRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Authorization History")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)
            AccessRequestRow(record: record)
                .padding(.horizontal, 16)
                .background {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor))
                }
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(Color(nsColor: .separatorColor))
                }
        }
    }
}

private struct AccessRequestRow: View {
    let record: AccessRequestRecord

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 22, height: 22)
                .background(color.opacity(0.12), in: Circle())
            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(record.decision.uppercased())
                        .font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 7)
                        .frame(height: 18)
                        .outlinedPill(color)
                    Text(record.approvalSourceLabel.uppercased())
                        .font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 7)
                        .frame(height: 18)
                        .outlinedPill(sourceColor)
                    Text(Self.formatter.string(from: record.date))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                Text(record.commandForDisplay)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                Text(record.reason)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 3) {
                    AccessMetaLine("Launcher", record.launcher ?? "unknown")
                    AccessMetaLine("Decision source", record.approvalSourceLabel)
                    AccessMetaLine("Secret names", record.keys.isEmpty ? "(none)" : record.keys.joined(separator: ", "))
                    if let sources = record.secretValueSources, !sources.isEmpty {
                        AccessMetaLine(
                            "Secret values",
                            sources.sorted { $0.key < $1.key }.map {
                                "\($0.key): \(escapedSecurityPath($0.value))"
                            }.joined(separator: "\n")
                        )
                    }
                    AccessMetaLine("Gate client", record.callerPath)
                    AccessMetaLine("Target", record.target)
                    if let runtime = record.targetRuntimeProtection {
                        AccessMetaLine("Target runtime", runtime)
                    }
                    AccessMetaLine("Working directory", escapedSecurityPath(record.cwd))
                    if let detail = record.detail, !detail.isEmpty {
                        AccessMetaLine("Detail", detail)
                    }
                }
            }
        }
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var color: Color {
        switch record.decision {
        case "Approved": .green
        case "Always Allowed": .blue
        case "Denied": .red
        default: .orange
        }
    }

    private var icon: String {
        switch record.decision {
        case "Approved", "Always Allowed": "checkmark"
        case "Denied": "xmark"
        default: "exclamationmark"
        }
    }

    private var sourceColor: Color {
        switch record.approvalSourceLabel {
        case "Human": .purple
        case "Policy": .cyan
        default: .gray
        }
    }
}

private struct AccessMetaLine: View {
    let label: String
    let value: String

    init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }

    var body: some View {
        Text("\(label): \(value)")
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
    }
}

private struct BlessedScriptReviewView: View {
    @ObservedObject var model: DashboardModel
    let request: BlessedScriptReviewRequest
    @ObservedObject private var approval: AuthorityApprovalState

    init(model: DashboardModel, request: BlessedScriptReviewRequest) {
        self.model = model
        self.request = request
        approval = model.authorityApproval
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(URL(fileURLWithPath: request.path).lastPathComponent)
                            .font(.system(size: 24, weight: .semibold))
                        Text(request.previousContents == nil
                            ? "Review before granting durable script authority."
                            : "Review every change before replacing the invalidated Blessing.")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                    if let previous = request.previousContents,
                       let rows = blessedScriptDiff(previous: previous, current: request.scriptData) {
                        BlessedScriptDiffView(rows: rows)
                    }
                    BlessedScriptFields(
                        path: request.path,
                        checksum: request.declaration.checksum,
                        keys: request.declaration.keys,
                        inheritsCapabilities: request.declaration.manifest.inheritsCapabilities,
                        capabilities: request.declaration.manifest.capabilities
                    )
                    launcherList(model.pendingBlessingLaunchers) {
                        model.removePendingBlessingLauncher($0)
                    }
                    Button {
                        model.addAppToPendingBlessing()
                    } label: {
                        Label("Add Verified Launcher…", systemImage: "plus")
                    }
                    .buttonStyle(.bordered)
                    if request.declaration.manifest.capabilities.values.contains(.fullIncludingSecretDumps) {
                        InfoBlock(
                            title: "Full Access",
                            text: String(localized: "This script requests access to operations that may reveal protected secret values.")
                        )
                    }
                    if let interpreter = request.declaration.snapshotIncompatibleInterpreter {
                        InfoBlock(
                            title: "Verified Snapshot Unavailable",
                            text: "\(interpreter) cannot execute Automic Vault’s verified script snapshot. If you continue, Automic Vault will verify the script, then run its canonical path. Another process can change the file before \(interpreter) opens it. Automic Vault will warn on every run."
                        )
                    }
                    if let error = model.errorMessage {
                        InfoBlock(title: "Error", text: error)
                    }
                }
                .padding(22)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .disabled(approval.isPending("blessing"))
            Divider()
            HStack {
                Button("Cancel", role: .cancel) { model.cancelPendingBlessing() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                AuthorityApprovalButton(
                    title: request.declaration.snapshotIncompatibleInterpreter == nil ? "Bless Script" : "Bless Anyway",
                    approval: model.authorityApproval, action: "blessing"
                ) {
                    model.approvePendingBlessing()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 720, height: request.previousContents == nil ? 520 : 680)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

private struct LauncherHelperReviewView: View {
    @ObservedObject var model: DashboardModel
    let review: LauncherHelperReview
    @ObservedObject private var approval: AuthorityApprovalState

    init(model: DashboardModel, review: LauncherHelperReview) {
        self.model = model
        self.review = review
        approval = model.authorityApproval
    }
    @State private var selectedHelperIDs: Set<String> = []

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        Text("Automic Vault found signed helpers sealed inside \(appName). "
                            + "Select only helpers that should share the app’s Launcher Identity.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        VStack(spacing: 0) {
                            ForEach(review.helpers) { helper in
                                helperRow(helper)
                                if helper.id != review.helpers.last?.id { hairline }
                            }
                        }
                        .padding(.horizontal, 12)
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(nsColor: .separatorColor))
                        }
                        VStack(alignment: .leading, spacing: 8) {
                            Label("This may widen Secret access", systemImage: "exclamationmark.triangle.fill")
                                .font(.headline)
                                .foregroundStyle(.orange)
                            Text("Each selected helper will represent \(appName) at every Authorization Gate "
                                + "where that app has a current or future Launcher-specific rule. It may apply "
                                + "protected Secrets or perform controlled operations up to that rule’s Access "
                                + "Level. Select it only if you trust the helper to act as the app.")
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(14)
                        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    }
                    .padding(22)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .disabled(approval.isPending("gate-launcher:\(review.gate.id)"))
            }
            .navigationTitle("Include App Helpers?")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { model.cancelLauncherHelperReview() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    AuthorityApprovalButton(
                        title: selectedHelperIDs.isEmpty ? "Add Verified Launcher" : "Add Verified Launcher with Helpers",
                        approval: model.authorityApproval, action: "gate-launcher:\(review.gate.id)"
                    ) {
                        model.confirmLauncherHelperReview(selectedHelperIDs: selectedHelperIDs)
                    }
                }
            }
        }
        .frame(width: 680, height: 520)
    }

    private var appName: String {
        review.helpers.first?.appName ?? review.signing.identifier
    }

    private func helperRow(_ helper: VerifiedLauncherHelper) -> some View {
        Toggle(isOn: Binding(
            get: { selectedHelperIDs.contains(helper.id) },
            set: { selected in
                if selected {
                    selectedHelperIDs.insert(helper.id)
                } else {
                    selectedHelperIDs.remove(helper.id)
                }
            }
        )) {
            VStack(alignment: .leading, spacing: 4) {
                Text(helper.name)
                    .font(.system(size: 13, weight: .medium))
                Text("\(helper.helperSigningIdentifier) · Team \(helper.helperTeamIdentifier)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                if let relativePath = helper.relativePath {
                    Text(relativePath)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
            .padding(.vertical, 10)
        }
        .toggleStyle(.checkbox)
    }
}

private struct BlessedScriptDiffView: View {
    let rows: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Changes since this script was blessed", systemImage: "plusminus")
                .font(.headline)
            ScrollView([.horizontal, .vertical]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                        Text(row.isEmpty ? " " : row)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(diffColor(row))
                            .textSelection(.enabled)
                            .fixedSize()
                    }
                }
                .padding(12)
            }
            .defaultScrollAnchor(.topLeading)
            .frame(height: 280)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Changes from the previously blessed script to the current file")
    }

    private func diffColor(_ row: String) -> Color {
        if row.hasPrefix("+ ") { return .green }
        if row.hasPrefix("- ") { return .red }
        return .primary
    }
}

private struct BlessedScriptDetailView: View {
    @ObservedObject var model: DashboardModel
    let script: BlessedScript

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(URL(fileURLWithPath: script.path).lastPathComponent)
                    .font(.system(size: 24, weight: .semibold))
                Text(status)
                    .font(.system(size: 13))
                    .foregroundStyle(status == "Blessed" ? .green : .orange)
            }
            BlessedScriptFields(
                path: script.path,
                checksum: script.checksum,
                keys: script.keys,
                inheritsCapabilities: script.usesCapabilityInheritance,
                capabilities: script.capabilities
            )
            launcherList(script.launchers) {
                model.removeLauncher($0, from: script)
            }
            HStack {
                if status == "Changed" {
                    Button("Review Changes…") { model.reviewChanges(to: script) }
                        .buttonStyle(.borderedProminent)
                        .disabled(script.verifiedReviewedContents == nil)
                        .help(script.verifiedReviewedContents == nil
                            ? "The original reviewed contents are unavailable for this legacy Blessing."
                            : "Show the diff and review a replacement Blessing.")
                }
                Spacer()
                Button("Revoke Blessing", role: .destructive) { model.revoke(script) }
            }
            if status == "Changed", script.verifiedReviewedContents == nil {
                Text("The original reviewed contents are unavailable for this legacy Blessing. Run `av bless` once to establish a diff baseline.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }

    private var status: String {
        blessedScriptStatus(script)
    }
}

private struct BlessedScriptFields: View {
    let path: String
    let checksum: String
    let keys: [String]
    let inheritsCapabilities: Bool
    let capabilities: [String: SecretGateProtection]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SecretGateField("Path", path)
            SecretGateField("SHA-256", checksum, monospaced: true)
            SecretGateField("Secrets", keys.joined(separator: ", "))
            SecretGateField(
                "Capabilities",
                blessedScriptAccessSummary(
                    capabilities: capabilities,
                    inheritsCapabilities: inheritsCapabilities
                )
            )
        }
    }
}

@MainActor
private func launcherList(
    _ launchers: [BlessedScriptLauncher],
    title: String = "Launcher Endorsements",
    empty: String = "No Verified Launchers endorsed.",
    approval: AuthorityApprovalState? = nil,
    remove: @escaping (BlessedScriptLauncher) -> Void
) -> some View {
    VStack(alignment: .leading, spacing: 10) {
        Text(localizedUIString(title))
            .font(.system(size: 13, weight: .semibold))
        if launchers.isEmpty {
            Text(localizedUIString(empty))
                .foregroundStyle(.secondary)
        }
        ForEach(launchers, id: \.requirement) { launcher in
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(launcher.bundleIdentifier)
                        .textSelection(.enabled)
                    Text(codeSigningTeamIdentifier(from: launcher.requirement).map { "Team \($0)" }
                        ?? "Verified designated requirement")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
                if let approval {
                    AuthorityApprovalButton(title: "Remove", approval: approval, action: "launchers") {
                        remove(launcher)
                    }
                } else {
                    Button {
                        remove(launcher)
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.plain)
                    .help("Remove Verified Launcher")
                }
            }
            .padding(10)
            .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
        }
    }
}

private struct SecretNameAccessSettingsView: View {
    @ObservedObject var model: DashboardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Secret Name Access")
                    .font(.system(size: 24, weight: .semibold))
                Text("These Verified Launchers may run av list without Approval.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            launcherList(
                model.snapshot.secretNameAccessApps,
                title: "Verified Launchers",
                empty: "No Verified Launchers have Secret Name Access."
            ) {
                model.removeSecretNameAccessApp($0)
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }
}

private struct AuthorizationHistoryAccessSettingsView: View {
    @ObservedObject var model: DashboardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Authorization History Access")
                    .font(.system(size: 24, weight: .semibold))
                Text("These Verified Launchers may run av history without Approval.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            launcherList(
                model.snapshot.authorizationHistoryAccessApps,
                title: "Verified Launchers",
                empty: "No Verified Launchers may read Authorization History without Approval."
            ) {
                model.removeAuthorizationHistoryAccessApp($0)
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }
}

private struct IPhoneApprovalSettingsView: View {
    @StateObject private var approval = AuthorityApprovalState()
    @AppStorage(phoneApprovalEnabledDefaultsKey) private var enabled = false
    @State private var status = "Checking for iPhones…"
    @State private var isWorking = false
    @State private var showsRecoveryWarning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("iPhone Approval")
                    .font(.system(size: 24, weight: .semibold))
                Text(enabled
                    ? (TouchIDApproval.isEnabled
                        ? String(localized: "Human Approval may come from an eligible iPhone or Touch ID on this Mac.")
                        : String(localized: "Every human Approval for this Mac must come from an eligible iPhone."))
                    : String(localized: "Keep agents with computer-use access away from their own Approval controls."))
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            Label(enabled ? String(localized: "Enabled") : String(localized: "Disabled"), systemImage: enabled ? "iphone.and.arrow.forward" : "iphone.slash")
                .foregroundStyle(enabled ? .green : .secondary)
            Text(status).font(.caption).foregroundStyle(.secondary)

            InfoBlock(
                title: "Physical separation",
                text: String(localized: "iPhone Mirroring and Show on Mac can expose phone controls to an agent. Disable them, or require Face ID or Touch ID in the iPhone app.")
            )

            if enabled {
                AuthorityApprovalButton(title: "Disable iPhone Approval", approval: approval, action: "disable") {
                    isWorking = true
                    approval.request(
                        "disable", title: "Disable iPhone Approval",
                        detail: "Future human Approvals will return to this Mac. Existing requests will be canceled."
                    ) { approved in
                        if approved { PhoneApprovalCoordinator.shared.disableAfterPhoneApproval() }
                        isWorking = false
                        status = approved ? "iPhone Approval disabled." : "Disable was denied or canceled."
                    }
                }
                .disabled(isWorking)

                Button("Recover Without iPhone…", role: .destructive) {
                    showsRecoveryWarning = true
                }
                .disabled(isWorking)
            } else {
                Button("Enable iPhone Approval") {
                    isWorking = true
                    Task {
                        do {
                            try await PhoneApprovalCoordinator.shared.enable()
                            status = TouchIDApproval.isEnabled
                                ? "Enabled. Approve on iPhone or with Touch ID on this Mac."
                                : "Enabled. This Mac no longer exposes an allow action."
                        } catch {
                            status = error.localizedDescription
                        }
                        isWorking = false
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isWorking)
            }
        }
        .task { await refreshStatus() }
        .alert("Invalidate every enrolled device?", isPresented: $showsRecoveryWarning) {
            Button("Cancel", role: .cancel) {}
            Button("Recover and Rotate Key", role: .destructive) {
                isWorking = true
                Task {
                    do {
                        try await PhoneApprovalCoordinator.shared.recoverWithoutIPhone()
                        status = "Recovered. Every iPhone and Mac must enroll again."
                    } catch {
                        status = "Recovery failed: \(error.localizedDescription)"
                    }
                    isWorking = false
                }
            }
        } message: {
            Text("macOS will authenticate you. Recovery disables iPhone Approval, cancels pending requests, rotates the iCloud key, and invalidates every iPhone and other Mac on this account.")
        }
        .onDisappear { approval.cancelAll(); isWorking = false }
    }

    private func refreshStatus() async {
        do {
            let registration = try await PhoneApprovalCoordinator.shared.registrationStatus()
            status = registration.count == 0
                ? "No iPhone has registered recently. Open the iPhone app and allow notifications."
                : "\(registration.count) iPhone registration\(registration.count == 1 ? "" : "s") available."
        } catch {
            status = error.localizedDescription
        }
    }
}

private struct TouchIDApprovalSettingsView: View {
    @StateObject private var approval = AuthorityApprovalState()
    @State private var enabled = TouchIDApproval.isEnabled
    @State private var status = TouchIDApproval.isAvailable
        ? "Touch ID is available on this Mac."
        : "Touch ID is unavailable or not enrolled on this Mac."
    @State private var isWorking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Touch ID Approval")
                    .font(.system(size: 24, weight: .semibold))
                Text("Approve an exact request on this Mac without exposing an agent-drivable allow button.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            Label(enabled ? String(localized: "Enabled") : String(localized: "Disabled"), systemImage: "touchid")
                .foregroundStyle(enabled ? .green : .secondary)
            Text(status).font(.caption).foregroundStyle(.secondary)

            InfoBlock(
                title: "Explicit local authority",
                text: String(localized: "Touch ID Approval works independently of relay availability and may coexist with iPhone Approval. It never accepts a password, Apple Watch, pointer, or keyboard action.")
            )

            if enabled {
                Button("Disable Touch ID Approval") {
                    do {
                        try TouchIDApproval.disable()
                        enabled = false
                        status = "Disabled. This Mac no longer accepts Touch ID Approval."
                    } catch {
                        status = error.localizedDescription
                    }
                }
                .disabled(isWorking)
            } else {
                AuthorityApprovalButton(title: "Enable Touch ID Approval", approval: approval, action: "enable") {
                    isWorking = true
                    status = PhoneApprovalCoordinator.shared.isEnabled
                        ? "Waiting for Approval on iPhone…"
                        : "Waiting for Touch ID…"
                    approval.request(
                        "enable", title: "Enable Touch ID Approval",
                        detail: "Add biometric-only Approval as a human-presence surface on this Mac."
                    ) { approved in
                        guard approved else {
                            status = "Enable was denied or canceled."
                            isWorking = false
                            return
                        }
                        Task {
                            do {
                                status = "Waiting for Touch ID…"
                                try await TouchIDApproval.enable()
                                enabled = true
                                status = "Enabled. Each Mac Approval now requires fresh Touch ID."
                            } catch {
                                status = error.localizedDescription
                            }
                            isWorking = false
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isWorking || !TouchIDApproval.isAvailable)
            }
        }
        .onDisappear { approval.cancelAll(); isWorking = false }
    }
}

private struct AutomaticApprovalFeedbackSettingsView: View {
    @AppStorage(automaticApprovalFeedbackDefaultsKey)
    private var feedback = AutomaticApprovalFeedback.notification
    @AppStorage(compactAutomaticApprovalNotificationsDefaultsKey)
    private var compactNotifications = true
    @AppStorage(autoCollapseTemporaryAccessGrantStripDefaultsKey)
    private var autoCollapseTemporaryAccessGrantStrip = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Automic Authorization")
                    .font(.system(size: 24, weight: .semibold))
                Text("Choose what appears when policy authorizes an operation.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            Picker("Feedback", selection: $feedback) {
                ForEach(AutomaticApprovalFeedback.allCases) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.radioGroup)
            Toggle("Compact Notifications", isOn: $compactNotifications)
                .disabled(feedback != .notification)
            Text("Shows each command without continuation formatting, wrapped to at most five lines. Authorization History keeps the full formatted command.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Automic authorizations are recorded in Authorization History. Approval prompts and policy-denial notifications are unaffected.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Divider()
            VStack(alignment: .leading, spacing: 6) {
                Text("Temporary Write Access")
                    .font(.headline)
                Toggle(
                    "Auto-collapse Temporary Access Grant Strip",
                    isOn: $autoCollapseTemporaryAccessGrantStrip
                )
                Text("After five seconds, the strip becomes a warning tab at the nearest screen edge. Select the tab or use the menu bar to restore it. New grants always show the complete strip.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .onChange(of: autoCollapseTemporaryAccessGrantStrip) {
            NotificationCenter.default.post(
                name: temporaryAccessGrantStripPresentationDidChange,
                object: nil
            )
        }
    }
}

private struct DetachedProcessAccessSettingsView: View {
    @StateObject private var approval = AuthorityApprovalState()
    @AppStorage(keepLauncherAccessForDetachedProcessesDefaultsKey)
    private var keepsLauncherAccess = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Detached Processes")
                    .font(.system(size: 24, weight: .semibold))
                Text("Control whether a live process keeps its verified Launcher attribution after its parent chain exits.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            Toggle(
                isOn: Binding(
                    get: { keepsLauncherAccess },
                    set: { enabled in
                        guard enabled else {
                            keepsLauncherAccess = false
                            return
                        }
                        approval.request(
                            "detached", title: "Keep Launcher Access for Detached Processes",
                            detail: "A live process may retain Launcher authority after its verified parent chain exits."
                        ) { approved in
                            if approved { keepsLauncherAccess = true }
                        }
                    }
                )
            ) {
                AuthorityApprovalLabel(
                    title: "Keep Launcher Access for Detached Processes", approval: approval,
                    action: "detached", requiresApproval: !keepsLauncherAccess
                )
            }
            .disabled(approval.isPending("detached"))
            Text("Off by default. When enabled, an exact signed process execution that participates in an automically authorized operation may continue using that Launcher’s current policy at the same Authorization Gate until the process or Automic Vault exits. New processes and other gates are not included.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            InfoBlock(
                title: "Security tradeoff",
                text: String(localized: "This extends authority after the verified parent chain disappears. Intermediary processes that permit same-user code injection can pass that authority to injected code. An enrolled Launcher Bundle payload represents its own bundle without this setting.")
            )
            Link("Learn about Launcher Bundles", destination: launcherBundleDocumentationURL)
                .font(.caption)
        }
        .onDisappear { approval.cancelAll() }
    }
}

private struct VerifiedLauncherHelpersSettingsView: View {
    @StateObject private var approval = AuthorityApprovalState()
    @State private var configuration = loadVerifiedLauncherHelperConfiguration()
    @State private var status = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Verified Launcher Helpers")
                    .font(.system(size: 24, weight: .semibold))
                Text("Allow exact vendor-signed helpers sealed inside their vendor's app to represent that app as the Verified Launcher.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            ForEach(configuration.helpers) { helper in
                helperRow(helper)
                if helper.id != configuration.helpers.last?.id { Divider() }
            }
            InfoBlock(
                title: "Exact identities only",
                text: String(localized: "Each association verifies both signing identities, binds the live helper to its on-disk executable, and confirms that exact executable is unmodified in the app's resource seal. Other bundled executables do not inherit the app's authority.")
            )
            if !status.isEmpty {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .onDisappear { approval.cancelAll() }
    }

    private func helperRow(_ helper: VerifiedLauncherHelper) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle(
                isOn: Binding(
                    get: { configuration.isEnabled(helper) },
                    set: { next in
                        guard next else {
                            persist(helper, enabled: false)
                            return
                        }
                        approval.request(
                            helper.id, title: "Enable \(helper.name) Launcher Helper",
                            detail: "Allow the exact signed \(helper.name) helper sealed inside \(helper.appName) to represent \(helper.appName) at every Authorization Gate where that app has a current or future Launcher-specific rule. This may widen Secret access and controlled operations up to each rule’s Access Level."
                        ) { approved in
                            if approved { persist(helper, enabled: true) }
                        }
                    }
                )
            ) {
                AuthorityApprovalLabel(
                    title: "\(helper.name) in \(helper.appName)", approval: approval,
                    action: helper.id, requiresApproval: !configuration.isEnabled(helper)
                )
            }
            .disabled(approval.isPending(helper.id))
            Text("\(helper.helperSigningIdentifier) → \(helper.appBundleIdentifier)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            if let relativePath = helper.relativePath {
                Text(relativePath)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
    }

    private func persist(_ helper: VerifiedLauncherHelper, enabled: Bool) {
        var next = configuration
        if enabled {
            next.disabledHelperIDs.remove(helper.id)
        } else {
            next.disabledHelperIDs.insert(helper.id)
        }
        let result = saveVerifiedLauncherHelperConfiguration(next)
        guard result == errSecSuccess else {
            status = "Could not save Verified Launcher Helpers: \(result)"
            return
        }
        configuration = next
        status = ""
    }
}

private struct SSHAgentSettingsView: View {
    let onCredentialSaved: () -> Void
    let onOpenGate: () -> Void
    @StateObject private var approval = AuthorityApprovalState()
    @ObservedObject private var runtime = SSHAgentRuntime.shared
    @State private var config = loadSSHAgentConfiguration()
    @State private var importing = false
    @State private var status = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("SSH Agent").font(.system(size: 24, weight: .semibold))
            Text("Authorize SSH authentication with one credential shared across Verified Launchers.")
                .foregroundStyle(.secondary)
            Toggle("Enable SSH Agent", isOn: Binding(get: { config.enabled }, set: { setEnabled($0) }))
                .disabled(config.publicKey.isEmpty || approval.isPending("enable") || (!SSHAgentRuntime.isSupported && !config.enabled))
            if !SSHAgentRuntime.isSupported {
                Text("This macOS version cannot provide the original process ancestry required by SSH Agent.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Every signature requires Approval until you change the SSH Agent Authorization Gate’s Access Level. Allow Authentication can grant remote access, including writes.")
                .font(.caption).foregroundStyle(.secondary)
            Button(config.publicKey.isEmpty ? "Import SSH Credential…" : "Replace SSH Credential…") {
                importing = true
            }
            if !config.publicKey.isEmpty {
                Text("Public key").font(.headline)
                Text(config.publicKey).font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Button("Copy Public Key") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(config.publicKey, forType: .string)
                }
                Button("Open Authorization Gate") { onOpenGate() }
            }
            Divider()
            Button("Configure OpenSSH") {
                do {
                    try configureOpenSSHAgent(enabled: true)
                    status = "Configured ~/.ssh/config to use the Automic Vault SSH agent."
                } catch { status = error.localizedDescription }
            }.disabled(!config.enabled)
            Button("Remove OpenSSH Configuration") {
                do {
                    try configureOpenSSHAgent(enabled: false)
                    status = "Removed Automic Vault’s SSH configuration block."
                } catch { status = error.localizedDescription }
            }
            Text("Other agent clients can use SSH_AUTH_SOCK=\(sshAgentSocketURL().path). Disabling the agent leaves OpenSSH configured to fail closed until you remove its configuration.")
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            InfoBlock(title: "Existing access paths", text: String(localized: "Importing does not delete your original private key, its Keychain passphrase, or keys loaded in another agent. These remain independent access paths. After verifying the new setup, remove the old copies and agent entries yourself. Explicit IdentityFile settings may still select other keys."))
            InfoBlock(title: "Local Launcher boundary", text: String(localized: "Destination-specific restrictions are not provided. Clients need a live Verified Launcher ancestor; a client cannot act as its own Launcher. Shared or forwarded connections carry requests under that ancestor’s attribution. OpenSSH configuration disables forwarding by default."))
            if !runtime.status.isEmpty { InfoBlock(title: "SSH Agent", text: runtime.status) }
            if !status.isEmpty { InfoBlock(title: "Status", text: status) }
        }
        .sheet(isPresented: $importing) {
            SSHCredentialSheetView { publicKey in
                config = loadSSHAgentConfiguration()
                status = "Saved SSH credential in the Data Protection Keychain."
                onCredentialSaved()
            }
        }
        .onDisappear { approval.cancelAll() }
    }

    private func setEnabled(_ enabled: Bool) {
        if !enabled { persistEnabled(false); return }
        let reviewed = loadSSHAgentConfiguration()
        approval.request("enable", title: "Enable SSH Agent?",
                         detail: "Make this SSH credential available through its Authorization Gate: \(reviewed.publicKey). Every Verified Launcher uses the same credential. Existing gate policy applies.") { allowed in
            guard allowed else { return }
            guard loadSSHAgentConfiguration() == reviewed else {
                status = "The SSH credential changed while awaiting Approval. Review it and try again."
                return
            }
            persistEnabled(true)
        }
    }

    private func persistEnabled(_ enabled: Bool) {
        var next = loadSSHAgentConfiguration()
        next.enabled = enabled
        next.generation = UUID()
        let result = saveSSHAgentConfiguration(next)
        guard result == errSecSuccess else { status = "Could not save SSH Agent setting: \(result)"; return }
        config = next
        NotificationCenter.default.post(name: .sshAgentConfigurationChanged, object: nil)
    }
}

private struct SSHCredentialSheetView: View {
    let onSaved: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @StateObject private var approval = AuthorityApprovalState()
    @State private var privateKey = ""
    @State private var passphrase = ""
    @State private var busy = false
    @State private var error = ""

    var body: some View {
        NavigationStack {
            Form {
                Text("OpenSSH private key").font(.caption)
                TextEditor(text: $privateKey)
                    .font(.system(.caption, design: .monospaced)).frame(minHeight: 130)
                    .accessibilityLabel("SSH private key")
                SecureField("Passphrase (leave empty if none)", text: $passphrase)
                Text("Paste a complete OPENSSH PRIVATE KEY block. Ed25519 and ECDSA authentication are supported. Stored private keys are never displayed. Replacing the credential cannot recover the previous private key.")
                    .font(.caption).foregroundStyle(.secondary)
                if !error.isEmpty { Text(error).foregroundStyle(.red) }
            }.formStyle(.grouped).disabled(busy)
                .navigationTitle("Import SSH Credential")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }.disabled(busy)
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button(busy ? "Saving…" : "Save") { submit() }
                            .disabled(privateKey.isEmpty || busy)
                    }
                }
        }.frame(width: 560, height: 420)
            .interactiveDismissDisabled(busy)
            .onDisappear { privateKey = ""; passphrase = ""; approval.cancelAll() }
    }

    private func submit() {
        busy = true
        let credential = ["private_key": privateKey, "passphrase": passphrase]
        let executable = Bundle.main.executableURL
        Task {
            do {
                let publicKey = try await validateSSHCredential(credential, executable: executable)
                approval.request("save", title: "Store this SSH credential?",
                                 detail: "Replace the shared SSH credential for every Verified Launcher. Public key: \(publicKey)") { allowed in
                    guard allowed else { busy = false; return }
                    do {
                        let data = try JSONEncoder().encode(credential)
                        // Disable first: a partial write cannot combine an old public key with new private material.
                        var config = loadSSHAgentConfiguration()
                        let enabled = config.enabled
                        config.enabled = false
                        config.generation = UUID()
                        var result = saveSSHAgentConfiguration(config)
                        guard result == errSecSuccess else { throw SSHAgentError.failed("Keychain error \(result)") }
                        result = saveStoredSecret(account: sshCredentialSecretName,
                                                  value: String(decoding: data, as: UTF8.self))
                        guard result == errSecSuccess else { throw SSHAgentError.failed("Keychain error \(result)") }
                        config.publicKey = publicKey
                        config.enabled = enabled
                        result = saveSSHAgentConfiguration(config)
                        guard result == errSecSuccess else { throw SSHAgentError.failed("Keychain error \(result)") }
                        privateKey = ""; passphrase = ""
                        NotificationCenter.default.post(name: .sshAgentConfigurationChanged, object: nil)
                        onSaved(publicKey)
                        dismiss()
                    } catch {
                        self.error = error.localizedDescription; busy = false
                        NotificationCenter.default.post(name: .sshAgentConfigurationChanged, object: nil)
                    }
                }
            } catch { self.error = error.localizedDescription; busy = false }
        }
    }
}

@concurrent
private func validateSSHCredential(_ credential: [String: String], executable: URL?) async throws -> String {
    let input = try JSONEncoder().encode(credential)
    guard input.count <= 1024 * 1024 else { throw SSHAgentError.failed("SSH credential exceeds 1 MiB") }
    let output = try runBundledCredentialCommand(arguments: ["__ssh-public-key"],
        input: input, mainExecutableURL: executable)
    guard let publicKey = String(data: output, encoding: .utf8), !publicKey.isEmpty else {
        throw SSHAgentError.failed("Could not derive the SSH public key")
    }
    return publicKey
}

private struct GPGSigningSettingsView: View {
    @StateObject private var approval = AuthorityApprovalState()
    let onCredentialSaved: () -> Void
    @State private var defaultConfigured = hasGPGSigningCredential(alternate: false)
    @State private var alternateConfigured = hasGPGSigningCredential(alternate: true)
    @State private var defaultPublicKey: String?
    @State private var alternatePublicKey: String?
    @State private var loadingPublicKeys = false
    @State private var credentialSheet: GPGCredentialSheet?
    @State private var configuration = loadGPGSigningConfiguration()
    @State private var status = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("GPG Signing")
                    .font(.system(size: 24, weight: .semibold))
                Text("Git commit signing becomes a Local Write operation at the GPG Signing Authorization Gate.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            InfoBlock(
                title: "Export from GnuPG",
                text: String(localized: "Run `gpg --list-secret-keys --keyid-format=long`, copy the signing key ID, then run `gpg --armor --export-secret-keys KEY_ID`. Add the complete PGP PRIVATE KEY BLOCK in the credential sheet. Automic Vault never displays a stored private key.")
            )

            credentialEditor(
                title: "Default signing credential",
                configured: defaultConfigured,
                publicKey: defaultPublicKey,
                alternate: false
            )

            Divider()

            credentialEditor(
                title: "Alternate signing credential",
                configured: alternateConfigured,
                publicKey: alternatePublicKey,
                alternate: true
            )

            Text("Use the alternate key for agents or other automation so commits made through those Verified Launchers are visibly distinct from your own.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            launcherList(
                configuration.alternateKeyLaunchers,
                title: "Verified Launchers using the alternate key",
                empty: "No Verified Launchers use the alternate key.",
                approval: approval
            ) { launcher in
                updateLaunchers(
                    configuration.alternateKeyLaunchers.filter {
                        $0.requirement != launcher.requirement
                    },
                    action: "Remove \(launcher.bundleIdentifier) from alternate GPG signing"
                )
            }

            AuthorityApprovalButton(title: "Add Verified Launcher…", approval: approval, action: "launchers") {
                chooseLauncher { launcher in
                    guard let launcher,
                          !configuration.alternateKeyLaunchers.contains(where: {
                              $0.requirement == launcher.requirement
                          })
                    else { return }
                    updateLaunchers(
                        configuration.alternateKeyLaunchers + [BlessedScriptLauncher(
                            bundleIdentifier: launcher.identifier,
                            requirement: launcher.requirement
                        )],
                        action: "Use the alternate GPG key for \(launcher.identifier)"
                    )
                }
            }

            Divider()

            Button("Configure Git") {
                do {
                    let program = Bundle.main.executableURL!
                        .deletingLastPathComponent()
                        .appendingPathComponent("av-gpg")
                    try configureGitForGPGSigning(programURL: program)
                    status = "Configured Git to sign commits with \(program.path)."
                } catch {
                    status = error.localizedDescription
                }
            }
            .buttonStyle(.borderedProminent)
            Text("Sets global `gpg.program`, `gpg.format=openpgp`, and `commit.gpgSign=true`. The executable stays inside the signed app bundle.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if !status.isEmpty {
                InfoBlock(title: "Status", text: status)
            }
        }
        .task {
            await refreshPublicKeys()
        }
        .sheet(item: $credentialSheet) { sheet in
            GPGCredentialSheetView(
                sheet: sheet,
                replacing: sheet.alternate ? alternateConfigured : defaultConfigured
            ) { publicKey in
                if sheet.alternate {
                    alternateConfigured = true
                    alternatePublicKey = publicKey
                } else {
                    defaultConfigured = true
                    defaultPublicKey = publicKey
                }
                status = "Saved the \(sheet.alternate ? "alternate" : "default") GPG signing credential in the Data Protection Keychain."
                onCredentialSaved()
            }
        }
        .onDisappear { approval.cancelAll() }
    }

    private func credentialEditor(
        title: String,
        configured: Bool,
        publicKey: String?,
        alternate: Bool
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(title).font(.system(size: 13, weight: .semibold))
                Spacer()
                Label(configured ? "Configured" : "Not configured", systemImage: configured ? "checkmark.circle.fill" : "circle")
                    .font(.caption)
                    .foregroundStyle(configured ? .green : .secondary)
            }
            if configured {
                if let publicKey {
                    publicKeyView(publicKey, title: title)
                } else if loadingPublicKeys {
                    ProgressView("Loading public key…")
                        .controlSize(.small)
                } else {
                    Text("Public key unavailable.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            HStack {
                Button(configured ? "Replace Credential…" : "Add Credential…") {
                    credentialSheet = alternate ? .importAlternate : .importDefault
                }
                if alternate {
                    Button("Generate Key…") {
                        credentialSheet = .generateAlternate
                    }
                }
            }
        }
    }

    private func publicKeyView(_ publicKey: String, title: String) -> some View {
        GroupBox("Public key") {
            VStack(alignment: .leading, spacing: 8) {
                ScrollView([.horizontal, .vertical]) {
                    Text(publicKey)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 100)
                Button("Copy Public Key") {
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(publicKey, forType: .string)
                    status = "Copied the \(title.lowercased()) public key."
                }
            }
        }
    }

    private func refreshPublicKeys() async {
        loadingPublicKeys = true
        defer { loadingPublicKeys = false }
        let mainExecutableURL = Bundle.main.executableURL
        if defaultConfigured {
            do {
                defaultPublicKey = try await storedGPGPublicKey(
                    alternate: false,
                    mainExecutableURL: mainExecutableURL
                )
            } catch {
                status = error.localizedDescription
            }
        }
        if alternateConfigured {
            do {
                alternatePublicKey = try await storedGPGPublicKey(
                    alternate: true,
                    mainExecutableURL: mainExecutableURL
                )
            } catch {
                status = error.localizedDescription
            }
        }
    }

    private func updateLaunchers(_ launchers: [BlessedScriptLauncher], action: String) {
        approval.request(
            "launchers", title: action,
            detail: "This changes which protected signing credential a Verified Launcher may use."
        ) { approved in
            guard approved else { return }
            let next = GPGSigningConfiguration(alternateKeyLaunchers: launchers)
            let result = saveGPGSigningConfiguration(next)
            guard result == errSecSuccess else {
                status = "Could not save the alternate-key Launcher list: \(result)"
                return
            }
            configuration = next
        }
    }
}

private enum GPGCredentialSheet: String, Identifiable {
    case importDefault
    case importAlternate
    case generateAlternate

    var id: String { rawValue }
    var alternate: Bool { self != .importDefault }
    var generatesKey: Bool { self == .generateAlternate }
}

private struct GPGCredentialSheetView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var privateKey = ""
    @State private var passphrase = ""
    @State private var name = ""
    @State private var email = ""
    @State private var errorMessage = ""
    @State private var isSaving = false

    let sheet: GPGCredentialSheet
    let replacing: Bool
    let onSaved: (String) -> Void

    var body: some View {
        NavigationStack {
            Form {
                if sheet.generatesKey {
                    TextField("Name", text: $name)
                    TextField("Verified Git email", text: $email)
                    Text("The email must match the commit email and a verified email on the Git host. The generated EdDSA private key is stored only in the Data Protection Keychain.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if replacing {
                        Text("Generating a key replaces the existing alternate signing credential. The previous private key cannot be recovered from Automic Vault.")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                } else {
                    Text("Armored private key")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $privateKey)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 110)
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                        .accessibilityLabel(sheet.alternate ? "Alternate private key" : "Default private key")
                    Text("Paste the complete PGP PRIVATE KEY BLOCK. It is visible only in this sheet and is never shown again after saving.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    SecureField("GnuPG passphrase (leave empty if none)", text: $passphrase)
                }
                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .formStyle(.grouped)
            .navigationTitle(navigationTitle)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(isSaving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(confirmationTitle) {
                        submit()
                    }
                    .disabled(!isValid || isSaving)
                }
            }
        }
        .frame(width: 560, height: sheet.generatesKey ? 240 : 390)
        .interactiveDismissDisabled(isSaving)
    }

    private var navigationTitle: String {
        if sheet.generatesKey {
            return replacing ? "Replace Alternate Signing Key" : "Generate Alternate Signing Key"
        }
        return replacing ? "Replace GPG Signing Credential" : "Add GPG Signing Credential"
    }

    private var confirmationTitle: String {
        if sheet.generatesKey { return replacing ? "Generate and Replace" : "Generate and Save" }
        return replacing ? "Replace" : "Save"
    }

    private var isValid: Bool {
        if sheet.generatesKey {
            return !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        return !privateKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func submit() {
        isSaving = true
        errorMessage = ""
        let mainExecutableURL = Bundle.main.executableURL
        Task {
            do {
                let publicKey = if sheet.generatesKey {
                    try await generateAndSaveAlternateGPGCredential(
                        name: name,
                        email: email,
                        mainExecutableURL: mainExecutableURL
                    )
                } else {
                    try await importAndSaveGPGCredential(
                        privateKey: privateKey,
                        passphrase: passphrase,
                        alternate: sheet.alternate,
                        mainExecutableURL: mainExecutableURL
                    )
                }
                privateKey = ""
                passphrase = ""
                onSaved(publicKey)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                isSaving = false
            }
        }
    }
}

@concurrent
private func storedGPGPublicKey(
    alternate: Bool,
    mainExecutableURL: URL?
) async throws -> String? {
    let name = alternate ? gpgAlternatePrivateKeySecretName : gpgDefaultPrivateKeySecretName
    guard let privateKey = loadStoredSecret(account: name) else { return nil }
    return try deriveGPGPublicKey(privateKey: privateKey, mainExecutableURL: mainExecutableURL)
}

@concurrent
private func importAndSaveGPGCredential(
    privateKey: String,
    passphrase: String,
    alternate: Bool,
    mainExecutableURL: URL?
) async throws -> String {
    let publicKey = try deriveGPGPublicKey(
        privateKey: privateKey,
        mainExecutableURL: mainExecutableURL
    )
    let status = saveGPGSigningCredential(
        privateKey: privateKey,
        passphrase: passphrase,
        alternate: alternate
    )
    guard status == errSecSuccess else {
        throw GPGSigningConfigurationError.credentialFailed("Data Protection Keychain error \(status)")
    }
    return publicKey
}

@concurrent
private func generateAndSaveAlternateGPGCredential(
    name: String,
    email: String,
    mainExecutableURL: URL?
) async throws -> String {
    let request = try JSONEncoder().encode(["name": name, "email": email])
    let privateKeyData = try runBundledCredentialCommand(
        arguments: ["__gpg-generate-key"],
        input: request,
        mainExecutableURL: mainExecutableURL
    )
    guard let privateKey = String(data: privateKeyData, encoding: .utf8) else {
        throw GPGSigningConfigurationError.credentialFailed("Generated private key is not valid UTF-8")
    }
    return try await importAndSaveGPGCredential(
        privateKey: privateKey,
        passphrase: "",
        alternate: true,
        mainExecutableURL: mainExecutableURL
    )
}

private func deriveGPGPublicKey(
    privateKey: String,
    mainExecutableURL: URL?
) throws -> String {
    let output = try runBundledCredentialCommand(
        arguments: ["__gpg-public-key"],
        input: Data(privateKey.utf8),
        mainExecutableURL: mainExecutableURL
    )
    guard let publicKey = String(data: output, encoding: .utf8) else {
        throw GPGSigningConfigurationError.credentialFailed("Public key is not valid UTF-8")
    }
    return publicKey
}

func validatedBundledAVURL(mainExecutableURL: URL?) throws -> URL {
    let executable = try bundledExecutableURL(
        named: "av",
        beside: mainExecutableURL
    )
    var staticCode: SecStaticCode?
    var signingInformation: CFDictionary?
    guard SecStaticCodeCreateWithPath(executable as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode,
          SecStaticCodeCheckValidity(
              staticCode,
              SecCSFlags(rawValue: kSecCSStrictValidate),
              nil
          ) == errSecSuccess,
          SecCodeCopySigningInformation(
              staticCode,
              SecCSFlags(rawValue: kSecCSSigningInformation),
              &signingInformation
          ) == errSecSuccess,
          let signing = signingInformation as? [CFString: Any],
          signing[kSecCodeInfoIdentifier] as? String == "com.automicvault.av",
          let teamIdentifier = selfTeamIdentifier(),
          signing[kSecCodeInfoTeamIdentifier] as? String == teamIdentifier
    else { throw GPGSigningConfigurationError.bundledExecutableUnavailable(executable.path) }
    return executable
}

func runBundledCredentialCommand(
    arguments: [String],
    input inputData: Data,
    mainExecutableURL: URL?
) throws -> Data {
    let process = Process()
    let executable = try validatedBundledAVURL(mainExecutableURL: mainExecutableURL)
    process.executableURL = executable
    process.arguments = arguments
    let inputPipe = Pipe()
    let output = Pipe()
    let errors = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    inputPipe.fileHandleForWriting.write(inputData)
    try inputPipe.fileHandleForWriting.close()
    let outputData = output.fileHandleForReading.readDataToEndOfFile()
    let errorData = errors.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        let detail = String(
            decoding: errorData,
            as: UTF8.self
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        throw GPGSigningConfigurationError.credentialFailed(detail)
    }
    return outputData
}

private struct AboutSettingsView: View {
    let guiPath: String
    let version: String

    init(guiPath: String = guiPATH(), version: String = appVersion() ?? "Unknown") {
        self.guiPath = guiPath
        self.version = version
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("About")
                    .font(.system(size: 24, weight: .semibold))
                Text("Details about the running Automic Vault app.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            SecretGateField("Version", version)
            SecretGateField("GUI PATH (before shells)", guiPath, monospaced: true)
            Text("This is the PATH inherited by the app before shell startup files run.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

func appVersion(bundle: Bundle = .main) -> String? {
    (bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
        .flatMap { $0.isEmpty ? nil : $0 }
}

private func guiPATH(environment: [String: String] = ProcessInfo.processInfo.environment) -> String {
    environment["PATH"].flatMap { $0.isEmpty ? nil : $0 } ?? "<unset>"
}

private struct SecretGateDetailView: View {
    @ObservedObject var model: DashboardModel
    let gate: SecretGate

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(gate.displayName)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(3)
                Text("\(countLabel(gate.keyPatterns.count, "secret")) protected with \(countLabel(gate.appPolicies.count, "Launcher rule"))")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 10) {
                if !gate.scriptPaths.isEmpty {
                    SecretGateField("Scripts", gate.scriptPaths.joined(separator: ", "))
                }
                SecretGateField("Secrets", gate.keyPatterns.joined(separator: ", "))
                SecretGateField("Targets", gate.targetPaths.joined(separator: ", "))
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("Verified Launcher Access")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)

                if model.isDiscoveringLauncherHelpers {
                    ProgressView("Inspecting the selected app for Verified Launcher Helpers…")
                        .controlSize(.small)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("verified-launcher-helper-inspection-progress")
                }

                VStack(spacing: 0) {
                    DefaultAppPolicyRow(gate: gate, protection: gate.defaultProtection, approval: model.authorityApproval) {
                        model.setDefaultProtection($0, for: gate)
                    }
                    if !gate.appPolicies.isEmpty { hairline }
                    ForEach(gate.appPolicies, id: \.requirement) { app in
                        ApprovedAppRow(
                            app: app,
                            launcherBundle: model.launcherBundles.first {
                                $0.launcherRequirement == app.requirement
                            },
                            gate: gate,
                            approval: model.authorityApproval,
                            setProtection: { model.setProtection($0, for: app, in: gate) },
                            remove: { model.removeAppPolicy(app, from: gate) }
                        )
                        if app.requirement != gate.appPolicies.last?.requirement {
                            hairline
                        }
                    }
                }
            }

            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }

    private func countLabel(_ count: Int, _ singular: String) -> String {
        count == 1 ? "1 \(singular)" : "\(count) \(singular)s"
    }
}

private struct SecretGateField: View {
    let label: String
    let value: String
    let monospaced: Bool

    init(_ label: String, _ value: String, monospaced: Bool = false) {
        self.label = label
        self.value = value
        self.monospaced = monospaced
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(localizedUIString(label).uppercased())
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }
}

private struct ApprovedAppRow: View {
    let app: SecretGatePolicy
    let launcherBundle: LauncherBundleEnrollment?
    let gate: SecretGate
    let approval: AuthorityApprovalState
    let setProtection: (SecretGateProtection) -> Void
    let remove: () -> Void
    @State private var isConfirmingDelete = false

    private var display: ApprovedAppDisplay {
        ApprovedAppDisplay(app, launcherBundle: launcherBundle)
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(nsImage: display.icon)
                .resizable()
                .frame(width: 34, height: 34)
            VStack(alignment: .leading, spacing: 4) {
                Text(display.name)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text(display.bundleIdentifier)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Text(display.signingSummary)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            ProtectionMenu(gate: gate, protection: app.protection, approval: approval, action: "gate-policy:\(gate.id):\(app.requirement)", setProtection: setProtection)
                .frame(minWidth: 132, alignment: .trailing)
        }
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .contextMenu {
            Button("Delete", role: .destructive) {
                isConfirmingDelete = true
            }
        }
        .alert("Delete \(display.name)?", isPresented: $isConfirmingDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive, action: remove)
        } message: {
            Text("This deletes the Launcher-specific rule. Future requests from this Verified Launcher at the \(gate.displayName) Authorization Gate will use the default \(gate.protectionTitle(gate.defaultProtection)) Access Level.")
        }
    }
}

private struct DefaultAppPolicyRow: View {
    let gate: SecretGate
    let protection: SecretGateProtection
    let approval: AuthorityApprovalState
    let setProtection: (SecretGateProtection) -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "square.stack.3d.up")
                .font(.system(size: 18))
                .frame(width: 34, height: 34)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(localizedUIString(gate.defaultPolicyLabel))
                    .font(.system(size: 13, weight: .medium))
                Text("Requires Hardened Runtime")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            ProtectionMenu(gate: gate, protection: protection, approval: approval, action: "gate-default:\(gate.id)", setProtection: setProtection)
                .frame(minWidth: 132, alignment: .trailing)
        }
        .padding(.vertical, 10)
    }
}

private struct ProtectionMenu: View {
    let gate: SecretGate
    let protection: SecretGateProtection
    @ObservedObject var approval: AuthorityApprovalState
    let action: String
    let setProtection: (SecretGateProtection) -> Void
    @AppStorage(phoneApprovalEnabledDefaultsKey) private var phoneEnabled = false

    var body: some View {
        if approval.isPending(action) {
            AuthorityApprovalLabel(title: "Change Access Level", approval: approval, action: action)
                .font(.caption)
        } else {
            NativeProtectionMenu(
                gate: gate, protection: protection,
                usesPhone: phoneEnabled && authorityChangeUsesIPhone,
                setProtection: setProtection
            )
        }
    }
}

private struct NativeProtectionMenu: NSViewRepresentable {
    let gate: SecretGate
    let protection: SecretGateProtection
    let usesPhone: Bool
    let setProtection: (SecretGateProtection) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    func makeNSView(context: Context) -> NSPopUpButton {
        let button = NSPopUpButton(frame: .zero, pullsDown: false)
        button.isBordered = false
        button.controlSize = .small
        button.target = context.coordinator
        button.action = #selector(Coordinator.selectProtection(_:))
        button.setAccessibilityLabel(String(localized: "Protection level"))
        configureItems(in: button)
        updateSelection(in: button)
        return button
    }

    func updateNSView(_ button: NSPopUpButton, context: Context) {
        context.coordinator.parent = self
        configureItems(in: button)
        updateSelection(in: button)
    }

    private func configureItems(in button: NSPopUpButton) {
        button.removeAllItems()
        for candidate in gate.availableProtections {
            button.addItem(withTitle: localizedUIString(gate.protectionTitle(candidate)))
            if usesPhone && candidate.addsAuthority(over: protection) {
                let title = NSMutableAttributedString(string: localizedUIString(gate.protectionTitle(candidate)) + "  ")
                let attachment = NSTextAttachment()
                attachment.image = NSImage(systemSymbolName: "iphone", accessibilityDescription: String(localized: "Approval on iPhone"))?
                    .withSymbolConfiguration(.init(pointSize: 11, weight: .regular))
                title.append(NSAttributedString(attachment: attachment))
                button.lastItem?.attributedTitle = title
                button.lastItem?.toolTip = String(localized: "Requires Approval on iPhone.")
            }
            if #available(macOS 14.4, *) {
                button.lastItem?.subtitle = localizedUIString(gate.protectionSubtitle(candidate))
            }
            if candidate == .fullExceptSecretDumps || candidate == .fullIncludingSecretDumps {
                let warning = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: String(localized: "Warning"))
                button.lastItem?.image = candidate == .fullIncludingSecretDumps
                    ? warning?.withSymbolConfiguration(.init(paletteColors: [.systemRed]))
                    : warning
            }
        }
    }

    private func updateSelection(in button: NSPopUpButton) {
        guard let selectedIndex = gate.availableProtections.firstIndex(of: protection) else { return }
        button.selectItem(at: selectedIndex)
        for (index, item) in button.itemArray.enumerated() {
            item.state = index == selectedIndex ? .on : .off
        }
        button.invalidateIntrinsicContentSize()
    }

    final class Coordinator: NSObject {
        var parent: NativeProtectionMenu

        init(parent: NativeProtectionMenu) {
            self.parent = parent
        }

        @MainActor @objc func selectProtection(_ sender: NSPopUpButton) {
            let candidates = parent.gate.availableProtections
            let selectedIndex = sender.indexOfSelectedItem
            guard candidates.indices.contains(selectedIndex) else { return }
            parent.setProtection(candidates[selectedIndex])
        }
    }
}

private struct ApprovedAppDisplay {
    let name: String
    let bundleIdentifier: String
    let icon: NSImage
    let signingSummary: String

    init(_ app: SecretGatePolicy, launcherBundle: LauncherBundleEnrollment? = nil) {
        if let launcherBundle {
            name = launcherBundle.displayName
            bundleIdentifier = launcherBundle.bundleIdentifier
            icon = NSWorkspace.shared.icon(forFile: launcherBundle.bundlePath)
            signingSummary = launcherBundle.signingIdentity ?? launcherBundle.signingKind.title
            return
        }
        let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.bundleIdentifier)
        let bundle = url.flatMap(Bundle.init(url:))
        name = bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? url?.deletingPathExtension().lastPathComponent
            ?? app.bundleIdentifier
        bundleIdentifier = app.bundleIdentifier
        icon = url.map { NSWorkspace.shared.icon(forFile: $0.path) } ?? NSImage(systemSymbolName: "app", accessibilityDescription: nil) ?? NSImage()
        if let teamIdentifier = codeSigningTeamIdentifier(from: app.requirement) {
            signingSummary = "Team \(teamIdentifier)"
        } else {
            signingSummary = "Signing identity unavailable"
        }
    }
}

struct LauncherSigning: Sendable {
    let identifier: String
    let teamIdentifier: String
    let path: String
    let requirement: String
    let runtimeProtection: LauncherRuntimeProtection
}

struct LauncherHelperReview: Identifiable, Sendable {
    let id = UUID()
    let signing: LauncherSigning
    let gate: SecretGate
    let runtimeRequirement: LauncherRuntimeRequirement
    let helpers: [VerifiedLauncherHelper]
}

struct DirectAccessLauncherSelection: Identifiable {
    let launcher: BlessedScriptLauncher
    let runtimeRequirement: LauncherRuntimeRequirement

    var id: String { launcher.requirement }
}

private let libraryValidationWarning = "This Launcher permits third-party libraries and plug-ins to run inside its process. That code can inherit the Launcher’s Secret Gate authority."

private func launcherRuntimeWarning(_ requirement: LauncherRuntimeRequirement) -> String? {
    requirement == .hardenedAllowingLibraryValidationDisabled
        ? libraryValidationWarning
        : nil
}

private func launcherRuntimeWarning(_ protection: LauncherRuntimeProtection) -> String? {
    switch protection {
    case .hardened:
        nil
    case .hardenedWithLibraryValidationDisabled:
        libraryValidationWarning
    case .hardenedRuntimeMissing:
        "This Launcher does not enable Hardened Runtime. It can be endorsed for an exact Blessed Script, but it cannot receive Secret Gate access."
    case .unsafeEntitlements(let entitlements):
        "This Launcher enables blocked Hardened Runtime exceptions: \(entitlements.joined(separator: ", ")). It can be endorsed for an exact Blessed Script, but it cannot receive Secret Gate access."
    }
}

private let launcherPickerAllowedContentTypes: [UTType] = [.applicationBundle, .data]

func launcherPickerAllows(filenameExtension: String) -> Bool {
    guard let type = UTType(filenameExtension: filenameExtension) else { return false }
    return launcherPickerAllowedContentTypes.contains { type.conforms(to: $0) }
}

private func secretGateAdmissionError(
    appName: String,
    protection: LauncherRuntimeProtection
) -> String {
    switch protection {
    case .hardened, .hardenedWithLibraryValidationDisabled:
        return ""
    case .hardenedRuntimeMissing:
        return "\(appName) does not enable Hardened Runtime and cannot receive secret-gate access."
    case .unsafeEntitlements(let entitlements):
        return "\(appName) weakens Hardened Runtime with \(entitlements.joined(separator: ", ")) and cannot receive secret-gate access."
    }
}

@MainActor
private func showLauncherCannotBeAllowed(_ reason: String) {
    let alert = NSAlert()
    alert.messageText = "Launcher cannot be allowed"
    alert.informativeText = reason
    alert.runModal()
}

@MainActor
private func chooseLauncher(_ completion: @escaping (LauncherSigning?) -> Void) {
    pickLauncher { signing in
        guard let signing else {
            completion(nil)
            return
        }
        let alert = NSAlert()
        alert.messageText = "Select \(signing.identifier) as a Verified Launcher?"
        alert.informativeText = """
        Identifier: \(signing.identifier)
        Team ID: \(signing.teamIdentifier)
        Path: \(signing.path)

        Designated requirement:
        \(signing.requirement)
        """
        if let warning = launcherRuntimeWarning(signing.runtimeProtection) {
            alert.alertStyle = .warning
            alert.informativeText += "\n\nWarning:\n\(warning)"
        }
        alert.addButton(withTitle: "Select")
        alert.addButton(withTitle: "Cancel")
        completion(alert.runModal() == .alertFirstButtonReturn ? signing : nil)
    }
}

@MainActor
private func pickLauncher(_ completion: @escaping (LauncherSigning?) -> Void) {
    let panel = NSOpenPanel()
    panel.title = "Choose Verified Launcher"
    panel.message = "Choose a .app, or press ⇧⌘G to enter the path to a CLI executable."
    panel.prompt = "Choose"
    panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
    panel.allowedContentTypes = launcherPickerAllowedContentTypes
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.begin { response in
        guard response == .OK, let selected = panel.url else {
            completion(nil)
            return
        }
        let isAccessing = selected.startAccessingSecurityScopedResource()
        defer {
            if isAccessing { selected.stopAccessingSecurityScopedResource() }
        }
        let resolved = selected.resolvingSymlinksInPath().standardizedFileURL
        guard let signing = launcherSigning(resolved) else {
            showLauncherCannotBeAllowed("Choose a valid Developer ID-signed executable or signed app.")
            completion(nil)
            return
        }
        completion(signing)
    }
}

private func launcherSigning(_ url: URL) -> LauncherSigning? {
    let isApp = url.pathExtension.caseInsensitiveCompare("app") == .orderedSame
    guard isApp || FileManager.default.isExecutableFile(atPath: url.path) else { return nil }
    if isApp,
       launcherBundleAppURL(containing: url.path) == url.standardizedFileURL,
       let launcherExecutable = Bundle(url: url)?.executableURL,
       let launcherEvidence = try? launcherBundleCodeEvidence(at: launcherExecutable),
       let enrollment = try? verifyLauncherBundle(
           at: url,
           liveLauncherIdentifier: launcherEvidence.identifier,
           liveLauncherCodeIdentifier: launcherEvidence.codeIdentifiers[0],
           liveRuntimeProtection: .hardened
       ) {
        return LauncherSigning(
            identifier: enrollment.bundleIdentifier,
            teamIdentifier: launcherEvidence.teamIdentifier ?? "Automic Vault",
            path: url.path,
            requirement: enrollment.launcherRequirement,
            runtimeProtection: enrollment.runtimeRequirement == .hardened
                ? .hardened
                : .hardenedWithLibraryValidationDisabled
        )
    }
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode
    else {
        return nil
    }
    let validationStatus = isApp
        ? validateAppBundleMainExecutable(staticCode)
        : SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode),
            nil
        )
    guard validationStatus == errSecSuccess else { return nil }

    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any],
          let requirementValue = dictionary[kSecCodeInfoDesignatedRequirement],
          ((dictionary[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0) & secCodeSignatureAdHoc == 0,
          let identifier = dictionary[kSecCodeInfoIdentifier] as? String
    else {
        return nil
    }
    let teamIdentifier = dictionary[kSecCodeInfoTeamIdentifier] as? String ?? "unknown"
    guard isApp || (teamIdentifier != "unknown" && satisfiesDeveloperIDRequirement {
        SecStaticCodeCheckValidity(staticCode, [], $0)
    }) else { return nil }
    let requirement = requirementValue as! SecRequirement
    guard let requirementText = requirementText(requirement) else {
        return nil
    }
    return LauncherSigning(
        identifier: identifier,
        teamIdentifier: teamIdentifier,
        path: url.path,
        requirement: requirementText,
        runtimeProtection: launcherRuntimeProtection(signingInformation: dictionary)
    )
}

private func requirementText(_ requirement: SecRequirement) -> String? {
    var text: CFString?
    guard SecRequirementCopyString(requirement, [], &text) == errSecSuccess,
          let text
    else {
        return nil
    }
    return text as String
}

private extension View {
    func outlinedPill(_ color: Color = .red) -> some View {
        foregroundStyle(color)
            .background(color.opacity(0.12), in: Capsule())
            .overlay {
                Capsule().stroke(color, lineWidth: 1)
            }
    }
}

private var hairline: some View {
    Rectangle().fill(Color(nsColor: .separatorColor)).frame(height: 1)
}

/// Bounded summaries only: full inventories and actions stay in their existing sections.
private struct DashboardOverviewView: View {
    @ObservedObject var model: DashboardModel
    let checkForUpdates: () -> Void

    private var projectCount: Int {
        Set(model.snapshot.secrets.flatMap(\.values).compactMap { value -> String? in
            if case .projectDirectory(let path) = value.source { return path }
            return nil
        }).count
    }

    var body: some View {
        GeometryReader { geometry in
            let compact = geometry.size.height < 550
            VStack(alignment: .leading, spacing: compact ? 12 : 20) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Overview").font(.largeTitle.bold())
                    Spacer()
                    Text("Automic Vault").foregroundStyle(.secondary)
                }
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 20) {
                        tools(limit: compact ? 3 : 6).frame(minWidth: 320)
                        attention(compact: compact).frame(width: 240)
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        tools(limit: max(2, min(6, Int((geometry.size.height - 420) / 44))))
                        attention(compact: true)
                    }
                }
                Spacer(minLength: 0)
                HStack(spacing: 12) {
                    summary(.allSecrets, value: "\(model.snapshot.secrets.count)", caption: "Secrets")
                    summary(.launcherBundles, value: "\(model.launcherBundles.count)", caption: "Launcher Bundles")
                    summary(.allSecrets, value: "\(projectCount)", caption: "Projects with Values")
                }
            }
            .padding(20)
            .frame(width: geometry.size.width, height: geometry.size.height, alignment: .topLeading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .navigationTitle("Overview")
    }

    private func tools(limit: Int) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Tools").font(.title2.bold())
                Spacer()
                destination("All detectors", section: .detectors)
            }
            Text("Findings and hardening on this Mac")
                .font(.caption).foregroundStyle(.secondary)
            VStack(spacing: 0) {
                if model.overviewTools.isEmpty {
                    Button {
                        model.navigateFromOverview(to: .detectors)
                    } label: {
                        Label(model.hasSearchQuery ? "No matching Tools · View detectors" : "Review available detectors", systemImage: "sensor.tag.radiowaves.forward")
                            .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    }.buttonStyle(.plain)
                }
                ForEach(model.overviewTools.prefix(limit)) { tool in
                    Button {
                        let section: DashboardSection = tool.isTriggered || model.snapshot.detectors.contains { $0.name == tool.id }
                            ? .detectors : .hardenedTools
                        model.navigateFromOverview(to: section, itemID: tool.id)
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: tool.isTriggered ? "exclamationmark.triangle.fill" : "hammer")
                                .foregroundStyle(tool.isTriggered ? Color.orange : Color.accentColor)
                                .frame(width: 20)
                            Text(tool.title).fontWeight(.medium).lineLimit(1)
                            Spacer(minLength: 8)
                            Text(tool.isTriggered ? "Finding" : "Hardened")
                                .font(.caption).foregroundStyle(.secondary)
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }.padding(12).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(tool.subtitle)
                    if tool.id != model.overviewTools.prefix(limit).last?.id { Divider().padding(.leading, 42) }
                }
            }
            .background(.background, in: RoundedRectangle(cornerRadius: 10))
            HStack {
                destination("\(model.snapshot.hardenedTools.count) hardened Tools", section: .hardenedTools)
                Spacer()
                if model.overviewTools.count > limit {
                    Text("Showing \(limit) of \(model.overviewTools.count)").foregroundStyle(.secondary)
                }
            }.font(.caption)
        }
    }

    private func attention(compact: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Attention").font(.headline)
            HStack {
                destination("\(model.snapshot.flaggedDetectorCount) flagged detectors", section: .detectors)
                if compact { Spacer() }
            }
            destination(model.snapshot.doctorIssues.count == 1 ? "Doctor · 1 issue" : "Doctor · \(model.snapshot.doctorIssues.count) issues", section: .doctor)
            if !compact, let issue = model.snapshot.doctorIssues.first {
                Button {
                    model.navigateFromOverview(to: .doctor, itemID: issue.id)
                } label: {
                    Text(issue.message).font(.callout).foregroundStyle(.secondary)
                        .lineLimit(3).frame(maxWidth: .infinity, alignment: .leading)
                }.buttonStyle(.plain)
            }
            Divider()
            HStack {
                Text("What’s new").font(.headline)
                Spacer()
                Button(model.availableUpdateVersion.map { "Update to v\($0)" } ?? "Check for updates",
                       action: checkForUpdates)
                    .buttonStyle(.link).lineLimit(1)
            }
            if !compact {
                Text("App updates and release notes")
                    .font(.caption).foregroundStyle(.secondary)
                destination("Settings", section: .settings)
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }

    private func summary(_ section: DashboardSection, value: String, caption: String) -> some View {
        Button {
            model.navigateFromOverview(to: section)
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: section.systemImage).foregroundStyle(Color.accentColor)
                    Spacer()
                    Text(value).font(.title2.monospacedDigit())
                }
                Text(caption).font(.caption).lineLimit(1)
            }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 10))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func destination(_ title: String, section: DashboardSection) -> some View {
        Button(title) { model.navigateFromOverview(to: section) }
            .buttonStyle(.link).lineLimit(1)
    }
}
