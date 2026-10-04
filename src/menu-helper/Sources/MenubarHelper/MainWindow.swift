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

    func setAvailableUpdateVersion(_ version: String?, checkedAt: Date? = nil) {
        model.availableUpdateVersion = version
        model.lastUpdateCheck = checkedAt
    }

    func showAccessRequest(id: UUID) {
        model.showAccessRequest(id: id)
    }

    func showScriptsNeedingReblessing() {
        model.showScriptsNeedingReblessing()
        model.reload()
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

// Presentation-only index; authorization decisions never consult these counts.
private struct DashboardActivityIndex {
    private let datesByTool: [String: [Date]]
    private let recordsByTool: [String: [AccessRequestRecord]]

    init(_ records: [AccessRequestRecord]) {
        recordsByTool = Dictionary(grouping: records, by: \.tool)
            .mapValues { $0.sorted { $0.date < $1.date } }
        datesByTool = recordsByTool.mapValues { $0.map(\.date) }
    }

    func latestActivity(for tool: String) -> Date {
        datesByTool[tool]?.last ?? .distantPast
    }

    func count(for tool: String, now: Date) -> Int {
        let dates = datesByTool[tool] ?? []
        return boundary(now, in: dates, includingEqual: true)
            - boundary(now.addingTimeInterval(-86_400), in: dates)
    }

    static func slotCount(forWidth width: CGFloat) -> Int {
        // Keep at least one point of fill plus the one-point gap per bucket.
        [96, 144, 288, 720, 1440].last { CGFloat($0) * 2 <= width } ?? 96
    }

    func slots(for tool: String, now: Date, count: Int = 96) -> [Int] {
        let dates = datesByTool[tool] ?? []
        let start = now.addingTimeInterval(-86_400)
        var previous = boundary(start, in: dates)
        return (0..<count).map { slot in
            let end = start.addingTimeInterval(Double(slot + 1) * (86_400 / Double(count)))
            let next = boundary(end, in: dates, includingEqual: slot == count - 1)
            defer { previous = next }
            return next - previous
        }
    }

    func latestRecord(for tool: String, now: Date, slot: Int, count: Int) -> AccessRequestRecord? {
        guard count > 0, (0..<count).contains(slot),
              let dates = datesByTool[tool], let records = recordsByTool[tool] else { return nil }
        let start = now.addingTimeInterval(-86_400)
        let duration = 86_400 / Double(count)
        let lower = boundary(start.addingTimeInterval(Double(slot) * duration), in: dates)
        let upper = boundary(start.addingTimeInterval(Double(slot + 1) * duration),
                             in: dates, includingEqual: slot == count - 1)
        return upper > lower ? records[upper - 1] : nil
    }

    // Binary searches avoid scanning retained records during rendering.
    private func boundary(_ date: Date, in dates: [Date], includingEqual: Bool = false) -> Int {
        var low = 0
        var high = dates.count
        while low < high {
            let middle = low + (high - low) / 2
            if dates[middle] < date || (includingEqual && dates[middle] == date) {
                low = middle + 1
            } else {
                high = middle
            }
        }
        return low
    }
}

@MainActor
final class DashboardModel: ObservableObject {
    @Published var selectedSection: DashboardSection = .overview
    @Published private(set) var snapshot = DashboardSnapshot.empty
    @Published private(set) var hasLoadedInitialSnapshot = false
    @Published private(set) var isReloading = false
    @Published var isAddingSecret = false
    @Published var isRenamingSecret = false
    @Published var isCreatingLauncherBundle = false
    @Published private(set) var isBuildingLauncherBundle = false
    @Published var errorMessage: String?
    @Published var selectedLauncherRequirement: String?
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
    @Published private var overviewHistory: [AccessRequestRecord]? = nil {
        didSet { overviewActivityIndex = overviewHistory.map(DashboardActivityIndex.init) }
    }
    private var overviewActivityIndex: DashboardActivityIndex?
    private var historyRecordsByID: [UUID: AccessRequestRecord] = [:]
    private var historySearchTask: Task<Void, Never>?
    private var historySearchWorker: Task<[HistorySearchDay], Never>?
    private var historySearchGeneration = 0
    @Published private(set) var cliInstallState: CLIInstallState?
    @Published fileprivate var availableUpdateVersion: String?
    @Published fileprivate var lastUpdateCheck: Date?
    @Published private(set) var lastHardeningRefresh: Date?
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
    private var selectScriptNeedingReblessing = false
    private var launcherHelperDiscoveryTask: Task<Void, Never>?
    let authorityApproval = AuthorityApprovalState()

    private var blessingCompletion: ((BlessedScriptReviewOutcome) -> Void)?

    init(snapshot: DashboardSnapshot? = nil, cliInstallState: CLIInstallState? = nil) {
        hasLoadedInitialSnapshot = snapshot != nil
        let snapshot = snapshot ?? .empty
        self.snapshot = snapshot
        self.cliInstallState = cliInstallState
        setHistoryRecords(snapshot.accessRequests)
        overviewHistory = snapshot.accessRequests
        overviewActivityIndex = DashboardActivityIndex(snapshot.accessRequests)
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
                    title: String(localized: "Authorization History"),
                    subtitle: String(localized: "Storage size and access"),
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

    var scriptsNeedingReblessing: [DashboardItem] {
        blessedScriptItems(snapshot.blessedScripts, pending: nil).filter { $0.blessingStatus == "Changed" }
    }

    func showScriptsNeedingReblessing() {
        searchText = ""
        selectSection(.blessedScripts)
        selectScriptNeedingReblessing = true
        normalizeSelection()
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
        selectedLauncherRequirement = nil
        selectScriptNeedingReblessing = false
        pendingAccessRequestID = nil
        selectedSection = section
        selectedItemID = nil
        if section == .secretUsage { refreshHistorySearch() }
        normalizeSelection()
    }

    func select(_ item: DashboardItem) {
        selectedLauncherRequirement = nil
        pendingAccessRequestID = nil
        selectScriptNeedingReblessing = false
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
        selectedLauncherRequirement = nil
        searchText = ""
        pendingAccessRequestID = nil
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

    func addApp(to script: BlessedScript, recentApp: AccessRequestRecord? = nil) {
        chooseLauncherApp(recentApp: recentApp) { [weak self] launcher in
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

    private func chooseLauncherApp(
        recentApp: AccessRequestRecord? = nil,
        _ completion: @escaping (BlessedScriptLauncher?) -> Void
    ) {
        chooseLauncher(recentApp: recentApp) { signing in
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
            let (page, activity) = await Task.detached(priority: .background) {
                (loadAccessRequestRecordsPage(),
                 loadAccessRequestRecordsForDisclosure(since: Date().addingTimeInterval(-86_400)))
            }.value
            guard !Task.isCancelled else { return }
            overviewHistory = activity
            next.accessRequests = generation == accessRequestsGeneration
                ? (page?.records ?? []) : snapshot.accessRequests
            snapshot = next
            lastHardeningRefresh = Date()
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
            hasLoadedInitialSnapshot = true
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
            let (page, activity) = await Task.detached(priority: .background) {
                (loadAccessRequestRecordsPage(),
                 loadAccessRequestRecordsForDisclosure(since: Date().addingTimeInterval(-86_400)))
            }.value
            guard !Task.isCancelled, let self,
                  generation == accessRequestsGeneration else { return }
            overviewHistory = activity
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

    fileprivate func reloadAuthorizationState() {
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
        if selectedSection == .blessedScripts, selectScriptNeedingReblessing,
           let changed = scriptsNeedingReblessing.first {
            selectedItemID = changed.id
            selectScriptNeedingReblessing = false
            return
        }
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

    func historyRecord(id: String) -> AccessRequestRecord? {
        UUID(uuidString: id).flatMap { historyRecordsByID[$0] }
    }

    func configureLauncher(from record: AccessRequestRecord) {
        guard record.canConfigureLauncher else { return }
        guard let gate = snapshot.secretGates.first(where: { $0.id == record.gateID }) else {
            showLauncherCannotBeAllowed(String(localized: "This Authorization Gate is no longer available."),
                                        title: String(localized: "Launcher cannot be configured"))
            return
        }
        // History supplies a destination, never current identity or authority.
        guard recentLauncherSigning(record) != nil else {
            showLauncherCannotBeAllowed(String(localized: "This Launcher no longer exists or its verified identity has changed."),
                                        title: String(localized: "Launcher cannot be configured"))
            return
        }
        if !gate.appPolicies.contains(where: { $0.requirement == record.launcherRequirement }) {
            let alert = NSAlert()
            alert.messageText = String(localized: "Create a Launcher rule?")
            alert.informativeText = String(localized: "This Launcher has no rule at the \(gate.displayName) Authorization Gate. Review its identity and approve a new rule to configure its Access Level.")
            alert.addButton(withTitle: String(localized: "Create Rule…"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            showSecretGate(id: gate.id)
            selectedLauncherRequirement = record.launcherRequirement
            addApp(to: gate, recentApp: record)
        } else {
            showSecretGate(id: gate.id)
            selectedLauncherRequirement = record.launcherRequirement
        }
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

    func addApp(to gate: SecretGate, recentApp: AccessRequestRecord? = nil) {
        guard !isDiscoveringLauncherHelpers, pendingLauncherHelperReview == nil else { return }
        chooseLauncher(recentApp: recentApp, reviewsIdentity: false) { [weak self] signing in
            guard let self, let signing else { return }
            self.reviewLauncher(signing, for: gate)
        }
    }

    func reviewLauncher(_ signing: LauncherSigning, for gate: SecretGate) {
        guard pendingLauncherHelperReview == nil else { return }
        guard let runtimeRequirement = signing.runtimeProtection.secretGateAdmissionRequirement else {
            showLauncherCannotBeAllowed(secretGateAdmissionError(
                appName: signing.identifier,
                protection: signing.runtimeProtection
            ))
            return
        }
        let review = LauncherHelperReview(
            signing: signing, gate: gate, runtimeRequirement: runtimeRequirement, helpers: []
        )
        let isApp = URL(fileURLWithPath: signing.path).pathExtension
            .caseInsensitiveCompare("app") == .orderedSame
        self.isDiscoveringLauncherHelpers = isApp
        self.pendingLauncherHelperReview = review
        guard isApp else { return }
        self.launcherHelperDiscoveryTask = Task { [weak self] in
            let discovered = await discoverVerifiedLauncherHelpers(
                in: URL(fileURLWithPath: signing.path, isDirectory: true)
            )
            guard !Task.isCancelled, let self,
                  self.pendingLauncherHelperReview?.id == review.id else { return }
            let configuration = loadVerifiedLauncherHelperConfiguration()
            var seen = Set<String>()
            var helpers = discovered.compactMap { discovered -> VerifiedLauncherHelper? in
                let helper = configuration.catalogHelper(matching: discovered) ?? discovered
                return seen.insert(helper.id).inserted ? helper : nil
            }
            if signing.identifier == claudeCodeVerifiedLauncherHelper.appBundleIdentifier,
               signing.teamIdentifier == claudeCodeVerifiedLauncherHelper.appTeamIdentifier {
                helpers.removeAll { $0.id == claudeCodeVerifiedLauncherHelper.id }
                helpers.insert(claudeCodeVerifiedLauncherHelper, at: 0)
            }
            self.pendingLauncherHelperReview?.helpers = helpers
            self.isDiscoveringLauncherHelpers = false
            self.launcherHelperDiscoveryTask = nil
        }
    }

    func cancelLauncherHelperDiscovery() {
        cancelLauncherHelperReview()
    }

    func confirmLauncherHelperReview(selectedHelperIDs: Set<String>) {
        guard !isDiscoveringLauncherHelpers, let review = pendingLauncherHelperReview else { return }
        finishAddingLauncher(
            review.signing,
            to: review.gate,
            runtimeRequirement: review.runtimeRequirement,
            helpers: review.helpers.filter { selectedHelperIDs.contains($0.id) },
            disabledHelperIDs: review.disabledHelperIDs(selected: selectedHelperIDs)
        )
    }

    func cancelLauncherHelperReview() {
        launcherHelperDiscoveryTask?.cancel()
        launcherHelperDiscoveryTask = nil
        isDiscoveringLauncherHelpers = false
        if let review = pendingLauncherHelperReview {
            authorityApproval.cancel("gate-launcher:\(review.gate.id)")
        }
        pendingLauncherHelperReview = nil
    }

    private func finishAddingLauncher(
        _ signing: LauncherSigning,
        to gate: SecretGate,
        runtimeRequirement: LauncherRuntimeRequirement,
        helpers: [VerifiedLauncherHelper],
        disabledHelperIDs: Set<String> = []
    ) {
        let existingPolicy = gate.appPolicies.contains { $0.requirement == signing.requirement }
        guard !existingPolicy || !helpers.isEmpty || !disabledHelperIDs.isEmpty else {
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
            !existingPolicy && gate.defaultDenialThreshold != nil
                ? "This Launcher will use its own Denial Threshold instead of the Default Policy." : nil,
            helperDetail,
            helpers.compactMap(\.runtimeCompatibilityWarning).first,
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
            if !helpers.isEmpty || !disabledHelperIDs.isEmpty {
                do {
                    try updateVerifiedLauncherHelperConfiguration {
                        $0.enable(helpers)
                        $0.disabledHelperIDs.formUnion(disabledHelperIDs)
                    }
                } catch {
                    self.errorMessage = "Could not save helper associations: \(error.localizedDescription)"
                    return
                }
            }
            if !existingPolicy {
                let policyStatus = setSecretGateAppProtection(
                    requirement: signing.requirement,
                    protection: gate.initialProtection,
                    for: gate,
                    runtimeRequirement: runtimeRequirement,
                    approvedDefaultDenialThreshold: gate.defaultDenialThreshold
                )
                guard policyStatus == errSecSuccess else {
                    self.errorMessage = String(localized: "Could not allow \(signing.identifier): \(String(policyStatus))")
                    return
                }
            }
            self.errorMessage = nil
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
        // A denial-only row creates no allow override, even if its displayed gate default is broad.
        guard protection.addsAuthority(over: app.usesGateDefault ? .noAccess : app.protection) else { update(); return }
        approveAuthorityChange(
            action: "gate-policy:\(gate.id):\(app.requirement)",
            "Broaden \(app.bundleIdentifier) to \(protection.title)",
            detail: protection.subtitle,
            perform: update
        )
    }

    func setDenialThreshold(_ threshold: SecretGateProtection?, for app: SecretGatePolicy?, in gate: SecretGate) {
        let previous = app == nil ? gate.defaultDenialThreshold : app?.denialThreshold
        let needsApproval = gate.weakeningDenial(from: previous, to: threshold)
        let update = { [weak self] in
            guard let self else { return }
            self.finishSecretGatePolicyUpdate(
                setSecretGateDenialThreshold(threshold, requirement: app?.requirement, in: gate,
                                            runtimeRequirement: app?.runtimeRequirement ?? .hardened,
                                            approvedDenialThreshold: needsApproval ? previous : nil),
                gate: gate, error: "Could not update the Denial Threshold"
            )
        }
        guard needsApproval else { update(); return }
        approveAuthorityChange(
            action: app.map { "gate-denial:\(gate.id):\($0.requirement)" } ?? "gate-default-denial:\(gate.id)",
            "Reduce denial for \(app?.bundleIdentifier ?? gate.defaultPolicyLabel)",
            detail: "Existing allow rules may authorize requests again. The new Denial Threshold is \(threshold.map { gate.protectionTitle($0) + " and above" } ?? "None").",
            perform: update
        )
    }

    func setSigningAccess(_ access: SigningGateAccess, for app: SecretGatePolicy?, in gate: SecretGate) {
        let previous = app == nil ? gate.defaultDenialThreshold : app?.denialThreshold
        let needsApproval = access.requiresApproval(in: gate,
            protection: app?.protection ?? gate.defaultProtection, denial: previous,
            usesGateDefault: app?.usesGateDefault == true)
        let update = { [weak self] in
            self?.finishSecretGatePolicyUpdate(
                setSecretGateDenialThreshold(access.denial, requirement: app?.requirement, in: gate,
                    runtimeRequirement: app?.runtimeRequirement ?? .hardened,
                    approvedDenialThreshold: needsApproval ? previous : nil, signingAccess: access),
                gate: gate, error: "Could not update the Access Level"
            )
        }
        guard needsApproval else { update(); return }
        approveAuthorityChange(
            action: "gate-signing:\(gate.id):\(app?.requirement ?? "")",
            "Change \(app?.bundleIdentifier ?? gate.defaultPolicyLabel) to \(access.title(for: gate))",
            detail: access == .allow ? gate.protectionSubtitle(access.protection(for: gate))
                : "Remove this denial. Future requests under this rule require Approval.",
            perform: { update() }
        )
    }

    func removeAppPolicy(_ app: SecretGatePolicy, from gate: SecretGate) {
        let update = { [weak self] in
            self?.finishSecretGatePolicyUpdate(
                removeSecretGateAppPolicy(app, from: gate, approvedDenialThreshold: app.denialThreshold), gate: gate,
                error: "Could not delete the Launcher-specific rule for \(app.bundleIdentifier)"
            )
        }
        guard app.denialThreshold != nil || gate.defaultProtection.addsAuthority(over: app.protection)
        else { update(); return }
        approveAuthorityChange(
            action: "gate-policy:\(gate.id):\(app.requirement)",
            "Remove Launcher-specific policy for \(app.bundleIdentifier)",
            detail: "The gate's default Access Level and other existing authority will apply. Any Denial Threshold in this rule will be removed.",
            perform: { update() }
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
        // Several detectors can describe one Tool; built-in Tools have no hardening record.
        let findings = Dictionary(grouping: detectorItems.filter(\.isTriggered)) { item in
            hardenerNameReferencedByDocumentation(item.documentation) ?? item.title
        }
        var rows = snapshot.hardenedTools.map { tool in
            if let finding = findings[tool.name]?.first { return finding }
            return DashboardItem(id: tool.stubPath ?? tool.name, title: tool.name,
                                 subtitle: "Hardened", detail: "", isHardened: true)
        }
        let hardenedNames = Set(snapshot.hardenedTools.map(\.name))
        rows += findings.filter { !hardenedNames.contains($0.key) }.compactMap { $0.value.first }
        rows += items(for: .settings).filter(\.isBuiltInTool)
        for issue in snapshot.doctorIssues where issue.hardener != "Doctor" && !rows.contains(where: { overviewDoctorIssue(for: $0)?.hardener == issue.hardener }) {
            rows.append(DashboardItem(id: "doctor:" + issue.hardener, title: issue.hardener,
                                      subtitle: issue.message, detail: ""))
        }
        let now = Date()
        return rows
            .filter { searchQuery.isEmpty || $0.title.localizedCaseInsensitiveContains(searchQuery) }
            .sorted {
                let lhsAttention = $0.isTriggered || overviewDoctorIssue(for: $0) != nil
                let rhsAttention = $1.isTriggered || overviewDoctorIssue(for: $1) != nil
                if lhsAttention != rhsAttention { return lhsAttention }
                let lhsActive = overviewHasGate($0) && (overviewRequestCount(for: $0, now: now) ?? 0) > 0
                let rhsActive = overviewHasGate($1) && (overviewRequestCount(for: $1, now: now) ?? 0) > 0
                if lhsActive != rhsActive { return lhsActive }
                return $0.title.localizedStandardCompare($1.title) == .orderedAscending
            }
    }

    func overviewDoctorIssue(for tool: DashboardItem) -> DoctorIssue? {
        let hardener = tool.overviewToolName
        return snapshot.doctorIssues.first { $0.hardener == hardener || $0.command == tool.title }
    }

    func overviewHasGate(_ tool: DashboardItem) -> Bool {
        let name = tool.overviewToolName
        let gateID = snapshot.hardeners.first { $0.name == name }?.secretGate?.id ?? name
        return snapshot.secretGates.contains { $0.id == gateID }
    }

    var overviewFindings: [DashboardItem] { detectorItems.filter(\.isTriggered) }

    var overviewClearStatus: String? {
        switch (snapshot.flaggedDetectorCount == 0, snapshot.doctorIssues.isEmpty) {
        case (true, true): "No vulnerability or doctor reports"
        case (true, false): "No vulnerabilities detected"
        case (false, true): "No doctor reports"
        case (false, false): nil
        }
    }

    fileprivate var doctorSeverity: DetectorSeverityLevel {
        snapshot.doctorIssues.allSatisfy {
            ["aws_update_available", "isotope_update_required"].contains($0.kind)
        } ? .medium : .high
    }


    func overviewVerification(for tool: DashboardItem) -> String {
        guard tool.isHardened else {
            return snapshot.detectorFindings.first { $0.source == tool.id }?.explanation
                ?? tool.subtitle
        }
        guard let refreshed = lastHardeningRefresh else { return String(localized: "Hardening not yet refreshed") }
        let timestamp = shortDashboardTimestamp(refreshed)
        return tool.isHardened && overviewDoctorIssue(for: tool) == nil
            ? String(localized: "Hardening verified: \(timestamp)")
            : String(localized: "Hardening checked: \(timestamp)")
    }

    fileprivate func overviewActivitySlots(for tool: DashboardItem, now: Date, count: Int = 96) -> [Int]? {
        let name = tool.overviewToolName
        return overviewActivityIndex?.slots(for: name, now: now, count: count)
    }

    fileprivate func overviewLatestRecord(for tool: DashboardItem, now: Date,
                                          slot: Int, count: Int) -> AccessRequestRecord? {
        overviewActivityIndex?.latestRecord(for: tool.overviewToolName, now: now, slot: slot, count: count)
    }

    fileprivate func overviewLatestActivity(for tool: DashboardItem) -> Date? {
        let name = tool.overviewToolName
        return overviewActivityIndex?.latestActivity(for: name)
    }

    private func overviewRequestCount(for tool: DashboardItem, now: Date) -> Int? {
        let name = tool.overviewToolName
        return overviewActivityIndex?.count(for: name, now: now)
    }

    func openOverviewTool(_ tool: DashboardItem) {
        if let issue = overviewDoctorIssue(for: tool) {
            navigateFromOverview(to: .doctor, itemID: issue.id)
        } else if tool.isBuiltInTool {
            navigateFromOverview(to: .settings, itemID: tool.id)
        } else {
            navigateFromOverview(to: tool.isTriggered ? .detectors : .hardenedTools, itemID: tool.id)
        }
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
                let subtitle = affectedCount == 0 ? "detector tripped"
                    : affectedCount == 1 ? "1 trigger tripped" : "\(affectedCount) triggers tripped"
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
    let scripts = blessed.map(blessedScriptItem).sorted {
        if ($0.blessingStatus == "Changed") != ($1.blessingStatus == "Changed") {
            return $0.blessingStatus == "Changed"
        }
        return $0.title.localizedStandardCompare($1.title) == .orderedAscending
    }
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
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let focusModel = DashboardModel(snapshot: .empty)
    let focusWindow = NSWindow(contentViewController: NSHostingController(rootView: DashboardRootView(
        model: focusModel, checkForUpdates: {}, requestScan: {})))
    focusWindow.setContentSize(NSSize(width: 1100, height: 700))
    defer { focusWindow.orderOut(nil) }
    func tables(in view: NSView) -> [NSTableView] {
        let nested = view.subviews.flatMap(tables(in:))
        return (view as? NSTableView).map { [$0] + nested } ?? nested
    }
    var focusFailure: String?
    DispatchQueue.main.async {
        for section in [DashboardSection.settings, .overview, .settings] {
            focusModel.selectSection(section)
            let deadline = Date().addingTimeInterval(2)
            var focusTargetReady = false
            repeat {
                RunLoop.current.run(until: Date().addingTimeInterval(0.01))
                focusWindow.contentView?.layoutSubtreeIfNeeded()
                let expectsSourceList = section == .overview
                if let table = focusWindow.contentView.flatMap({ tables(in: $0).first {
                    $0.selectedRow >= 0 && ($0.style == .sourceList) == expectsSourceList
                } }) {
                    // Directly launched self-check binaries cannot become the active application on
                    // hosted runners. Assert the selected focus target there, and additionally assert
                    // the responder whenever AppKit gives the modal window keyboard focus.
                    focusTargetReady = !focusWindow.isKeyWindow || focusWindow.firstResponder === table
                }
            } while !focusTargetReady && Date() < deadline
            guard focusTargetReady else {
                focusFailure = "Dashboard selection did not prepare keyboard focus: \(section), active=\(app.isActive), key=\(focusWindow.isKeyWindow), responder=\(String(describing: focusWindow.firstResponder))"
                break
            }
        }
        app.abortModal()
    }
    app.runModal(for: focusWindow)
    if let focusFailure {
        print(focusFailure)
        return 1
    }
    for state in [CLIInstallState.outdated, .missing, .current] {
        let model = DashboardModel(snapshot: .empty, cliInstallState: state)
        let host = NSHostingController(rootView: DashboardRootView(
            model: model, checkForUpdates: {}, requestScan: {}))
        let window = NSWindow(contentViewController: host)
        window.setContentSize(NSSize(width: 1100, height: 700))
        for section in [DashboardSection.overview, .doctor, .overview] {
            model.selectedSection = section
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
            window.contentView?.layoutSubtreeIfNeeded()
            let hasCLIAction = window.toolbar?.items.contains {
                $0.itemIdentifier.rawValue.contains("cli-install")
            } == true
            guard hasCLIAction == (state.actionTitle != nil) else {
                print("CLI toolbar missing or unexpected: \(section), \(state)")
                return 1
            }
        }
    }
    let controller = AutomicVaultMainWindowController(checkForUpdates: {}, requestScan: {})
    let checked = Date(timeIntervalSince1970: 1_790_000_000)
    controller.setAvailableUpdateVersion("2.8.0", checkedAt: checked)
    guard controller.rootView.model.availableUpdateVersion == "2.8.0" else { return 1 }
    controller.setAvailableUpdateVersion(nil, checkedAt: checked)
    return controller.rootView.model.availableUpdateVersion == nil
        && controller.rootView.model.lastUpdateCheck == checked ? 0 : 1
}

@MainActor
func runDashboardSearchSelfCheck() -> Int32 {
    guard !DashboardModel().hasLoadedInitialSnapshot,
          DashboardModel(snapshot: .empty).hasLoadedInitialSnapshot else { return 1 }
    // History navigation must bind the exact Gate and current Launcher identity,
    // even when display names collide. This exercises no policy writes.
    let terminalURL = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
    guard let terminal = launcherSigning(terminalURL) else { return 1 }
    func historyLauncherRecord(requirement: String, path: String = terminalURL.path) -> AccessRequestRecord {
        AccessRequestRecord(date: .now, tool: "display-name-is-not-the-gate", command: "",
            decision: "Approved", reason: "", launcher: "Same name", launcherIconPath: path,
            launcherRequirement: requirement, gateID: "gh", callerPath: "", target: "", cwd: "", keys: [], detail: nil)
    }
    let launcherRecord = historyLauncherRecord(requirement: terminal.requirement)
    guard recentLauncherSigning(launcherRecord)?.requirement == terminal.requirement,
          recentLauncherSigning(historyLauncherRecord(requirement: "other signer")) == nil,
          recentLauncherSigning(historyLauncherRecord(requirement: terminal.requirement, path: "/missing-launcher.app")) == nil
    else { return 1 }
    var navigationSnapshot = DashboardSnapshot.empty
    let rules = [terminal.requirement, "other signer"].map {
        SecretGatePolicy(bundleIdentifier: "Same name", requirement: $0, protection: .noAccess)
    }
    navigationSnapshot.secretGates = ["aws", "gh"].map {
        SecretGate(id: $0, keyPatterns: [], routes: [], defaultProtection: .noAccess, appPolicies: rules)
    }
    let navigationModel = DashboardModel(snapshot: navigationSnapshot)
    navigationModel.searchText = "no match"
    navigationModel.configureLauncher(from: launcherRecord)
    guard navigationModel.selectedSection == .secretGates,
          navigationModel.selectedItemID == "gh",
          navigationModel.selectedLauncherRequirement == terminal.requirement,
          navigationModel.searchText.isEmpty,
          navigationModel.snapshot == navigationSnapshot
    else { return 1 }
    // A selected/new rule must leave every existing rule and Default Policy visible.
    var renderedRows: [String] = []
    let policyHost = NSHostingView(rootView: SecretGateDetailView(
        model: navigationModel, gate: navigationSnapshot.secretGates[1])
        .onPreferenceChange(GatePolicyRowPreference.self) { renderedRows = $0 })
    policyHost.frame = NSRect(x: 0, y: 0, width: 1000, height: 1000)
    let expectedRows = ["default"] + rules.map { $0.requirement }
    let deadline = Date().addingTimeInterval(2)
    repeat {
        policyHost.layoutSubtreeIfNeeded()
        if renderedRows.sorted() == expectedRows.sorted() { break }
        RunLoop.current.run(until: Date().addingTimeInterval(0.01))
    } while Date() < deadline
    guard renderedRows.sorted() == expectedRows.sorted() else {
        print("History-selected Launcher hid existing rules or Default Policy")
        return 1
    }
    navigationModel.showSecretGate(id: "aws")
    guard navigationModel.selectedLauncherRequirement == nil else { return 1 }
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
    // Unsorted input, duplicate timestamps, both inclusive boundaries, and clock reversal.
    let activityRecords = [86_401.0, 0, 86_400, -1, 0, 900, 901, 85_500].map { offset in
        AccessRequestRecord(date: accessRequest.date.addingTimeInterval(offset),
            tool: "aws", command: "fixture", decision: offset == 900 ? "Denied" : "Approved", reason: "Test",
            launcher: nil, callerPath: "/fixture/av", target: "/fixture/tool",
            cwd: "/fixture", keys: [], detail: nil)
    }
    let activityIndex = DashboardActivityIndex(activityRecords)
    for offset in [0.0, 86_400, 86_401, 172_802, -2, 0] {
        let now = accessRequest.date.addingTimeInterval(offset)
        let expected = activityRecords.filter {
            $0.date >= now.addingTimeInterval(-86_400) && $0.date <= now
        }.count
        for width: CGFloat in [0, 240, 287, 288, 575, 576, 1000, 1439, 1440, 2879, 2880, 4000] {
            let count = DashboardActivityIndex.slotCount(forWidth: width)
            let expectedCount = width >= 2880 ? 1440 : width >= 1440 ? 720
                : width >= 576 ? 288 : width >= 288 ? 144 : 96
            guard count == expectedCount else { return 1 }
            let slots = activityIndex.slots(for: "aws", now: now, count: count)
            guard slots.count == count, slots.reduce(0, +) == expected,
                  activityIndex.slots(for: "missing", now: now, count: count) == Array(repeating: 0, count: count)
            else { return 1 }
            for slot in slots.indices {
                let start = now.addingTimeInterval(-86_400 + Double(slot) * (86_400 / Double(count)))
                let end = start.addingTimeInterval(86_400 / Double(count))
                let expectedRecords = activityRecords.filter {
                    $0.date >= start && ($0.date < end || (slot == count - 1 && $0.date == end))
                }
                let latest = activityIndex.latestRecord(for: "aws", now: now, slot: slot, count: count)
                guard slots[slot] == expectedRecords.count,
                      latest?.date == expectedRecords.map(\.date).max(),
                      latest.map({ expectedRecords.contains($0) }) ?? expectedRecords.isEmpty,
                      activityIndex.latestRecord(for: "missing", now: now, slot: slot, count: count) == nil
                else { return 1 }
            }
        }
        guard activityIndex.count(for: "aws", now: now) == expected,
              activityIndex.count(for: "missing", now: now) == 0,
              DashboardActivityIndex([]).count(for: "aws", now: now) == 0 else { return 1 }
    }
    guard activityIndex.latestRecord(for: "aws", now: accessRequest.date, slot: -1, count: 96) == nil,
          activityIndex.latestRecord(for: "aws", now: accessRequest.date, slot: 96, count: 96) == nil,
          activityIndex.latestRecord(for: "aws", now: accessRequest.date, slot: 0, count: 0) == nil
    else { return 1 }
    // Built-in Tools must remain discoverable before credentials are configured.
    for (id, title) in [("gpg-signing", "GPG Signing"), ("ssh-agent", "SSH Agent")] {
        let unconfigured = DashboardModel(snapshot: .empty)
        guard let tool = unconfigured.overviewTools.first(where: { $0.id == id }),
              tool.title == title, !tool.isHardened, !unconfigured.overviewHasGate(tool)
        else {
            print("Overview is missing the built-in Tool: \(id)")
            return 1
        }
        unconfigured.openOverviewTool(tool)
        guard unconfigured.selectedSection == .settings, unconfigured.selectedItemID == id else { return 1 }
        unconfigured.searchText = title
        guard unconfigured.overviewTools.map(\.id) == [id] else { return 1 }
        var configured = DashboardSnapshot.empty
        configured.secretGates = [SecretGate(id: id, keyPatterns: [], routes: [],
            defaultProtection: .noAccess, appPolicies: [])]
        let now = Date()
        configured.accessRequests = [AccessRequestRecord(date: now, tool: id, command: "fixture",
            decision: "Approved", reason: "Test", launcher: nil, callerPath: "/fixture/av",
            target: "/fixture/av", cwd: "/tmp", keys: [], detail: nil)]
        let configuredModel = DashboardModel(snapshot: configured)
        guard configuredModel.overviewTools.filter({ $0.id == id }).count == 1,
              configuredModel.overviewHasGate(tool),
              configuredModel.overviewTools.first?.id == id,
              configuredModel.overviewActivitySlots(for: tool, now: now)?.reduce(0, +) == 1,
              configuredModel.overviewLatestActivity(for: tool) == now,
              configuredModel.overviewVerification(for: tool) == tool.subtitle
        else { return 1 }
    }
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
          model.overviewTools.map(\.title) == ["aws", "gh", "GPG Signing", "SSH Agent"] else { return 1 }
    var duplicateDetectorSnapshot = model.snapshot
    duplicateDetectorSnapshot.detectors.append(DetectorMetadata(
        name: "aws-extra", homepage: "", docsURL: "", documentation: "Run `av harden aws`."
    ))
    let groupedModel = DashboardModel(snapshot: duplicateDetectorSnapshot)
    guard groupedModel.overviewTools.map(\.title) == ["aws", "gh", "GPG Signing", "SSH Agent"],
          groupedModel.overviewTools.filter(\.isHardened).count == groupedModel.count(for: .hardenedTools)
    else { return 1 }
    guard let awsOverview = model.overviewTools.first(where: { $0.title == "aws" }),
          let ghOverview = model.overviewTools.first(where: { $0.title == "gh" }),
          model.overviewDoctorIssue(for: awsOverview)?.hardener == "aws",
          model.overviewDoctorIssue(for: ghOverview) == nil else { return 1 }
    model.openOverviewTool(awsOverview)
    guard model.selectedSection == .doctor,
          model.selectedItemID == model.snapshot.doctorIssues.first?.id else { return 1 }
    model.openOverviewTool(ghOverview)
    guard model.selectedSection == .hardenedTools,
          model.selectedItemID == ghOverview.id else { return 1 }
    var attentionSnapshot = model.snapshot
    attentionSnapshot.doctorIssues.append(DoctorIssue(hardener: "wrangler", kind: "test",
        command: "wrangler", message: "Wrangler needs attention", remediation: "Review configuration"))
    let attentionModel = DashboardModel(snapshot: attentionSnapshot)
    guard attentionModel.overviewTools.prefix(2).map(\.title) == ["aws", "wrangler"],
          model.overviewActivitySlots(for: awsOverview, now: accessRequest.date)?.reduce(0, +) == 1,
          model.overviewActivitySlots(for: awsOverview, now: accessRequest.date.addingTimeInterval(86_401))?.reduce(0, +) == 0
    else { return 1 }
    let singleRequestIndex = DashboardActivityIndex([accessRequest])
    guard singleRequestIndex.latestActivity(for: accessRequest.tool) == accessRequest.date,
          DashboardActivityIndex([]).latestActivity(for: accessRequest.tool) == .distantPast,
          activityIndex.latestActivity(for: "unused-tool") == .distantPast,
          model.overviewLatestActivity(for: awsOverview) == accessRequest.date
    else { return 1 }
    var findingSnapshot = attentionSnapshot
    findingSnapshot.detectorFindings = try! JSONDecoder().decode([DetectorFinding].self,
        from: Data(#"[{"source":"git","severity":"high","explanation":"Git credentials are exposed."}]"#.utf8))
    let findingModel = DashboardModel(snapshot: findingSnapshot)
    guard findingModel.overviewTools.prefix(3).map(\.title) == ["aws", "git", "wrangler"] else { return 1 }
    guard let gitFinding = findingModel.overviewTools.first(where: { $0.title == "git" }),
          gitFinding.subtitle == "detector tripped",
          findingModel.overviewFindings.first(where: { $0.id == gitFinding.id })?.subtitle == "detector tripped",
          findingModel.overviewVerification(for: gitFinding) == "Git credentials are exposed.",
          detectorSeverityColor(gitFinding.severity) == .red,
          detectorSeverityColor("medium") == .orange,
          findingModel.overviewVerification(for: DashboardItem(id: "no-explanation", title: "SIP",
              subtitle: "SIP is disabled", detail: "", isTriggered: true)) == "SIP is disabled"
    else {
        print("Overview must show detection text for an unhardened tool")
        return 1
    }
    guard !model.overviewHasGate(awsOverview),
          model.overviewVerification(for: awsOverview) == "Hardening not yet refreshed" else { return 1 }
    var statusSnapshot = model.snapshot
    guard model.overviewClearStatus == "No vulnerabilities detected" else { return 1 }
    statusSnapshot.doctorIssues = []
    guard DashboardModel(snapshot: statusSnapshot).overviewClearStatus == "No vulnerability or doctor reports" else { return 1 }
    statusSnapshot.detectorFindings = findingSnapshot.detectorFindings
    guard DashboardModel(snapshot: statusSnapshot).overviewClearStatus == "No doctor reports",
          findingModel.overviewClearStatus == nil else { return 1 }
    statusSnapshot.doctorIssues = ["aws_update_available", "isotope_update_required"].map {
        DoctorIssue(hardener: "test", kind: $0, message: "Update available", remediation: "Update")
    }
    guard DashboardModel(snapshot: statusSnapshot).doctorSeverity == .medium else { return 1 }
    statusSnapshot.doctorIssues += model.snapshot.doctorIssues
    guard DashboardModel(snapshot: statusSnapshot).doctorSeverity == .high else { return 1 }
    var gatedSnapshot = model.snapshot
    gatedSnapshot.secretGates.append(SecretGate(id: "aws", keyPatterns: [], routes: [],
        defaultProtection: .noAccess, appPolicies: []))
    let gatedModel = DashboardModel(snapshot: gatedSnapshot)
    guard gatedModel.overviewHasGate(awsOverview), !gatedModel.overviewHasGate(ghOverview) else { return 1 }
    var activitySnapshot = attentionSnapshot
    activitySnapshot.doctorIssues.removeAll { $0.hardener == "aws" }
    activitySnapshot.accessRequests = [AccessRequestRecord(date: Date(), tool: "gh", command: "gh api user",
        decision: "Approved", reason: "Test", launcher: nil, callerPath: "/usr/bin/gh",
        target: "/usr/bin/gh", cwd: "/tmp", keys: [], detail: nil)]
    // History alone must not imply a Gate; attention always precedes activity.
    guard DashboardModel(snapshot: activitySnapshot).overviewTools.map(\.title) == ["wrangler", "aws", "gh", "GPG Signing", "SSH Agent"] else { return 1 }
    activitySnapshot.secretGates.append(SecretGate(id: "gh", keyPatterns: [], routes: [],
        defaultProtection: .noAccess, appPolicies: []))
    guard DashboardModel(snapshot: activitySnapshot).overviewTools.map(\.title) == ["wrangler", "gh", "aws", "GPG Signing", "SSH Agent"] else { return 1 }
    if ProcessInfo.processInfo.environment["AV_BENCHMARK_DASHBOARD"] == "1" {
        var benchmarkSnapshot = activitySnapshot
        benchmarkSnapshot.hardenedTools = (0..<12).map {
            HardenedTool(name: "tool-\($0)", targetPath: "/fixture/tool-\($0)")
        }
        benchmarkSnapshot.secretGates = (0..<12).map {
            SecretGate(id: "tool-\($0)", keyPatterns: [], routes: [],
                       defaultProtection: .noAccess, appPolicies: [])
        }
        benchmarkSnapshot.accessRequests = (0..<50_000).map {
            AccessRequestRecord(date: Date().addingTimeInterval(-Double($0)),
                tool: "tool-\($0 % 12)", command: "fixture", decision: "Approved",
                reason: "Test", launcher: nil, callerPath: "/fixture/av",
                target: "/fixture/tool", cwd: "/fixture", keys: [], detail: nil)
        }
        let benchmark = DashboardModel(snapshot: benchmarkSnapshot)
        let start = ContinuousClock.now
        for _ in 0..<5 {
            benchmark.selectSection(.settings)
            benchmark.selectSection(.overview)
            let tools = benchmark.overviewTools
            for tool in tools {
                _ = benchmark.overviewActivitySlots(for: tool, now: Date())
            }
        }
        let elapsed = start.duration(to: .now)
        print("Dashboard: five Overview selections, 50k records: \(elapsed)")
        guard elapsed < .milliseconds(300) else { return 1 }
    }
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
        guard NSImage(named: "LoadingShield") != nil else { return 1 }
        for scheme in [ColorScheme.light, .dark] {
            let renderer = ImageRenderer(content: InitialLoadingView()
                .environment(\.colorScheme, scheme)
                .frame(width: 420, height: 300)
                .background(scheme == .dark ? Color(white: 0.13) : Color(white: 0.93)))
            renderer.scale = 2
            guard let data = renderer.nsImage?.tiffRepresentation,
                  let png = NSBitmapImageRep(data: data)?.representation(using: .png, properties: [:]) else { return 1 }
            do {
                try png.write(to: URL(fileURLWithPath: directory)
                    .appendingPathComponent("loading-\(scheme == .dark ? "dark" : "light").png"))
            } catch { return 1 }
        }
        for scheme in [ColorScheme.light, .dark] {
            let previewRecord = AccessRequestRecord(date: accessRequest.date, tool: "aws",
                command: "never display this raw command", displayCommand: "aws s3 ls s3://release-artifacts",
                decision: "Approved", reason: "Read Only", launcher: "Codex", callerPath: "/fixture/av",
                target: "/fixture/aws", cwd: "/fixture", keys: [], detail: nil)
            let renderer = ImageRenderer(content: ToolActivityPopover(record: previewRecord,
                interval: "10:00–10:15: 4 recorded requests")
                .background(Color(nsColor: .windowBackgroundColor))
                .environment(\.colorScheme, scheme))
            renderer.scale = 2
            guard let data = renderer.nsImage?.tiffRepresentation,
                  let png = NSBitmapImageRep(data: data)?.representation(using: .png, properties: [:]) else { return 1 }
            do {
                try png.write(to: URL(fileURLWithPath: directory)
                    .appendingPathComponent("activity-popover-\(scheme == .dark ? "dark" : "light").png"))
            } catch { return 1 }
        }
        var renderSnapshot = findingSnapshot
        renderSnapshot.secretGates.append(SecretGate(id: "aws", keyPatterns: [], routes: [],
            defaultProtection: .noAccess, appPolicies: []))
        renderSnapshot.hardenedTools += (1...12).map {
            HardenedTool(name: "tool-\($0)", targetPath: "/usr/local/bin/tool-\($0)")
        }
        renderSnapshot.accessRequests = (0..<384).map { index in
            AccessRequestRecord(date: Date().addingTimeInterval(-Double((index * index) % 86_400)),
                tool: index.isMultiple(of: 3) ? "gh" : "aws", command: "fixture",
                decision: index.isMultiple(of: 5) ? "Denied" : "Approved", reason: "Test",
                launcher: nil, callerPath: "/fixture/av", target: "/fixture/tool",
                cwd: "/fixture", keys: [], detail: nil)
        }
        let renderModel = DashboardModel(snapshot: renderSnapshot)
        for size in [NSSize(width: 590, height: 480), NSSize(width: 590, height: 550), NSSize(width: 980, height: 680)] {
            let headlines = try! BlogFeed.posts(from: Data(#"{"items":[{"title":"Automic Vault vs AWS Secrets Manager","url":"https://www.automicvault.com/blog/automic-vault-vs-aws-secrets-manager/"},{"title":"Automic Vault vs HashiCorp Vault","url":"https://www.automicvault.com/blog/automic-vault-vs-hashicorp-vault/"}]}"#.utf8))
            let host = NSHostingView(rootView: DashboardOverviewView(model: renderModel, checkForUpdates: {}, news: headlines))
            host.frame = NSRect(origin: .zero, size: size)
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
            host.layoutSubtreeIfNeeded()
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return 1 }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { return 1 }
            do {
                try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("overview-\(Int(size.width))-\(Int(size.height)).png"))
            } catch { return 1 }
        }
    }
    if let directory = ProcessInfo.processInfo.environment["AV_SSH_RENDER_DIR"] {
        let github = SSHAgentCredential(name: "GitHub", publicKey: "ssh-ed25519 " + Data(repeating: 1, count: 51).base64EncodedString())
        let homelab = SSHAgentCredential(name: "Homelab", publicKey: "ssh-ed25519 " + Data(repeating: 2, count: 51).base64EncodedString())
        let configuration = SSHAgentConfiguration(enabled: true, credentials: [github, homelab])
        var fixture = DashboardSnapshot.empty
        fixture.secretGates = [github, homelab].map { key in
            SecretGate(id: key.gateID, keyPatterns: [key.secretName], routes: [], defaultProtection: .noAccess,
                appPolicies: key.id == github.id ? [SecretGatePolicy(bundleIdentifier: "com.anthropic.claudefordesktop",
                    requirement: "identifier com.anthropic.claudefordesktop", protection: .fullExceptSecretDumps)] : [])
        }
        let fixtureModel = DashboardModel(snapshot: fixture)
        for dark in [false, true] {
            for width in [590, 980] {
                let host = NSHostingView(rootView: ScrollView {
                    SSHAgentSettingsView(model: fixtureModel, configuration: configuration).padding(24)
                }.frame(width: CGFloat(width), height: 900)
                    .background(Color(nsColor: .windowBackgroundColor))
                    .environment(\.colorScheme, dark ? .dark : .light))
                host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
                host.frame = NSRect(x: 0, y: 0, width: width, height: 900)
                host.layoutSubtreeIfNeeded()
                RunLoop.current.run(until: Date().addingTimeInterval(0.1))
                host.layoutSubtreeIfNeeded()
                guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return 1 }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { return 1 }
                do { try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("ssh-\(dark ? "dark" : "light")-\(width).png")) }
                catch { return 1 }
            }
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
    if let directory = ProcessInfo.processInfo.environment["AV_GATE_RENDER_DIR"] {
        let previewGate = SecretGate(id: "aws", keyPatterns: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            routes: [], defaultProtection: .noAccess, defaultDenialThreshold: .fullIncludingSecretDumps, appPolicies: [
                SecretGatePolicy(bundleIdentifier: "codex", requirement: "identifier codex", protection: .readOnly,
                                 denialThreshold: .fullIncludingSecretDumps),
                SecretGatePolicy(bundleIdentifier: "com.openai.codex", requirement: "identifier com.openai.codex",
                                 protection: .fullExceptSecretDumps, denialThreshold: .unknownOnly),
                SecretGatePolicy(bundleIdentifier: "herdr", requirement: "identifier herdr", protection: .readOnly),
            ])
        for dark in [false, true] {
            for width in [560, 1000] {
                let host = NSHostingView(rootView: SecretGateDetailView(model: model, gate: previewGate)
                    .padding(24).frame(width: CGFloat(width), height: 820, alignment: .topLeading)
                    .background(Color(nsColor: .windowBackgroundColor))
                    .environment(\.colorScheme, dark ? .dark : .light))
                host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
                host.frame = NSRect(x: 0, y: 0, width: width, height: 820)
                host.layoutSubtreeIfNeeded()
                RunLoop.current.run(until: Date().addingTimeInterval(0.1))
                host.layoutSubtreeIfNeeded()
                guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return 1 }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { return 1 }
                do {
                    try png.write(to: URL(fileURLWithPath: directory)
                        .appendingPathComponent("gate-\(dark ? "dark" : "light")-\(width).png"))
                } catch { return 1 }
            }
        }
    }
    // Both native pickers must preserve the distinction between None and deny-all.
    func policyPopup(in view: NSView) -> NSPopUpButton? {
        (view as? NSPopUpButton) ?? view.subviews.lazy.compactMap { policyPopup(in: $0) }.first
    }
    for (isDenial, usesPhone) in [(false, false), (false, true), (true, false)] {
        var selections: [SecretGateProtection?] = []
        let host = NSHostingView(rootView: NativeProtectionMenu(gate: gate,
            protection: isDenial ? nil : .readOnly, usesPhone: usesPhone, isDenial: isDenial) {
                selections.append($0)
            })
        host.frame = NSRect(x: 0, y: 0, width: 170, height: 30)
        host.layoutSubtreeIfNeeded()
        guard let popup = policyPopup(in: host), !popup.isBordered,
              popup.numberOfItems == (isDenial ? gate.availableDenialThresholds.count + 1 : gate.availableProtections.count),
              popup.indexOfSelectedItem == (isDenial ? 0 : 1), let action = popup.action,
              popup.itemArray.allSatisfy({ $0.image == nil }) else { print("Protection menu self-check failed at line \(#line)"); return 1 }
        if !isDenial {
            for (index, candidate) in gate.availableProtections.enumerated() {
                let warningCount = candidate == .fullExceptSecretDumps || candidate == .fullIncludingSecretDumps ? 1 : 0
                let phoneCount = usesPhone && candidate.addsAuthority(over: .readOnly) ? 1 : 0
                guard let title = popup.item(at: index)?.attributedTitle,
                      title.string.hasPrefix(localizedUIString(gate.protectionTitle(candidate))),
                      title.string.filter({ $0 == "\u{fffc}" }).count == warningCount + phoneCount else { print("Protection menu self-check failed at line \(#line)"); return 1 }
            }
        }
        popup.selectItem(at: isDenial ? 1 : 0)
        NSApp.sendAction(action, to: popup.target, from: popup)
        guard selections == [.noAccess] else { print("Protection menu self-check failed at line \(#line)"); return 1 }
        if isDenial {
            popup.selectItem(at: 0)
            NSApp.sendAction(action, to: popup.target, from: popup)
            guard selections == [.noAccess, nil] else { print("Protection menu self-check failed at line \(#line)"); return 1 }
            popup.selectItem(at: popup.numberOfItems - 1)
            NSApp.sendAction(action, to: popup.target, from: popup)
            guard selections.last == .some(.unknownOnly) else { print("Protection menu self-check failed at line \(#line)"); return 1 }
        }
    }
    for id in ["ssh-agent", "gpg-signing"] {
        let signingGate = SecretGate(id: id, keyPatterns: ["SECRET"], routes: [],
                                     defaultProtection: .noAccess, appPolicies: [])
        var selections: [SecretGateProtection?] = []
        let host = NSHostingView(rootView: NativeProtectionMenu(gate: signingGate,
            protection: nil, usesPhone: false, includesDeny: true) { selections.append($0) })
        host.frame = NSRect(x: 0, y: 0, width: 240, height: 30)
        host.layoutSubtreeIfNeeded()
        guard let popup = policyPopup(in: host), popup.numberOfItems == 3,
              Array(popup.itemTitles.prefix(2)) == [String(localized: "Deny"), String(localized: "Approval Required")],
              popup.itemTitles[2].hasPrefix(localizedUIString(signingGate.protectionTitle(signingGate.availableProtections[1]))),
              popup.indexOfSelectedItem == 0, let action = popup.action,
              popup.itemArray.allSatisfy({ $0.image == nil }) else { print("Protection menu self-check failed at line \(#line)"); return 1 }
        let allowTitle = popup.item(at: 2)?.attributedTitle?.string ?? ""
        guard allowTitle.filter({ $0 == "\u{fffc}" }).count == (id == "ssh-agent" ? 1 : 0) else { print("Protection menu self-check failed at line \(#line)"); return 1 }
        if #available(macOS 14.4, *) {
            guard popup.item(at: 0)?.subtitle == String(localized: "Requests are denied without asking for Approval.") else { print("Protection menu self-check failed at line \(#line)"); return 1 }
        }
        for index in 0..<3 {
            popup.selectItem(at: index)
            NSApp.sendAction(action, to: popup.target, from: popup)
        }
        guard selections == [nil, .noAccess, signingGate.availableProtections[1]] else { print("Protection menu self-check failed at line \(#line)"); return 1 }
    }
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
        rootView: VerifiedLauncherHelpersSettingsView(model: model)
    ).fittingSize.height
    model.reviewLauncher(LauncherSigning(
        identifier: "com.example.app", teamIdentifier: "EXAMPLETEAM",
        path: "/missing-launcher.app", requirement: "example-review",
        runtimeProtection: .hardened
    ), for: gate)
    guard model.isDiscoveringLauncherHelpers,
          model.pendingLauncherHelperReview?.signing.requirement == "example-review",
          model.pendingLauncherHelperReview?.helpers.isEmpty == true else { return 1 }
    model.confirmLauncherHelperReview(selectedHelperIDs: [])
    guard model.pendingLauncherHelperReview != nil else { return 1 }
    model.cancelLauncherHelperReview()
    guard !model.isDiscoveringLauncherHelpers,
          model.pendingLauncherHelperReview == nil else { return 1 }
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
    changedModel.selectedItemID = "unrelated-script"
    changedModel.showScriptsNeedingReblessing()
    guard changedModel.searchText.isEmpty,
          changedModel.selectedSection == .blessedScripts,
          changedModel.selectedItemID == changedScript.path else { return 1 }
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
          launcherHelperReviewSize == CGSize(width: 680, height: 720),
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

    var isBuiltInTool: Bool { id == "gpg-signing" || id == "ssh-agent" }

    var overviewToolName: String {
        isBuiltInTool ? id : hardenerNameReferencedByDocumentation(documentation) ?? title
    }

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

private struct AddLauncherButton: View {
    let recentApps: [AccessRequestRecord]
    let existingRequirements: Set<String>
    @ObservedObject var approval: AuthorityApprovalState
    let action: String
    let perform: (AccessRequestRecord?) -> Void

    var body: some View {
        let apps = recentApprovedLauncherApps(in: recentApps, excluding: existingRequirements)
            .filter { $0.launcherIconPath.map { FileManager.default.fileExists(atPath: $0) } == true }
        HStack(spacing: 0) {
            AuthorityApprovalButton(title: "Add Verified Launcher", approval: approval, action: action) {
                perform(nil)
            }
            if !apps.isEmpty {
                Menu {
                    ForEach(apps) { app in
                        Button {
                            guard !approval.isPending(action) else { return }
                            perform(app)
                        } label: {
                            let url = URL(fileURLWithPath: app.launcherIconPath!)
                            let bundle = Bundle(url: url)
                            Text(bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                                ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
                                ?? app.launcher ?? url.deletingPathExtension().lastPathComponent)
                        }
                    }
                } label: {
                    Image(systemName: "chevron.down")
                }
                .menuIndicator(.hidden)
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Recently Approved Apps")
                .accessibilityLabel("Recently Approved Apps")
                .disabled(approval.isPending(action))
            }
        }
    }
}

struct DashboardRootView: View {
    @ObservedObject var model: DashboardModel
    @ObservedObject private var proxySessions = ProxySessionViewModel.shared
    @State private var secretToDelete: StoredSecret?
    let checkForUpdates: () -> Void
    let requestScan: () -> Void

    @ToolbarContentBuilder
    private var cliInstallToolbar: some ToolbarContent {
        if let cliActionTitle = model.cliInstallState?.actionTitle {
            ToolbarItem(id: "cli-install", placement: .primaryAction) {
                Button {
                    model.installCLI()
                } label: {
                    Label(cliActionTitle, systemImage: "terminal")
                }
                .labelStyle(.titleAndIcon)
                .help("\(cliActionTitle) at /usr/local/bin/av")
            }
        }
    }

    @ViewBuilder
    private var sectionToolbarButtons: some View {
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
                AddLauncherButton(
                    recentApps: model.recentAccessRequests,
                    existingRequirements: Set(gate.appPolicies.map(\.requirement)),
                    approval: model.authorityApproval, action: "gate-launcher:\(gate.id)"
                ) { model.addApp(to: gate, recentApp: $0) }
                .labelStyle(.titleAndIcon)
                .help("Add Verified Launcher")
            }
        }
        if model.selectedSection == .blessedScripts {
            if let script = model.selectedBlessedScript {
                AddLauncherButton(
                    recentApps: model.recentAccessRequests,
                    existingRequirements: Set(script.launchers.map(\.requirement)),
                    approval: model.authorityApproval, action: "script-launcher:\(script.path)"
                ) { model.addApp(to: script, recentApp: $0) }
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
        if model.selectedSection == .allSecrets, let secret = model.selectedStoredSecret {
            Button { model.isRenamingSecret = true } label: {
                Label("Rename", systemImage: "pencil")
            }
            .labelStyle(.titleAndIcon)
            .help("Rename")
            Button(role: .destructive) { secretToDelete = secret } label: {
                Label("Delete Secret", systemImage: "trash")
            }
            .labelStyle(.iconOnly)
            .help("Delete Secret")
        }
    }

    var body: some View {
        Group {
            if model.selectedSection == .overview {
                NavigationSplitView {
                    DashboardSidebarView(model: model)
                        .navigationSplitViewColumnWidth(min: 186, ideal: 227, max: 250)
                } detail: {
                    DashboardOverviewView(model: model, checkForUpdates: checkForUpdates)
                        .toolbar { cliInstallToolbar }
                        .toolbar {
                            ToolbarItem(placement: .primaryAction) {
                                Button {
                                    requestScan()
                                    model.reload()
                                } label: {
                                    Label("Refresh", systemImage: "arrow.clockwise")
                                }
                                .disabled(model.isReloading)
                            }
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
                .toolbar { cliInstallToolbar }
                .navigationSplitViewColumnWidth(min: 320, ideal: 320)
                .toolbar {
                    ToolbarItemGroup(placement: .primaryAction) {
                        Spacer()
                        if let version = model.availableUpdateVersion {
                            Button(action: checkForUpdates) {
                                Label("Update to v\(version)…", systemImage: "arrow.down.circle")
                            }
                            .buttonStyle(.borderedProminent)
                            .labelStyle(.titleAndIcon)
                            .help("Install Automic Vault v\(version)")
                        }
                    }
                    if #available(macOS 26, *) {
                        ToolbarSpacer(.fixed, placement: .primaryAction)
                    }
                    ToolbarItemGroup(placement: .primaryAction) {
                        sectionToolbarButtons
                    }
                    if #available(macOS 26, *) {
                        ToolbarSpacer(.fixed, placement: .primaryAction)
                    }
                    ToolbarItem(placement: .primaryAction) {
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
        }
        .navigationTitle(model.selectedSection == .overview ? "Automic Vault" : model.selectedSection.title)
        .searchable(text: $model.searchText, placement: .sidebar, prompt: "Search")
        .onReceive(NotificationCenter.default.publisher(for: launcherDenialDidChange).receive(on: RunLoop.main)) { _ in
            model.reloadAuthorizationState()
        }
        .onChange(of: proxySessions.historyRevision) { _, _ in
            model.reloadAccessRequests()
        }
        .alert("Delete \(secretToDelete?.account ?? "")?", isPresented: Binding(
            get: { secretToDelete != nil },
            set: { if !$0 { secretToDelete = nil } }
        ), presenting: secretToDelete) { secret in
            Button("Cancel", role: .cancel) { secretToDelete = nil }
            Button("Delete", role: .destructive) {
                model.deleteSecret(account: secret.account)
                secretToDelete = nil
            }
        } message: { _ in
            Text("This secret will be permanently deleted.")
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
    @FocusState private var isFocused: Bool

    var body: some View {
        List(selection: sectionSelection) {
            sidebarRow(.overview).tag(DashboardSection.overview)
            Section("Tools") {
                ForEach([DashboardSection.detectors, .hardenedTools, .doctor]) { section in
                    sidebarRow(section).tag(section)
                }
            }
            Section("Access") {
                ForEach([DashboardSection.secretGates, .blessedScripts, .launcherBundles, .allSecrets, .proxySessions]) { section in
                    sidebarRow(section).tag(section)
                }
            }
            Section("Activity & Settings") {
                ForEach([DashboardSection.secretUsage, .settings]) { section in
                    sidebarRow(section).tag(section)
                }
            }
        }
        .listStyle(.sidebar)
        .focused($isFocused)
        .onAppear {
            if model.selectedSection == .overview { isFocused = true }
        }
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
                    DetectorCountPill(count: count, color: model.doctorSeverity.color)
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
    @FocusState private var isFocused: Bool

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
        .onChange(of: model.selectedSection, initial: true) { _, _ in
            isFocused = true
        }
    }

    private var itemSelection: Binding<String?> {
        Binding {
            model.selectedItemID
        } set: { id in
            if id != model.selectedItemID { model.selectedLauncherRequirement = nil }
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
        .focused($isFocused)
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
                            .contextMenu {
                                if let record = model.historyRecord(id: item.id), record.canConfigureLauncher {
                                    Button("Configure Launcher…") { model.configureLauncher(from: record) }
                                }
                            }
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
                AuthorizationHistoryDetailView(model: model, record: record)
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
                    VerifiedLauncherHelpersSettingsView(model: model)
                        .padding(.horizontal, 22)
                        .padding(.top, 32)
                        .padding(.bottom, 28)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.selectedItem?.id == "ssh-agent" {
                    SSHAgentSettingsView(model: model)
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

            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
        .onChange(of: secret.accessibility) { _, accessibility in
            isAvailableWhileLocked = accessibility.isAvailableWhileLocked
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

fileprivate enum DetectorSeverityLevel {
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
    @ObservedObject var model: DashboardModel
    let record: AccessRequestRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("\(record.launcher ?? "Launcher unavailable") used \(record.tool)")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)
            AccessRequestRow(record: record, configureLauncher: record.canConfigureLauncher
                ? { model.configureLauncher(from: record) } : nil)
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

private struct TemporaryLauncherDenialButton: View {
    let requirement: String
    let launcherName: String?
    let scope: TemporaryLauncherDenialScope
    @State private var deadline: TimeInterval?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button(deadline != nil ? "Denial Active" : "Deny For 2 Minutes") {
                TemporaryLauncherDenials.shared.deny(requirement, launcherName: launcherName ?? "Verified Launcher", scope: scope)
                refresh()
            }
            .disabled(deadline != nil)
            Text("Denies \(scope.operationTitle == "all requests" ? "all use" : scope.operationTitle) of \(Text(scope.gateName).monospaced()) by \(launcherName ?? "this Verified Launcher"). Ordinary policy resumes after two minutes; end early from the menu bar.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .onAppear { refresh() }
        .onReceive(NotificationCenter.default.publisher(for: launcherDenialDidChange).receive(on: RunLoop.main)) { _ in
            refresh()
        }
        .task(id: deadline) {
            guard let deadline else { return }
            do {
                try await Task.sleep(for: .seconds(max(0, deadline - TemporaryLauncherDenials.now)))
            } catch { return }
            refresh()
        }
    }

    private func refresh() {
        deadline = TemporaryLauncherDenials.shared.deadline(for: requirement, scope: scope)
    }
}

private struct AccessRequestRow: View {
    let record: AccessRequestRecord
    var configureLauncher: (() -> Void)? = nil

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
                Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 8) {
                    if let accessLevel = record.accessLevelForDisplay {
                        AccessMetaLine("Access Level", accessLevel)
                    } else {
                        AccessMetaLine("Reason", record.reason)
                    }
                    GridRow(alignment: .firstTextBaseline) {
                        Text("Launcher")
                            .foregroundStyle(.secondary)
                        HStack(spacing: 8) {
                            if let path = record.launcherIconPath {
                                Image(nsImage: NSWorkspace.shared.icon(forFile: path))
                                    .resizable().frame(width: 20, height: 20)
                                    .accessibilityHidden(true)
                            }
                            Text(record.launcher ?? "unknown")
                            if let configureLauncher {
                                Button("Configure Launcher…", action: configureLauncher)
                                    .controlSize(.small)
                            }
                        }
                    }
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
                .font(.system(size: 11))
                .textSelection(.enabled)
                .padding(.top, 12)
                if let requirement = record.launcherRequirement, !requirement.isEmpty, let scope = record.temporaryDenialScope {
                    Divider()
                        .padding(.vertical, 5)
                    TemporaryLauncherDenialButton(requirement: requirement, launcherName: record.launcher, scope: scope)
                        .id(requirement)
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
        GridRow(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .fixedSize()
            Text(value)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

@MainActor
func presentBlessingReview(
    _ request: BlessedScriptReviewRequest,
    on parent: NSPanel,
    cancellation: ApprovalCancellation,
    completion: @escaping @MainActor () -> Void
) {
    guard !cancellation.isCanceled else { completion(); return }
    let model = DashboardModel()
    let sheet = NSPanel(
        contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: false
    )
    sheet.isReleasedWhenClosed = false
    let cancellationID = UUID()
    let abortObserver = NotificationCenter.default.addObserver(
        forName: approvalPresentationDidAbort, object: nil, queue: .main
    ) { _ in
        MainActor.assumeIsolated { model.cancelPendingBlessing() }
    }
    var completed = false
    let finish: @MainActor () -> Void = {
        guard !completed else { return }
        completed = true
        cancellation.stopObserving(id: cancellationID)
        NotificationCenter.default.removeObserver(abortObserver)
        sheet.orderOut(nil)
        sheet.contentView = nil
        completion()
    }
    model.reviewBlessing(request) { _ in
        if sheet.sheetParent != nil {
            parent.endSheet(sheet)
        } else {
            finish()
        }
    }
    guard let pending = model.pendingBlessing else { return }
    let view = NSHostingView(rootView: BlessedScriptReviewView(model: model, request: pending))
    sheet.contentView = view
    sheet.setContentSize(view.fittingSize)
    guard cancellation.observe(id: cancellationID, { model.cancelPendingBlessing() }) else {
        model.cancelPendingBlessing()
        return
    }
    parent.beginSheet(sheet) { _ in
        model.cancelPendingBlessing()
        finish()
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

private struct LauncherHelperOutlineView<Row: View>: View {
    let helpers: [VerifiedLauncherHelper]
    @ViewBuilder let row: (VerifiedLauncherHelper) -> Row

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(verifiedLauncherHelperOutline(helpers)) { item in
                Group {
                    if let helper = item.helper {
                        row(helper)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        Label(item.title, systemImage: "shippingbox")
                            .font(.title3.weight(.semibold))
                            .padding(.top, 16)
                            .padding(.bottom, 6)
                    }
                }
                .padding(.leading, CGFloat(item.depth) * 18)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct LauncherHelperReviewView: View {
    @ObservedObject var model: DashboardModel
    private let initialReview: LauncherHelperReview
    private var review: LauncherHelperReview { model.pendingLauncherHelperReview ?? initialReview }
    private let configuration = loadVerifiedLauncherHelperConfiguration()
    @ObservedObject private var approval: AuthorityApprovalState

    init(model: DashboardModel, review: LauncherHelperReview) {
        self.model = model
        initialReview = review
        approval = model.authorityApproval
        let configuration = loadVerifiedLauncherHelperConfiguration()
        _selectedHelperIDs = State(initialValue: Set(review.helpers.filter {
            configuration.shouldSelectInReview($0)
        }.map(\.id)))
    }
    @State private var selectedHelperIDs: Set<String> = []

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        ViewThatFits(in: .horizontal) {
                            HStack(alignment: .top, spacing: 24) {
                                SecretGateField("Identifier", review.signing.identifier, monospaced: true)
                                SecretGateField("Team ID", review.signing.teamIdentifier, monospaced: true)
                                SecretGateField("Path", review.signing.path, monospaced: true)
                            }
                            .fixedSize(horizontal: true, vertical: false)
                            VStack(alignment: .leading, spacing: 12) {
                                SecretGateField("Identifier", review.signing.identifier, monospaced: true)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                HStack(alignment: .top, spacing: 24) {
                                    SecretGateField("Team ID", review.signing.teamIdentifier, monospaced: true)
                                        .fixedSize(horizontal: true, vertical: false)
                                    SecretGateField("Path", review.signing.path, monospaced: true)
                                        .fixedSize(horizontal: false, vertical: true)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                        }
                        if let warning = launcherRuntimeWarning(review.signing.runtimeProtection) {
                            InfoBlock(title: "Runtime warning", text: warning)
                        }
                        Text("Helpers").font(.title2.weight(.semibold))
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
                        if model.isDiscoveringLauncherHelpers {
                            ProgressView("Inspecting app for signed helpers…")
                                .accessibilityIdentifier("launcher-review-discovery-progress")
                        } else if review.helpers.isEmpty {
                            Text("No eligible signed helpers were found.")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            LauncherHelperOutlineView(helpers: review.helpers, row: helperRow)
                            .padding(12)
                            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                            .overlay {
                                RoundedRectangle(cornerRadius: 8).stroke(Color(nsColor: .separatorColor))
                            }
                        }
                        Text("To change helper associations later, open Settings → Verified Launcher Helpers. Use Refresh Helper List for the app to find new helpers, then enable, disable, or remove associations.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        SecretGateField("Designated requirement", review.signing.requirement, monospaced: true)
                    }
                    .padding(.horizontal, 22)
                    .padding(.top, 10)
                    .padding(.bottom, 22)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .disabled(approval.isPending("gate-launcher:\(review.gate.id)"))
            }
            .navigationTitle("Add Verified Launcher")
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
                    .disabled(model.isDiscoveringLauncherHelpers)
                }
            }
        }
        .frame(width: 680, height: 720)
        .onChange(of: review.helpers) { _, helpers in
            selectedHelperIDs = Set(helpers.filter {
                configuration.shouldSelectInReview($0)
            }.map(\.id))
        }
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
                Text(configuration.isEnabled(helper) ? "\(helper.name) · Already enabled" : helper.name)
                    .font(.system(size: 13, weight: .medium))
                Text("\(helper.helperSigningIdentifier) · Team \(helper.helperTeamIdentifier)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                if helper == claudeCodeVerifiedLauncherHelper {
                    Text("Claude Desktop installs Claude Code outside Claude.app. Selected by default; includes any eligible executable with this exact signing identity. Clearing this option disables the association at every Authorization Gate.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let warning = helper.runtimeCompatibilityWarning {
                    Label {
                        Text(warning)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                        .font(.system(size: 12))
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let relativePath = helper.relativePath {
                    Text(relativePath)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 8)
        }
        .toggleStyle(.checkbox)
        .frame(maxWidth: .infinity, alignment: .leading)
        .disabled(configuration.isEnabled(helper) && helper != claudeCodeVerifiedLauncherHelper)
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
    @AppStorage(AuthorizationHistoryRetention.sizeDefaultsKey)
    private var sizeMiB = AuthorizationHistoryRetention.defaultSizeMiB
    @State private var draftSizeMiB = AuthorizationHistoryRetention.configuredSizeMiB()

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Authorization History")
                    .font(.system(size: 24, weight: .semibold))
                Text("These Verified Launchers may run av history without Approval.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent("Database size (MiB)") {
                    TextField("Database size (MiB)", value: $draftSizeMiB, format: .number.grouping(.never))
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 90)
                    Button("Apply") { sizeMiB = draftSizeMiB }
                        .disabled(!AuthorizationHistoryRetention.sizeRangeMiB.contains(draftSizeMiB)
                            || draftSizeMiB == sizeMiB)
                }
                Text("1–1024 MiB; default 25 MiB. Limits encrypted record payloads; SQLite adds disk overhead. Records are kept for up to 30 days. Lowering the limit removes older records on the next history access.")
                    .font(.caption)
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
    @State private var embeddedTouchID = embeddedTouchIDApprovalIsEnabled()
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

            Toggle("Use Touch ID directly in the Approval window", isOn: Binding(
                get: { embeddedTouchID },
                set: { value in
                    let result = setEmbeddedTouchIDApprovalEnabled(value)
                    if result == errSecSuccess {
                        embeddedTouchID = value
                        abortActiveApprovalPrompt()
                    } else {
                        status = TouchIDApprovalError.storage(result).localizedDescription
                    }
                }
            ))
            Text("When enabled, touching the sensor approves the displayed request once, without clicking first. Turn this off if you prefer to click Approve before Touch ID starts. Touch ID Approval must be enabled separately.")
                .font(.caption)
                .foregroundStyle(.secondary)

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
    @ObservedObject var model: DashboardModel
    @StateObject private var approval = AuthorityApprovalState()
    @State private var configuration = loadVerifiedLauncherHelperConfiguration()
    @State private var status = ""
    @State private var discoveredHelpers: [VerifiedLauncherHelper] = []
    @State private var discoveryTask: Task<Void, Never>?

    private var helpers: [VerifiedLauncherHelper] {
        var result = configuration.helpers
        for discovered in discoveredHelpers {
            let helper = configuration.catalogHelper(matching: discovered) ?? discovered
            if !result.contains(where: { $0.id == helper.id }) { result.append(helper) }
        }
        return result
    }

    private var parents: [VerifiedLauncherHelperParent] {
        let policies = model.snapshot.secretGates.flatMap(\.appPolicies).filter {
            NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0.bundleIdentifier)?
                .pathExtension.caseInsensitiveCompare("app") == .orderedSame
        }
        return verifiedLauncherHelperParents(helpers: helpers, appPolicies: policies).sorted {
            $0.appName.localizedCaseInsensitiveCompare($1.appName) == .orderedAscending
        }
    }

    private func appName(_ parent: VerifiedLauncherHelperParent) -> String {
        let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: parent.appBundleIdentifier)
        let bundle = url.flatMap(Bundle.init(url:))
        return bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? parent.appName
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Verified Launcher Helpers")
                    .font(.system(size: 24, weight: .semibold))
                Text("Allow exact vendor-signed helpers to represent their parent app as the Verified Launcher.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            Text("Associations apply at every current and future Authorization Gate where the parent app has a Launcher-specific rule. Enabling a helper may widen Secret access and controlled operations up to each rule’s Access Level. Enable only helpers you trust to act as the app.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if discoveryTask != nil {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Inspecting app…").font(.caption)
                }
            }
            ForEach(parents) { parent in
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text(appName(parent)).font(.title2.weight(.semibold))
                        Spacer()
                        Button("Refresh Helper List") { discoverHelpers(for: parent) }
                            .disabled(discoveryTask != nil)
                            .accessibilityLabel("Refresh helper list for \(appName(parent))")
                            .help("Rescan the installed app for eligible signed helpers. New helpers remain disabled until approved.")
                    }
                    Text("\(parent.appBundleIdentifier) · Team \(parent.appTeamIdentifier)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    LauncherHelperOutlineView(helpers: helpers.filter {
                        $0.appBundleIdentifier == parent.appBundleIdentifier
                            && $0.appTeamIdentifier == parent.appTeamIdentifier
                    }) { helper in
                        helperRow(helper).padding(.vertical, 8)
                    }
                    .padding(.leading, 18)
                }
                Divider()
            }
            InfoBlock(
                title: "Exact identities only",
                text: String(localized: "Each association verifies both signing identities and binds the live helper to its on-disk executable. Except for Claude Code, helpers default to requiring unmodified membership in the parent app's resource seal. Claude Desktop installs Claude Code outside its bundle, so that association defaults to allowing outside-bundle execution. Allowing a helper outside the bundle removes that containment requirement; the signed parent app must still be installed. Other executables do not inherit the app's authority.")
            )
            if !status.isEmpty {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .onAppear { configuration = loadVerifiedLauncherHelperConfiguration() }
        .onDisappear {
            approval.cancelAll()
            discoveryTask?.cancel()
            discoveryTask = nil
        }
    }

    private func helperRow(_ helper: VerifiedLauncherHelper) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if let warning = helper.runtimeCompatibilityWarning {
                InfoBlock(title: "Runtime warning", text: warning)
            }
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
                            detail: "Signing ID: \(helper.helperSigningIdentifier) · Team \(helper.helperTeamIdentifier)\nPath: \(helper.relativePath ?? "Vendor-reviewed association")\n\nAllow the exact signed \(helper.name) helper\(configuration.allowedOutsideBundleHelperIDs.contains(helper.id) ? ", including outside the parent bundle," : " sealed inside \(helper.appName)") to represent \(helper.appName) at every Authorization Gate where that app has a current or future Launcher-specific rule. This may widen Secret access and controlled operations up to each rule’s Access Level."
                                + (helper.runtimeCompatibilityWarning.map { "\n\n" + $0 } ?? "")
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
            if configuration.catalogHelper(matching: helper) != nil {
                Toggle("Allow outside the parent bundle", isOn: Binding(
                    get: { configuration.allowedOutsideBundleHelperIDs.contains(helper.id) },
                    set: { next in
                        guard next else {
                            persistOutsideBundle(helper, allowed: false)
                            return
                        }
                        approval.request(
                            helper.id, title: "Allow \(helper.name) Outside Its Parent Bundle",
                            detail: "Allow any valid executable with this helper's exact signing identity to represent \(helper.appName) after being moved or copied outside its bundle. The helper will no longer be checked against the parent app's resource seal. Both signing identities and the helper's runtime protections remain verified, and the signed parent app must remain installed. This applies at every Authorization Gate where the app has a current or future Launcher-specific rule."
                                + (helper.runtimeCompatibilityWarning.map { "\n\n" + $0 } ?? "")
                        ) { approved in
                            if approved { persistOutsideBundle(helper, allowed: true) }
                        }
                    }
                ))
                .toggleStyle(.checkbox)
                .disabled(approval.isPending(helper.id))
            }
            Text("\(helper.helperSigningIdentifier) · Team \(helper.helperTeamIdentifier)")
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
            if configuration.userApprovedHelpers.contains(where: { $0.id == helper.id }) {
                Button("Remove Association", role: .destructive) {
                    approval.cancel(helper.id)
                    persist { $0.remove(helper) }
                }
                .disabled(approval.isPending(helper.id))
            } else if configuration.catalogHelper(matching: helper) == nil {
                Text("Discovered · Not enabled").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func discoverHelpers(for parent: VerifiedLauncherHelperParent) {
        guard let url = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: parent.appBundleIdentifier
        ) else {
            status = "Could not find the installed \(appName(parent)) app. Install or restore the app, then refresh its helper list."
            return
        }
        discoverHelpers(in: url, parent: parent)
    }

    private func discoverHelpers(in url: URL, parent: VerifiedLauncherHelperParent) {
        guard discoveryTask == nil else { return }
        status = ""
        discoveryTask = Task {
            let discovered = await discoverVerifiedLauncherHelpers(in: url)
            guard !Task.isCancelled else { return }
            let matching = discovered.filter { helper in
                return helper.appBundleIdentifier == parent.appBundleIdentifier
                    && helper.appTeamIdentifier == parent.appTeamIdentifier
            }
            configuration = loadVerifiedLauncherHelperConfiguration()
            // Keep other apps' discovered choices visible while reviewing this app.
            discoveredHelpers.removeAll { helper in
                helper.appBundleIdentifier == parent.appBundleIdentifier
                    && helper.appTeamIdentifier == parent.appTeamIdentifier
            }
            discoveredHelpers.append(contentsOf: matching)
            status = matching.isEmpty
                ? "No eligible signed helpers matching this app’s identity were found."
                : "Helper list refreshed for \(matching[0].appName). Newly discovered helpers require Approval to enable."
            discoveryTask = nil
        }
    }

    private func persist(_ helper: VerifiedLauncherHelper, enabled: Bool) {
        persist { next in
            if enabled {
                next.enable([helper])
            } else {
                next.disabledHelperIDs.insert(helper.id)
            }
        }
    }

    private func persistOutsideBundle(_ helper: VerifiedLauncherHelper, allowed: Bool) {
        persist { next in
            if allowed {
                next.allowedOutsideBundleHelperIDs.insert(helper.id)
            } else {
                next.allowedOutsideBundleHelperIDs.remove(helper.id)
            }
        }
    }

    private func persist(_ update: (inout VerifiedLauncherHelperConfiguration) -> Void) {
        do {
            configuration = try updateVerifiedLauncherHelperConfiguration(update)
            status = ""
        } catch {
            status = "Could not update Verified Launcher Helpers: \(error.localizedDescription)"
        }
    }
}

private struct SSHAgentSettingsView: View {
    @ObservedObject var model: DashboardModel
    @StateObject private var approval = AuthorityApprovalState()
    @ObservedObject private var runtime = SSHAgentRuntime.shared
    @State private var config = loadSSHAgentConfiguration()
    @State private var selectedID: String?
    @State private var importing = false
    @State private var renaming = false
    @State private var removing = false
    @State private var editingCredential: SSHAgentCredential?
    @State private var newName = ""
    @State private var status = ""
    @State private var availableWidth: CGFloat = 0

    init(model: DashboardModel, configuration: SSHAgentConfiguration = loadSSHAgentConfiguration()) {
        self.model = model
        _config = State(initialValue: configuration)
    }

    private var selected: SSHAgentCredential? {
        config.credentials.first { $0.id == selectedID } ?? config.credentials.first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Text("SSH Agent").font(.system(size: 24, weight: .semibold))
                Spacer()
                Toggle("Enable SSH Agent", isOn: Binding(get: { config.enabled }, set: { setEnabled($0) }))
                    .disabled(config.credentials.isEmpty || approval.isPending("enable") || (!SSHAgentRuntime.isSupported && !config.enabled))
            }
            Text("Each SSH key has its own Default Policy and Verified Launcher rules.")
                .foregroundStyle(.secondary)
            if !SSHAgentRuntime.isSupported {
                Text("This macOS version cannot provide the original process ancestry required by SSH Agent.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Group {
                if availableWidth >= 720 {
                    HStack(alignment: .top, spacing: 20) {
                        keyList.frame(width: 180, alignment: .leading)
                        Divider()
                        selectedKeyDetail
                    }
                } else {
                    VStack(alignment: .leading, spacing: 16) {
                        if !config.credentials.isEmpty {
                            Picker("SSH Key", selection: Binding(get: { selected?.id ?? "" }, set: { selectedID = $0 })) {
                                ForEach(config.credentials) { Text($0.name).tag($0.id) }
                            }
                        }
                        Button("Add SSH Key…", systemImage: "plus") { importing = true }
                            .disabled(config.credentials.count >= 32)
                        selectedKeyDetail
                    }
                }
            }
            Divider()
            HStack {
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
            }
            Text("Other agent clients can use SSH_AUTH_SOCK=\(sshAgentSocketURL().path). Disabling the agent leaves OpenSSH configured to fail closed until you remove its configuration.")
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            InfoBlock(title: "Existing access paths", text: String(localized: "Importing does not delete your original private key, its Keychain passphrase, or keys loaded in another agent. These remain independent access paths. After verifying the new setup, remove the old copies and agent entries yourself. Explicit IdentityFile settings may still select other keys."))
            InfoBlock(title: "Local Launcher boundary", text: String(localized: "Clients need a live Verified Launcher ancestor; a client cannot act as its own Launcher. Shared or forwarded connections carry requests under that ancestor’s attribution. OpenSSH configuration disables forwarding by default."))
            if !runtime.status.isEmpty { InfoBlock(title: "SSH Agent", text: runtime.status) }
            if !status.isEmpty { InfoBlock(title: "Status", text: status) }
            if let error = model.errorMessage { InfoBlock(title: "Error", text: error) }
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { availableWidth = $0 }
        .sheet(isPresented: $importing) {
            SSHCredentialSheetView { credential in
                refresh()
                selectedID = credential.id
                status = "Saved SSH key. Copy its public key to the services where it should authenticate."
            }
        }
        .alert("Rename SSH Key", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Cancel", role: .cancel) { }
            Button("Rename") { rename() }
        }
        .alert("Remove SSH Key?", isPresented: $removing) {
            Button("Cancel", role: .cancel) { }
            Button("Remove", role: .destructive) { remove() }
        } message: {
            Text("This removes \(editingCredential?.name ?? "the key") from this agent and deletes its stored private key. External copies and registrations with remote services remain.")
        }
        .onReceive(NotificationCenter.default.publisher(for: .sshAgentConfigurationChanged)) { _ in refresh() }
        .onDisappear { approval.cancelAll() }
    }

    private var keyList: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SSH Keys").font(.headline)
            ForEach(config.credentials) { credential in
                Button { selectedID = credential.id } label: {
                    HStack(alignment: .top) {
                        Image(systemName: "key.fill")
                        VStack(alignment: .leading, spacing: 4) {
                            Text(credential.name).fontWeight(.medium)
                            Text(keySummary(credential)).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 0)
                    }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(selected?.id == credential.id ? Color.accentColor.opacity(0.12) : .clear,
                                    in: RoundedRectangle(cornerRadius: 8))
                }.buttonStyle(.plain)
                    .accessibilityAddTraits(selected?.id == credential.id ? .isSelected : [])
            }
            Button("Add SSH Key…", systemImage: "plus") { importing = true }
                .disabled(config.credentials.count >= 32)
        }
    }

    @ViewBuilder private var selectedKeyDetail: some View {
        if let credential = selected {
            keyDetail(credential).frame(maxWidth: .infinity, alignment: .leading)
        } else {
            ContentUnavailableView("Add an SSH Key", systemImage: "key",
                description: Text("Import an existing key or generate a new Ed25519 key. New keys require Approval for every authentication."))
        }
    }

    private func keySummary(_ credential: SSHAgentCredential) -> String {
        guard let gate = model.snapshot.secretGates.first(where: { $0.id == credential.gateID }) else { return "Approval Required" }
        let allowed = gate.appPolicies.filter { $0.protection == .fullExceptSecretDumps && $0.denialThreshold == nil }
        if gate.defaultProtection == .fullExceptSecretDumps && gate.defaultDenialThreshold == nil { return "Default: Allow Authentication" }
        if gate.defaultDenialThreshold != nil { return "Default: Deny" }
        if !allowed.isEmpty { return allowed.count == 1 ? "1 Launcher allowed" : "\(allowed.count) Launchers allowed" }
        return "Approval Required"
    }

    @ViewBuilder private func keyDetail(_ credential: SSHAgentCredential) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(credential.name).font(.title2.weight(.semibold))
            Text(credential.publicKey.split(separator: " ").first.map(String.init) ?? "SSH key")
                .font(.caption).foregroundStyle(.secondary)
            Text(credential.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            Button("Copy Public Key") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(credential.publicKey, forType: .string)
            }
            Divider()
            Text("Authorization").font(.headline)
            if let gate = model.snapshot.secretGates.first(where: { $0.id == credential.gateID }) {
                GatePolicyTable(model: model, gate: gate, approval: model.authorityApproval).id(gate.id)
                Button("Add Launcher…") { model.addApp(to: gate) }
                Button("Open Authorization Gate") { model.showSecretGate(id: gate.id) }
            } else { ProgressView("Loading Authorization Gate…") }
            Text("Allow Authentication permits access wherever this key is accepted, including remote writes.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Key names describe intended use. They do not restrict destinations.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Rename…") { editingCredential = credential; newName = credential.name; renaming = true }
                Button("Remove Key…", role: .destructive) { editingCredential = credential; removing = true }
            }
        }
    }

    private func refresh() {
        config = loadSSHAgentConfiguration()
        if !config.credentials.contains(where: { $0.id == selectedID }) { selectedID = config.credentials.first?.id }
        model.reload()
    }

    private func persist(_ next: SSHAgentConfiguration) -> Bool {
        var next = next
        next.generation = UUID()
        let result = saveSSHAgentConfiguration(next)
        guard result == errSecSuccess else { status = "Could not save SSH Agent configuration: \(result)"; return false }
        config = next
        NotificationCenter.default.post(name: .sshAgentConfigurationChanged, object: nil)
        return true
    }

    private func rename() {
        guard let credential = editingCredential else { return }
        var next = loadSSHAgentConfiguration()
        guard let index = next.credentials.firstIndex(where: { $0.id == credential.id }) else { return }
        next.credentials[index].name = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        _ = persist(next)
    }

    private func remove() {
        guard let credential = editingCredential else { return }
        var next = loadSSHAgentConfiguration()
        next.credentials.removeAll { $0.id == credential.id }
        if next.credentials.isEmpty { next.enabled = false }
        // Unpublish first. A failed deletion cannot leave usable agent authority.
        guard persist(next) else { return }
        let result = deleteStoredSecretRevokingDirectAccess(account: credential.secretName)
        status = result == errSecSuccess || result == errSecItemNotFound
            ? "Removed SSH key." : "The key is no longer available to the agent, but its stored Secret could not be deleted: \(result)."
        model.reload()
    }

    private func setEnabled(_ enabled: Bool) {
        let reviewed = loadSSHAgentConfiguration()
        if !enabled { var next = reviewed; next.enabled = false; _ = persist(next); return }
        approval.request("enable", title: "Enable SSH Agent?",
                         detail: "Make these SSH keys available through their Authorization Gates: \(reviewed.credentials.map(\.name).joined(separator: ", ")). Each key’s existing policy applies.") { allowed in
            guard allowed else { return }
            guard loadSSHAgentConfiguration() == reviewed else {
                status = "The SSH keys changed while awaiting Approval. Review them and try again."
                return
            }
            var next = reviewed
            next.enabled = true
            _ = persist(next)
        }
    }
}

private struct SSHCredentialSheetView: View {
    let onSaved: (SSHAgentCredential) -> Void
    @Environment(\.dismiss) private var dismiss
    @StateObject private var approval = AuthorityApprovalState()
    @State private var name = ""
    @State private var generate = false
    @State private var privateKey = ""
    @State private var passphrase = ""
    @State private var busy = false
    @State private var error = ""

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name (for example, GitHub or Homelab)", text: $name)
                Picker("Key", selection: $generate) {
                    Text("Import Existing").tag(false)
                    Text("Generate New").tag(true)
                }.pickerStyle(.segmented)
                if generate {
                    Text("Generate an Ed25519 key. Its private key is stored in the Keychain and never displayed or written to a file.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("OpenSSH private key").font(.caption)
                    TextEditor(text: $privateKey)
                        .font(.system(.caption, design: .monospaced)).frame(minHeight: 130)
                        .accessibilityLabel("SSH private key")
                    SecureField("Passphrase (leave empty if none)", text: $passphrase)
                    Text("Paste a complete OPENSSH PRIVATE KEY block. Ed25519 and ECDSA authentication are supported. Stored private keys are never displayed.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("New keys start at Approval Required. Register the public key with the services where it should authenticate.")
                    .font(.caption).foregroundStyle(.secondary)
                if !error.isEmpty { Text(error).foregroundStyle(.red) }
            }.formStyle(.grouped).disabled(busy)
                .navigationTitle("Add SSH Key")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }.disabled(busy)
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button(busy ? "Saving…" : "Save") { submit() }
                            .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (!generate && privateKey.isEmpty) || busy)
                    }
                }
        }.frame(width: 560, height: 480)
            .interactiveDismissDisabled(busy)
            .onDisappear { privateKey = ""; passphrase = ""; approval.cancelAll() }
    }

    private func submit() {
        busy = true
        let requestedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let imported = ["private_key": privateKey, "passphrase": passphrase]
        let generating = generate
        let executable = Bundle.main.executableURL
        Task {
            do {
                let credential = try await prepareSSHCredential(imported, generating: generating, executable: executable)
                let key = SSHAgentCredential(name: requestedName, publicKey: credential.publicKey)
                let reviewed = loadSSHAgentConfiguration()
                var next = reviewed
                next.credentials.append(key)
                next.generation = UUID()
                guard next.isValid else { throw SSHAgentError.failed("Use a unique key and a name of up to 128 bytes without control characters. At most 32 keys are supported.") }
                approval.request("save", title: "Store this SSH key?",
                                 detail: "Add \(key.name) · \(key.fingerprint). Its Default Policy starts at Approval Required. Existing keys and their permissions are unchanged.") { allowed in
                    guard allowed else { busy = false; return }
                    do {
                        guard loadSSHAgentConfiguration() == reviewed else { throw SSHAgentError.failed("The SSH keys changed while awaiting Approval. Review them and try again.") }
                        let result = saveStoredSecret(account: key.secretName, value: credential.value)
                        guard result == errSecSuccess else { throw SSHAgentError.failed("Keychain error \(result)") }
                        let published = saveSSHAgentConfiguration(next)
                        guard published == errSecSuccess else {
                            _ = deleteStoredSecret(account: key.secretName)
                            throw SSHAgentError.failed("Could not publish SSH key: \(published)")
                        }
                        privateKey = ""; passphrase = ""
                        NotificationCenter.default.post(name: .sshAgentConfigurationChanged, object: nil)
                        onSaved(key)
                        dismiss()
                    } catch { self.error = error.localizedDescription; busy = false }
                }
            } catch { self.error = error.localizedDescription; busy = false }
        }
    }
}

@concurrent
private func prepareSSHCredential(_ imported: [String: String], generating: Bool, executable: URL?) async throws -> (publicKey: String, value: String) {
    let data = try generating
        ? runBundledCredentialCommand(arguments: ["__ssh-generate-key"], input: Data(), mainExecutableURL: executable)
        : JSONEncoder().encode(imported)
    guard data.count <= 1024 * 1024 else { throw SSHAgentError.failed("SSH credential exceeds 1 MiB") }
    let credential = try JSONDecoder().decode([String: String].self, from: data)
    let publicKey = try await validateSSHCredential(credential, executable: executable)
    return (publicKey, String(decoding: data, as: UTF8.self))
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

                GatePolicyTable(model: model, gate: gate, approval: model.authorityApproval)
                    .id(gate.id)
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

/// Drafts contain only the field the user edited. In particular, editing denial
/// must not turn an inherited gate default into a Launcher-specific allow rule.
private struct GatePolicyChange: Identifiable, Equatable {
    enum Value: Equatable {
        case allow(SecretGateProtection)
        case denial(SecretGateProtection?)
        case signing(SigningGateAccess)
    }
    let requirement: String?
    let value: Value

    var id: String {
        switch value {
        case .allow: requirement.map { "gate-policy:\($0)" } ?? "gate-default"
        case .denial: "gate-denial:\(requirement ?? "")"
        case .signing: "gate-signing:\(requirement ?? "")"
        }
    }

    func action(gate: SecretGate) -> String {
        switch value {
        case .allow: requirement.map { "gate-policy:\(gate.id):\($0)" } ?? "gate-default:\(gate.id)"
        case .denial: requirement.map { "gate-denial:\(gate.id):\($0)" } ?? "gate-default-denial:\(gate.id)"
        case .signing: "gate-signing:\(gate.id):\(requirement ?? "")"
        }
    }
}

// Observe rendered row identities without depending on the native backing controls.
private struct GatePolicyRowPreference: PreferenceKey {
    static let defaultValue: [String] = []
    static func reduce(value: inout [String], nextValue: () -> [String]) {
        value += nextValue()
    }
}

private struct GatePolicyTable: View {
    @ObservedObject var model: DashboardModel
    let gate: SecretGate
    @ObservedObject var approval: AuthorityApprovalState
    @State private var drafts: [GatePolicyChange] = []
    @State private var reviewing = false
    @State private var availableWidth: CGFloat = 720

    init(model: DashboardModel, gate: SecretGate, approval: AuthorityApprovalState) {
        self.model = model
        self.gate = gate
        self.approval = approval
        _availableWidth = State(initialValue: gate.isSSHAgentGate ? 480 : 720)
    }

    private var levels: [SecretGateProtection] { Array(gate.availableProtections.dropFirst()) }
    // These gates admit only signing requests; unsupported requests fail validation.
    private var showsUnknownOperations: Bool { gate.supportsUnknownDenial }
    private var changes: [GatePolicyChange] {
        drafts.filter { change in
            let app = gate.appPolicies.first { $0.requirement == change.requirement }
            if change.requirement != nil && app == nil { return false }
            switch change.value {
            case .allow(let level): return level != (app?.protection ?? gate.defaultProtection)
            case .denial(let level): return level != denialThreshold(for: app)
            case .signing(let access):
                return access != signingAccess(for: app)
            }
        }
    }
    private var pending: Bool {
        drafts.contains { approval.isPending($0.action(gate: gate)) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(gate.isSSHAgentGate ? "Choose an Access Level. Changes stay pending until reviewed." : "Drag the boundaries, or focus a handle and use the arrow keys. Changes stay pending until reviewed.")
                .font(.caption).foregroundStyle(.secondary)
            ScrollView(.horizontal) {
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 16) {
                        Text("Verified Launcher").frame(width: 190, alignment: .leading)
                        HStack(spacing: 0) {
                            if gate.isSSHAgentGate {
                                Text("Access Level").frame(maxWidth: .infinity, alignment: .leading)
                            } else {
                                ForEach(levels) { level in
                                    Text(localizedUIString(gate.protectionTitle(level)))
                                        .frame(maxWidth: .infinity)
                                        .help(localizedUIString(gate.protectionSubtitle(level)))
                                }
                            }
                            if showsUnknownOperations {
                                Text("Unknown").frame(maxWidth: .infinity)
                                    .help("Unclassified operations can require Approval or be denied, but cannot be automatically allowed.")
                            }
                        }
                        .padding(.trailing, 16)
                    }
                    .font(.caption).foregroundStyle(.secondary).padding(.vertical, 10)
                    Divider()
                    policyRow(app: nil)
                    ForEach(gate.appPolicies.sorted {
                        $0.requirement == model.selectedLauncherRequirement
                            && $1.requirement != model.selectedLauncherRequirement
                    }, id: \.requirement) { app in
                        Divider()
                        policyRow(app: app)
                            .background(app.requirement == model.selectedLauncherRequirement
                                ? Color.accentColor.opacity(0.08) : .clear)
                    }
                    Divider()
                }
                .frame(width: max(gate.isSSHAgentGate ? 480 : 720, availableWidth))
            }
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { availableWidth = $0 }

            Label(showsUnknownOperations
                ? String(localized: "Denial wins over allow rules. Unknown requires Approval unless a Denial Threshold is set.")
                : String(localized: "Denial wins over allow rules."), systemImage: "info.circle")
                .font(.caption).foregroundStyle(.secondary)
            Text("Expanding allow or reducing deny requires Approval.")
                .font(.caption).foregroundStyle(.secondary)
            if !changes.isEmpty {
                HStack {
                    Group {
                        if changes.count == 1 { Text("1 proposed change") }
                        else { Text("\(changes.count) proposed changes") }
                    }.font(.caption)
                    Spacer()
                    Button("Revert") { drafts.removeAll() }
                    Button("Review Changes") { reviewing = true }
                        .buttonStyle(.borderedProminent)
                }
                .disabled(pending)
            }
        }
        .onChange(of: gate) { _, _ in drafts = changes }
        .sheet(isPresented: $reviewing) { review }
    }

    private func stage(_ value: GatePolicyChange.Value, for app: SecretGatePolicy?) {
        let change = GatePolicyChange(requirement: app?.requirement, value: value)
        drafts.removeAll { $0.id == change.id }
        drafts.append(change)
        drafts = changes
    }

    private func policyRow(app: SecretGatePolicy?) -> some View {
        let rowChanges = changes.filter { $0.requirement == app?.requirement }
        let protection = rowChanges.compactMap { change -> SecretGateProtection? in
            if case .allow(let value) = change.value { return value }
            return nil
        }.first ?? app?.protection ?? gate.defaultProtection
        let denial: SecretGateProtection? = {
            if let change = rowChanges.first(where: { if case .denial = $0.value { return true }; return false }),
               case .denial(let value) = change.value { return value }
            return denialThreshold(for: app)
        }()
        return HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                if let app {
                    ApprovedAppRow(app: app, launcherBundle: model.launcherBundles.first {
                        $0.launcherRequirement == app.requirement
                    }, gate: gate, isEdited: !rowChanges.isEmpty, approval: approval, remove: { model.removeAppPolicy(app, from: gate) })
                } else {
                    HStack(spacing: 8) {
                        Label(localizedUIString(gate.defaultPolicyLabel), systemImage: "square.stack.3d.up")
                            .font(.system(size: 13, weight: .medium))
                            .help("Applies when no Launcher rule matches.")
                        if !rowChanges.isEmpty { PolicyEditedLabel() }
                    }
                    Text("Auto-allow requires Hardened Runtime.").font(.caption).foregroundStyle(.secondary)
                    Text("Denial applies regardless of runtime.").font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(width: 190, alignment: .leading)
            VStack(alignment: .leading, spacing: 8) {
                if !gate.supportsUnknownDenial {
                    let access = rowChanges.compactMap { change -> SigningGateAccess? in
                        if case .signing(let value) = change.value { return value }
                        return nil
                    }.first ?? signingAccess(for: app)
                    if !gate.isSSHAgentGate {
                    GatePolicyTrack(gate: gate, protection: access.protection(for: gate), denial: access.denial,
                        setProtection: { stage(.signing(SigningGateAccess(protection: $0, denial: nil)), for: app) },
                        setDenial: { stage(.signing(SigningGateAccess(protection: access.protection(for: gate), denial: $0)), for: app) })
                    } else {
                        NativeProtectionMenu(gate: gate,
                            protection: access == .deny ? nil : access.protection(for: gate),
                            usesPhone: false, includesDeny: true) { level in
                            stage(.signing(level.map { SigningGateAccess(protection: $0, denial: nil) } ?? .deny), for: app)
                        }
                        .frame(maxWidth: 240, alignment: .leading)
                    }
                } else {
                    GatePolicyTrack(gate: gate, protection: protection, denial: denial,
                                    setProtection: { stage(.allow($0), for: app) },
                                    setDenial: { stage(.denial($0), for: app) })
                }
                if app?.usesGateDefault == true && !rowChanges.contains(where: {
                    switch $0.value {
                    case .allow, .signing: return true
                    case .denial: return false
                    }
                }) {
                    Text("Auto-allow uses gate default").font(.caption).foregroundStyle(.secondary)
                }
                if gate.supportsUnknownDenial && GatePolicyRegions(gate: gate, protection: protection, denial: denial).allowEnd
                    > GatePolicyRegions(gate: gate, protection: protection, denial: denial).denyStart {
                    Text("Denial overrides overlapping allow levels.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .frame(minHeight: 52)
        .padding(.vertical, 14)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(app?.bundleIdentifier ?? localizedUIString(gate.defaultPolicyLabel))
        .preference(key: GatePolicyRowPreference.self, value: [app?.requirement ?? "default"])
        .disabled(pending)
    }

    private func signingAccess(for app: SecretGatePolicy?) -> SigningGateAccess {
        SigningGateAccess(protection: gate.normalizedProtection(app?.protection ?? gate.defaultProtection),
                          denial: denialThreshold(for: app))
    }

    private func denialThreshold(for app: SecretGatePolicy?) -> SecretGateProtection? {
        app == nil ? gate.defaultDenialThreshold : app?.denialThreshold
    }

    private func denialTitle(_ level: SecretGateProtection?) -> String {
        guard let level else { return String(localized: "None") }
        return level == .noAccess ? String(localized: "All operations") : localizedUIString(gate.protectionTitle(level))
    }

    private var review: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Review Changes").font(.title2.bold())
            Text("Apply each change separately. Expanding allow or reducing deny requires Approval. Unapplied changes remain pending.")
                .foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(changes) { change in
                        let app = gate.appPolicies.first { $0.requirement == change.requirement }
                        VStack(alignment: .leading, spacing: 6) {
                            Text(app?.bundleIdentifier ?? localizedUIString(gate.defaultPolicyLabel)).font(.headline)
                            HStack {
                                switch change.value {
                                case .allow(let level):
                                    Text("Allow ≤ \(gate.protectionTitle(app?.protection ?? gate.defaultProtection)) → \(gate.protectionTitle(level))")
                                case .signing(let access):
                                    Text("\(signingAccess(for: app).title(for: gate)) → \(access.title(for: gate))")
                                case .denial(let level):
                                    Text("Deny ≥ \(denialTitle(denialThreshold(for: app))) → \(denialTitle(level))")
                                }
                                Spacer()
                                Button {
                                    switch change.value {
                                    case .allow(let level):
                                        if let app { model.setProtection(level, for: app, in: gate) }
                                        else { model.setDefaultProtection(level, for: gate) }
                                    case .denial(let level):
                                        model.setDenialThreshold(level, for: app, in: gate)
                                    case .signing(let access):
                                        model.setSigningAccess(access, for: app, in: gate)
                                    }
                                } label: {
                                    AuthorityApprovalLabel(title: "Apply", approval: approval,
                                                           action: change.action(gate: gate), requiresApproval: requiresApproval(change, app: app))
                                }
                                .disabled(pending)
                            }
                        }
                        Divider()
                    }
                    if changes.isEmpty { Label("Changes applied", systemImage: "checkmark.circle") }
                }
            }
            if let error = model.errorMessage { Text(error).foregroundStyle(.red) }
            HStack {
                Spacer()
                if pending {
                    Button("Cancel Approval") {
                        for change in drafts { approval.cancel(change.action(gate: gate)) }
                    }
                }
                Button("Done") { reviewing = false }.keyboardShortcut(.cancelAction).disabled(pending)
            }
        }
        .padding(24).frame(width: 640, height: 420)
        .interactiveDismissDisabled(pending)
    }

    private func requiresApproval(_ change: GatePolicyChange, app: SecretGatePolicy?) -> Bool {
        switch change.value {
        case .allow(let level):
            return level.addsAuthority(over: app.map { $0.usesGateDefault ? .noAccess : $0.protection } ?? gate.defaultProtection)
        case .denial(let level): return gate.weakeningDenial(from: denialThreshold(for: app), to: level)
        case .signing(let access):
            return access.requiresApproval(in: gate, protection: app?.protection ?? gate.defaultProtection,
                denial: denialThreshold(for: app), usesGateDefault: app?.usesGateDefault == true)
        }
    }
}

private struct GatePolicyTrack: View {
    let gate: SecretGate
    let protection: SecretGateProtection
    let denial: SecretGateProtection?
    let setProtection: (SecretGateProtection) -> Void
    let setDenial: (SecretGateProtection?) -> Void
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.displayScale) private var displayScale
    @GestureState private var allowDrag: Int?
    @GestureState private var denyDrag: Int?
    @FocusState private var focusedHandle: Bool?
    @State private var showsKeyboardFocus = false

    private var regions: GatePolicyRegions { GatePolicyRegions(gate: gate, protection: protection, denial: denial) }

    var body: some View {
        GeometryReader { geometry in
            let width = geometry.size.width
            let hairline = 1 / displayScale
            let count = regions.columnCount
            let allow = allowDrag ?? regions.allowEnd
            let deny = denyDrag ?? regions.denyStart
            let effectiveAllow = min(allow, deny)
            ZStack(alignment: .leading) {
                HStack(spacing: 0) {
                    region("Allow", symbol: "checkmark", color: .green, columns: effectiveAllow, width: width)
                    region("Approval Required", symbol: "hand.raised", color: .secondary, columns: deny - effectiveAllow, width: width)
                    region("Deny", symbol: "nosign", color: .red, columns: count - deny, width: width)
                }
                .clipShape(RoundedRectangle(cornerRadius: 5))
                ForEach(1..<max(1, count), id: \.self) { boundary in
                    Rectangle().fill(Color.primary.opacity(boundary == regions.levels.count ? 0.4 : 0.12))
                        .frame(width: boundary == regions.levels.count ? 2 : 1, height: 8)
                        .frame(height: 40, alignment: .top)
                        .offset(x: width * CGFloat(boundary) / CGFloat(count))
                        .accessibilityHidden(true)
                }
                if allow != deny {
                    Rectangle().fill(Color.green)
                        .frame(width: hairline, height: 20)
                        .offset(x: width * CGFloat(allow) / CGFloat(count) - hairline / 2, y: 10)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                    Rectangle().fill(Color.red)
                        .frame(width: hairline, height: 20)
                        .offset(x: width * CGFloat(deny) / CGFloat(count) - hairline / 2, y: -10)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
                handle(isAllow: true, boundary: allow, width: width)
                handle(isAllow: false, boundary: deny, width: width)
            }
        }
        .frame(height: 40)
        .coordinateSpace(name: "gate-policy-track")
        // Keep the final handle and focus outline inside the scroll view.
        .padding(.trailing, 16)
    }

    private func region(_ title: String, symbol: String, color: Color, columns: Int, width: CGFloat) -> some View {
        Group {
            if columns > 0 {
                Label(localizedUIString(title), systemImage: symbol)
                    .font(.caption).lineLimit(1).minimumScaleFactor(0.85)
                    .frame(width: width * CGFloat(columns) / CGFloat(regions.columnCount), height: 40)
                    .foregroundStyle(.primary)
                    .background(color.opacity(color == .secondary ? 0.16 : (colorScheme == .dark ? 0.30 : 0.25)))
            }
        }
    }

    private func handle(isAllow: Bool, boundary: Int, width: CGFloat) -> some View {
        let value = isAllow ? gate.protectionTitle(regions.protection(at: boundary))
            : regions.denial(at: boundary).map { $0 == .noAccess ? String(localized: "All operations") : gate.protectionTitle($0) } ?? String(localized: "None")
        let isDragging = isAllow ? allowDrag != nil : denyDrag != nil
        let isFocused = focusedHandle == isAllow && showsKeyboardFocus
        let tint: Color = isFocused || isDragging ? .accentColor : (isAllow ? .green : .red)
        return RoundedRectangle(cornerRadius: 4, style: .continuous)
            .fill(Color(nsColor: .controlBackgroundColor))
            .overlay {
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .strokeBorder(tint.opacity(isFocused || isDragging ? 0.9 : 0.45), lineWidth: isFocused ? 2 : 1)
            }
            .overlay {
                HStack(spacing: 3) {
                    Capsule().frame(width: 1.5, height: 9)
                    Capsule().frame(width: 1.5, height: 9)
                }
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            }
            .frame(width: 14, height: 22)
            .shadow(color: .black.opacity(isDragging ? 0.25 : 0.15), radius: 2, y: 1)
            .scaleEffect(isDragging ? 1.08 : 1)
            // Separate the handles vertically so both remain reachable when they meet.
            .frame(width: 22, height: 22)
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .named("gate-policy-track"))
                .updating(isAllow ? $allowDrag : $denyDrag) { event, state, _ in
                    state = min(isAllow ? regions.levels.count : regions.columnCount,
                                regions.snappedBoundary(fraction: event.location.x / max(1, width)))
                }
                .onEnded { event in
                    let snapped = regions.snappedBoundary(fraction: event.location.x / max(1, width))
                    if isAllow { setProtection(regions.protection(at: snapped)) }
                    else { setDenial(regions.denial(at: snapped)) }
                })
            .focusable(interactions: .edit)
            .focused($focusedHandle, equals: isAllow)
            .focusEffectDisabled()
            .onChange(of: focusedHandle) { _, handle in
                showsKeyboardFocus = handle != nil && NSApp.currentEvent?.type == .keyDown
            }
            .simultaneousGesture(DragGesture(minimumDistance: 0).onChanged { _ in
                showsKeyboardFocus = false
            })
            .onKeyPress(keys: [.leftArrow, .rightArrow, .upArrow, .downArrow]) { press in
                showsKeyboardFocus = true
                adjust(isAllow: isAllow, boundary: boundary,
                       increment: press.key == .rightArrow || press.key == .upArrow)
                return .handled
            }
            .accessibilityElement()
            .accessibilityLabel(isAllow ? "Allow through" : "Deny from")
            .accessibilityValue(value)
            .accessibilityAdjustableAction { direction in
                switch direction {
                case .increment: adjust(isAllow: isAllow, boundary: boundary, increment: true)
                case .decrement: adjust(isAllow: isAllow, boundary: boundary, increment: false)
                @unknown default: break
                }
            }
            .accessibilityHint("Use the arrow keys to adjust this boundary. Changes stay pending until reviewed.")
            .help(isAllow ? "Drag or use arrow keys to adjust allow." : "Drag or use arrow keys to adjust deny.")
            .offset(x: width * CGFloat(boundary) / CGFloat(regions.columnCount) - 11, y: isAllow ? -10 : 10)
    }

    private func adjust(isAllow: Bool, boundary: Int, increment: Bool) {
        let next = regions.adjustedBoundary(boundary, isAllow: isAllow, increment: increment)
        if isAllow { setProtection(regions.protection(at: next)) }
        else { setDenial(regions.denial(at: next)) }
    }
}

private struct PolicyEditedLabel: View {
    var body: some View {
        Text("Edited")
            .textCase(.uppercase)
            .font(.system(size: 8, weight: .semibold))
            .tracking(0.8)
            .foregroundStyle(Color.accentColor)
            .fixedSize()
            .allowsHitTesting(false)
    }
}

private struct ApprovedAppRow: View {
    let app: SecretGatePolicy
    let launcherBundle: LauncherBundleEnrollment?
    let gate: SecretGate
    var isEdited = false
    @ObservedObject var approval: AuthorityApprovalState
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
                .overlay(alignment: .bottom) {
                    if isEdited {
                        PolicyEditedLabel()
                            .offset(y: 16)
                    }
                }
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

        }
        .contentShape(Rectangle())
        .contextMenu {
            Button("Delete", role: .destructive) {
                isConfirmingDelete = true
            }
            .disabled(approval.isPending("gate-policy:\(gate.id):\(app.requirement)")
                      || approval.isPending("gate-denial:\(gate.id):\(app.requirement)"))
        }
        .alert("Delete \(display.name)?", isPresented: $isConfirmingDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive, action: remove)
        } message: {
            Text("This deletes the Launcher-specific rule. Future requests from this Verified Launcher at the \(gate.displayName) Authorization Gate will use the default \(gate.protectionTitle(gate.defaultProtection)) Access Level.")
        }
    }
}

private struct NativeProtectionMenu: NSViewRepresentable {
    let gate: SecretGate
    let protection: SecretGateProtection?
    let usesPhone: Bool
    var isDenial = false
    var includesDeny = false
    let setProtection: (SecretGateProtection?) -> Void

    private var candidates: [SecretGateProtection?] {
        ((isDenial || includesDeny) ? [nil] : []) + (isDenial ? gate.availableDenialThresholds : gate.availableProtections).map(Optional.some)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    func makeNSView(context: Context) -> NSPopUpButton {
        let button = NSPopUpButton(frame: .zero, pullsDown: false)
        button.isBordered = false
        button.controlSize = .small
        button.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        button.target = context.coordinator
        button.action = #selector(Coordinator.selectProtection(_:))
        button.setAccessibilityLabel(includesDeny ? String(localized: "Access Level")
            : isDenial ? String(localized: "Denial Threshold") : String(localized: "Protection level"))
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
        let warning = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: String(localized: "Warning"))
        for value in candidates {
            guard let candidate = value else {
                button.addItem(withTitle: includesDeny ? String(localized: "Deny") : String(localized: "None"))
                if includesDeny {
                    let subtitle = String(localized: "Requests are denied without asking for Approval.")
                    button.lastItem?.toolTip = subtitle
                    if #available(macOS 14.4, *) { button.lastItem?.subtitle = subtitle }
                }
                continue
            }
            button.addItem(withTitle: isDenial && candidate == .noAccess
                ? String(localized: "All operations") : localizedUIString(gate.protectionTitle(candidate)))
            // Allow explanations and warnings would misdescribe a denial choice.
            if isDenial { continue }
            let title = NSMutableAttributedString(string: localizedUIString(gate.protectionTitle(candidate)))
            if candidate == .fullExceptSecretDumps || candidate == .fullIncludingSecretDumps {
                let attachment = NSTextAttachment()
                let icon = warning?.withSymbolConfiguration(.init(pointSize: 11, weight: .regular))
                attachment.image = candidate == .fullIncludingSecretDumps
                    ? icon?.withSymbolConfiguration(.init(paletteColors: [.white, .systemRed])) : icon
                title.append(NSAttributedString(string: "  "))
                title.append(NSAttributedString(attachment: attachment))
            }
            if usesPhone && candidate.addsAuthority(over: protection ?? .noAccess) {
                title.append(NSAttributedString(string: "  "))
                let attachment = NSTextAttachment()
                attachment.image = NSImage(systemSymbolName: "iphone", accessibilityDescription: String(localized: "Approval on iPhone"))?
                    .withSymbolConfiguration(.init(pointSize: 11, weight: .regular))
                title.append(NSAttributedString(attachment: attachment))
                button.lastItem?.toolTip = String(localized: "Requires Approval on iPhone.")
            }
            button.lastItem?.attributedTitle = title
            if #available(macOS 14.4, *) {
                button.lastItem?.subtitle = localizedUIString(gate.protectionSubtitle(candidate))
            }
        }
    }

    private func updateSelection(in button: NSPopUpButton) {
        guard let selectedIndex = candidates.firstIndex(of: protection) else { return }
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
            let candidates = parent.candidates
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
    var helpers: [VerifiedLauncherHelper]

    func defaultSelectedHelperIDs(configuration: VerifiedLauncherHelperConfiguration) -> Set<String> {
        Set(helpers.filter {
            $0 == claudeCodeVerifiedLauncherHelper ? configuration.isEnabled($0) : configuration.shouldSelectInReview($0)
        }.map(\.id))
    }

    func disabledHelperIDs(selected: Set<String>) -> Set<String> {
        Set(helpers.filter {
            $0 == claudeCodeVerifiedLauncherHelper && !selected.contains($0.id)
        }.map(\.id))
    }
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
private func showLauncherCannotBeAllowed(_ reason: String, title: String = "Launcher cannot be allowed") {
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = reason
    alert.runModal()
}

@MainActor
private func chooseLauncher(
    recentApp: AccessRequestRecord? = nil,
    reviewsIdentity: Bool = true,
    _ completion: @escaping (LauncherSigning?) -> Void
) {
    let review: (LauncherSigning?) -> Void = { signing in
        guard let signing else {
            completion(nil)
            return
        }
        guard reviewsIdentity else { completion(signing); return }
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
    if let recentApp {
        // History is a chooser shortcut, never evidence of current identity or authority.
        guard let signing = recentLauncherSigning(recentApp)
        else {
            showLauncherCannotBeAllowed("Choose a valid Developer ID-signed executable or signed app.")
            completion(nil)
            return
        }
        review(signing)
    } else {
        pickLauncher(review)
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

private func recentLauncherSigning(_ record: AccessRequestRecord) -> LauncherSigning? {
    guard let path = record.launcherIconPath,
          let requirement = record.launcherRequirement,
          let signing = launcherSigning(URL(fileURLWithPath: path).resolvingSymlinksInPath()),
          signing.requirement == requirement
    else { return nil }
    return signing
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

private func shortDashboardTimestamp(_ date: Date) -> String {
    date.formatted(.dateTime.month(.twoDigits).day(.twoDigits).hour().minute())
}

/// Spatial acquisition tolerance only; once horizontal panning starts, buckets stay exact.
private struct ActivityHoverSelection {
    static let buffer: CGFloat = 12
    private(set) var slot: Int?
    private var entryX: CGFloat?
    private var isPanning = false

    mutating func update(x: CGFloat, width: CGFloat, counts: [Int]) {
        guard width > 0, !counts.isEmpty else { self = Self(); return }
        let pitch = (width + 1) / CGFloat(counts.count)
        let exact = Int(floor(x / pitch))
        if let entryX {
            if abs(x - entryX) >= 1 { isPanning = true }
            if isPanning {
                slot = x >= 0 && x <= width && counts.indices.contains(exact) && counts[exact] > 0
                    ? exact : nil
            }
        } else {
            entryX = x
            // Only the initial entry may snap to a nearby populated bar.
            slot = counts.indices.filter { counts[$0] > 0 }.min { lhs, rhs in
                distance(to: lhs, x: x, pitch: pitch) < distance(to: rhs, x: x, pitch: pitch)
            }
            if let slot, distance(to: slot, x: x, pitch: pitch) > Self.buffer { self.slot = nil }
        }
    }

    private func distance(to slot: Int, x: CGFloat, pitch: CGFloat) -> CGFloat {
        let left = CGFloat(slot) * pitch
        return max(left - x, x - (left + max(0.5, pitch - 1)), 0)
    }
}

private struct ToolActivityStrip: View {
    let counts: [Int]?
    let now: Date
    let latestActivity: Date?
    let latestRecord: (Int) -> AccessRequestRecord?
    @State private var hover = ActivityHoverSelection()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = 0

    var body: some View {
        Group {
            if let counts {
                GeometryReader { geometry in
                    HStack(spacing: 1) {
                        ForEach(counts.indices, id: \.self) { slot in
                            Rectangle()
                                // A fixed logarithmic scale keeps Tools comparable: 1, 4, 16, 64 requests.
                                .fill(Color.primary.opacity(counts[slot] == 0
                                    ? 0.06 : min(1, 0.25 + log2(Double(counts[slot])) / 8)))
                                .overlay {
                                    if slot == counts.indices.last {
                                        Rectangle().fill(Color.accentColor)
                                            .keyframeAnimator(initialValue: 0.0, trigger: pulse) { content, opacity in
                                                content.opacity(opacity)
                                            } keyframes: { _ in
                                                MoveKeyframe(1)
                                                LinearKeyframe(0, duration: 0.8)
                                            }
                                            .opacity(reduceMotion ? 0 : 1)
                                    }
                                }
                                .frame(minWidth: 0.5)
                        }
                    }
                    .overlay(alignment: .topLeading) {
                        Color.clear
                            .frame(width: geometry.size.width + ActivityHoverSelection.buffer * 2,
                                   height: 8 + ActivityHoverSelection.buffer * 2)
                            .contentShape(Rectangle())
                            .onContinuousHover { phase in
                                switch phase {
                                case .active(let location):
                                    hover.update(x: location.x - ActivityHoverSelection.buffer,
                                                 width: geometry.size.width, counts: counts)
                                case .ended:
                                    hover = ActivityHoverSelection()
                                }
                            }
                            .offset(x: -ActivityHoverSelection.buffer, y: -ActivityHoverSelection.buffer)
                    }
                    .background {
                        InstantActivityPopover(
                            content: hover.slot.flatMap { slot in
                                guard counts.indices.contains(slot), let record = latestRecord(slot) else { return nil }
                                return ToolActivityPopover(record: record,
                                    interval: slotDescription(slot, count: counts[slot], slotCount: counts.count))
                            },
                            anchorX: (Double(hover.slot ?? 0) + 0.5) / Double(max(1, counts.count))
                        )
                        .frame(width: geometry.size.width, height: 8)
                        .allowsHitTesting(false)
                    }
                    .onChange(of: counts) { _, _ in hover = ActivityHoverSelection() }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Activity in the last 24 hours")
                .accessibilityValue("\(String(counts.reduce(0, +))) recorded requests")
            } else {
                RoundedRectangle(cornerRadius: 1)
                    .stroke(Color.secondary, style: StrokeStyle(lineWidth: 0.5, dash: [2, 2]))
                    .help("History unavailable")
                    .accessibilityLabel("History unavailable")
            }
        }
        .frame(height: 8)
        .onChange(of: latestActivity) { previous, latest in
            // Initial loads and history removal are not live activity.
            if let previous, let latest, latest > previous, !reduceMotion {
                pulse += 1
            }
        }
    }

    private func slotDescription(_ slot: Int, count: Int, slotCount: Int) -> String {
        let duration = 86_400 / Double(slotCount)
        let start = now.addingTimeInterval(-86_400 + Double(slot) * duration)
        let end = start.addingTimeInterval(duration)
        let interval = start.formatted(.dateTime.hour().minute()) + "–"
            + end.formatted(.dateTime.hour().minute())
        return String(localized: "\(interval): \(String(count)) recorded requests")
    }
}

/// SwiftUI's transaction animation does not control NSPopover's window animation.
private struct InstantActivityPopover: NSViewRepresentable {
    let content: ToolActivityPopover?
    let anchorX: CGFloat

    func makeNSView(context: Context) -> AnchorView { AnchorView() }

    func updateNSView(_ view: AnchorView, context: Context) {
        view.content = content
        view.anchorX = anchorX
        view.refresh()
    }

    static func dismantleNSView(_ view: AnchorView, coordinator: ()) {
        view.popover.close()
    }

    final class AnchorView: NSView {
        let popover = NSPopover()
        var content: ToolActivityPopover?
        var anchorX: CGFloat = 0
        private var presentedContent: ToolActivityPopover?
        private var presentedAnchor: NSRect?

        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
            popover.animates = false
            popover.behavior = .transient
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            refresh()
        }

        override func layout() {
            super.layout()
            refresh()
        }

        func refresh() {
            guard window != nil, let content else {
                popover.close()
                popover.contentViewController = nil
                return
            }
            let anchor = NSRect(x: bounds.minX + (bounds.width + 1) * anchorX - 0.5,
                                y: bounds.midY - 4, width: 1, height: 8)
            guard !popover.isShown || presentedContent != content || presentedAnchor != anchor else { return }
            if let host = popover.contentViewController as? NSHostingController<ToolActivityPopover> {
                host.rootView = content
            } else {
                popover.contentViewController = NSHostingController(rootView: content)
            }
            // Resolve SwiftUI's ideal size before AppKit positions the window. Deferred
            // sizing otherwise moves the arrow on the first pan or a command-length change.
            if let host = popover.contentViewController {
                host.view.layoutSubtreeIfNeeded()
                popover.contentSize = host.view.fittingSize
            }
            presentedContent = content
            presentedAnchor = anchor
            popover.show(relativeTo: anchor, of: self, preferredEdge: .minY)
            // This is a read-only hover surface. Its window overlaps the acquisition
            // buffer, so receiving mouse events would cause exit/dismiss/re-entry loops.
            popover.contentViewController?.view.window?.ignoresMouseEvents = true

        }
    }
}

/// The same redacted command presentation as Authorization History; no Secret values are loaded.
private struct ToolActivityPopover: View, Equatable {
    let record: AccessRequestRecord
    let interval: String

    private var color: Color {
        switch record.decision {
        case "Approved": .green
        case "Always Allowed": .blue
        case "Denied": .red
        default: .orange
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("Latest request").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Text(localizedUIString(record.decision))
                    .font(.system(size: 10, weight: .bold))
                    .padding(.horizontal, 7)
                    .frame(height: 18)
                    .outlinedPill(color)
            }
            Text(record.commandForDisplay)
                .font(.system(size: 12, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 6) {
                Label(record.launcher ?? String(localized: "unknown"), systemImage: "app")
                    .lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 8)
                Text(localizedUIString(record.approvalSourceLabel))
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            Divider()
            VStack(alignment: .leading, spacing: 3) {
                Text(record.date.formatted(.dateTime.month(.abbreviated).day().hour().minute().second().timeZone()))
                    .font(.caption).monospacedDigit()
                Text(interval).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .frame(width: 440, alignment: .leading)
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct InitialLoadingView: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private static let shield = NSImage(named: "LoadingShield")

    var body: some View {
        Group {
            if let shield = Self.shield {
                ZStack {
                    Image(nsImage: shield)
                        .renderingMode(.template)
                        .resizable()
                        .scaledToFit()
                        .foregroundStyle(.primary)
                        // Keep the silhouettes, clearing the baked-in eye and its reflections.
                        .mask {
                            HStack(spacing: 6) {
                                Rectangle()
                                Rectangle()
                            }
                        }
                        .opacity(reduceTransparency ? 1 : 0.17)

                    Capsule()
                        .fill(.primary)
                        .frame(width: 3, height: 28.98)
                        // Animate intensity only; eye dimensions and glow radius stay fixed.
                        .keyframeAnimator(initialValue: 1.0, repeating: !reduceMotion) { eye, intensity in
                            eye
                                .opacity(0.15 + 0.394 * intensity)
                                .background {
                                    // Preserve the original glow independently of the dimmer eye.
                                    eye
                                        .blur(radius: 7.5)
                                        .opacity(0.89 * intensity * (0.15 + 0.85 * intensity))
                                }
                        } keyframes: { _ in
                            LinearKeyframe(1, duration: 1.0)
                            CubicKeyframe(0, duration: 1.15, startVelocity: 0, endVelocity: 0)
                            CubicKeyframe(1, duration: 0.4, startVelocity: 0, endVelocity: 0)
                        }
                        .offset(y: 1.75)
                }
            } else {
                ProgressView()
            }
        }
        .frame(width: 128, height: 128)
        .scaleEffect(0.8)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Loading Automic Vault…")
    }
}

private struct OverviewTextButtonStyle: ButtonStyle {
    @Environment(\.colorScheme) private var colorScheme

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .brightness(configuration.isPressed ? (colorScheme == .light ? -0.22 : -0.08) : 0)
    }
}

private struct OverviewToolButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(maxWidth: .infinity, minHeight: 53)
            .background(.primary.opacity(configuration.isPressed ? 0.12 : 0),
                        in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
    }
}

/// Bounded summaries only: full inventories and actions stay in their existing sections.
private struct DashboardOverviewView: View {
    @ObservedObject var model: DashboardModel
    let checkForUpdates: () -> Void
    @State private var news: [BlogPost] = []

    init(model: DashboardModel, checkForUpdates: @escaping () -> Void, news: [BlogPost] = []) {
        self.model = model
        self.checkForUpdates = checkForUpdates
        _news = State(initialValue: news)
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: 10)
            .fill(.quaternary.opacity(0.3))
    }

    private var projectCount: Int {
        Set(model.snapshot.secrets.flatMap(\.values).compactMap { value -> String? in
            if case .projectDirectory(let path) = value.source { return path }
            return nil
        }).count
    }

    var body: some View {
        Group {
            if model.hasLoadedInitialSnapshot {
                dashboard
            } else {
                InitialLoadingView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Color.accentColor)
        .buttonStyle(OverviewTextButtonStyle())
        .task {
            do { news = try await BlogFeed.load() }
            catch { /* News is optional; the blog link remains available offline. */ }
        }
    }

    private var dashboard: some View {
        GeometryReader { geometry in
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    summary(.allSecrets, value: "\(model.snapshot.secrets.count)", caption: "Secrets", projects: projectCount)
                    summary(.blessedScripts, value: "\(model.count(for: .blessedScripts))", caption: "Blessed Scripts")
                    summary(.launcherBundles, value: "\(model.launcherBundles.count)", caption: "Launcher Bundles")
                }
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 20) {
                        toolPanel.frame(minWidth: 320)
                        attention(compact: false).frame(width: 240)
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        toolPanel
                        attention(compact: true)
                    }
                }
                .frame(maxHeight: .infinity)
                HStack(spacing: 16) {
                    Spacer()
                    Link("Documentation ↗", destination: URL(string: "https://www.automicvault.com/docs/")!)
                        .foregroundStyle(Color.accentColor)
                    Link("GitHub ↗", destination: URL(string: "https://github.com/automic-vault/automic-vault")!)
                        .foregroundStyle(Color.accentColor)
                }.font(.caption)
            }
            .padding([.horizontal, .bottom], 20)
            .frame(width: geometry.size.width, height: geometry.size.height, alignment: .topLeading)
        }
    }

    private var toolPanel: some View {
        TimelineView(.periodic(from: .now, by: 60)) { context in
            tools(now: max(context.date, Date()))
        }
    }

    private func tools(now: Date) -> some View {
        let allTools = model.overviewTools
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text("Tools").font(Font(NSFont.titleBarFont(ofSize: 0)))
                Text("Last 24 hours").font(.caption2).foregroundStyle(.secondary)
                    .help("Retained Authorization Records, including denials. Older records may have been removed by the storage limit.")
                Spacer()
                if let status = model.overviewClearStatus {
                    Text(localizedUIString(status))
                        .font(.caption).foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
            }
            GeometryReader { tableSpace in
                let visibleTools = Array(allTools.prefix(max(1, Int((tableSpace.size.height - 24) / 54))))
                let slotCount = DashboardActivityIndex.slotCount(forWidth: tableSpace.size.width - 30)
                VStack(spacing: 0) {
                    if allTools.isEmpty {
                        Button {
                            model.navigateFromOverview(to: .detectors)
                        } label: {
                            Label(localizedUIString(model.hasSearchQuery ? "No matching Tools · View detectors" : "Review available detectors"), systemImage: "sensor.tag.radiowaves.forward")
                                .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 12)
                        }
                    }
                    ForEach(visibleTools) { tool in
                        let issue = model.overviewDoctorIssue(for: tool)
                        let needsAttention = tool.isTriggered || issue != nil
                        let attentionColor = tool.isTriggered ? detectorSeverityColor(tool.severity) : Color.orange
                        let hasGate = model.overviewHasGate(tool)
                        Button {
                            model.openOverviewTool(tool)
                        } label: {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 4) {
                                    Image(systemName: needsAttention ? "exclamationmark.triangle.fill" : (tool.isBuiltInTool ? "key" : "hammer"))
                                        .foregroundStyle(needsAttention ? attentionColor : Color.secondary)
                                        .frame(width: 20)
                                        .padding(.trailing, 6)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(tool.title).fontWeight(.medium).lineLimit(1)
                                            .help((issue?.message ?? tool.subtitle) + (hasGate
                                                ? "\n" + String(localized: "Recorded authorization requests in the last 24 hours. This is not a count of Tool executions.") : ""))
                                        if !tool.isBuiltInTool && (!hasGate || !tool.isHardened) {
                                            Text(model.overviewVerification(for: tool))
                                                .font(.caption2)
                                                .foregroundStyle(.secondary).lineLimit(1)
                                        }
                                    }
                                    Spacer(minLength: 0)
                                    if !tool.isBuiltInTool || needsAttention {
                                        HStack(spacing: 4) {
                                            if !needsAttention && tool.isHardened { Image(systemName: "checkmark.seal") }
                                            Text(localizedUIString(issue != nil ? (tool.isTriggered ? "Finding · Doctor report" : "Doctor report") : (tool.isTriggered ? "Finding" : "Hardened")))
                                        }
                                        .font(.caption)
                                        .foregroundStyle(needsAttention ? attentionColor : Color.secondary)
                                    }
                                    Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                                }
                                if hasGate {
                                    ToolActivityStrip(counts: model.overviewActivitySlots(for: tool, now: now,
                                                      count: slotCount), now: now,
                                                      latestActivity: model.overviewLatestActivity(for: tool),
                                                      latestRecord: { slot in
                                                          model.overviewLatestRecord(for: tool, now: now,
                                                              slot: slot, count: slotCount)
                                                      })
                                        .padding(.leading, 30)
                                }
                            }.padding(.vertical, 8).contentShape(Rectangle())
                        }
                        .buttonStyle(OverviewToolButtonStyle())
                        .frame(height: 53)
                        if tool.id != visibleTools.last?.id { Divider().padding(.leading, 30) }
                    }
                    HStack {
                        Spacer()
                        if model.snapshot.hardenedTools.isEmpty {
                            Link("Learn about hardening tools →", destination: URL(string: "https://www.automicvault.com/docs/hardeners/")!)
                                .foregroundStyle(Color.accentColor)
                        } else {
                            destination(String(localized: "View all \(String(model.snapshot.hardenedTools.count)) hardened Tools →"), section: .hardenedTools)
                        }
                    }
                    .font(.caption)
                    .frame(height: 24, alignment: .bottom)
                    Spacer(minLength: 0)
                }
                .frame(maxHeight: .infinity, alignment: .top)
            }
        }
    }

    private func attention(compact: Bool) -> some View {
        VStack(alignment: .leading, spacing: compact ? 8 : 14) {
            Text(localizedUIString(model.snapshot.doctorIssues.isEmpty && model.snapshot.flaggedDetectorCount == 0 && model.scriptsNeedingReblessing.isEmpty
                 ? "No attention required" : "Attention required")).font(.headline)
            ForEach(model.scriptsNeedingReblessing) { script in
                Button {
                    model.navigateFromOverview(to: .blessedScripts, itemID: script.id)
                } label: {
                    Label("\(script.title) needs reblessing", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange).multilineTextAlignment(.leading)
                }
            }
            ForEach(model.overviewFindings) { finding in
                Button {
                    model.navigateFromOverview(to: .detectors, itemID: finding.id)
                } label: {
                    Text("\(finding.title): \(finding.subtitle)")
                        .font(.callout).foregroundStyle(.secondary)
                        .multilineTextAlignment(.leading)
                }
            }
            ForEach(model.snapshot.doctorIssues) { issue in
                Button {
                    model.navigateFromOverview(to: .doctor, itemID: issue.id)
                } label: {
                    Text(issue.message.prefix(1).uppercased() + issue.message.dropFirst()).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            Divider()
            if let version = model.availableUpdateVersion {
                Text("Update Available").font(.headline)
                ScrollView {
                    VStack(alignment: .leading, spacing: compact ? 8 : 14) {
                        AvailableReleaseNotesView(version: version)
                            .id(version)
                        Button(action: checkForUpdates) {
                            Text("Update to v\(version)…")
                        }
                        .buttonStyle(.borderedProminent)
                        .frame(maxWidth: .infinity, alignment: .center)
                    }
                }
                .frame(maxHeight: compact ? 220 : .infinity, alignment: .topLeading)
            } else {
                HStack {
                    Text("What’s new").font(.headline)
                    Spacer()
                    Link("Blog ↗", destination: URL(string: "https://www.automicvault.com/blog/")!)
                        .foregroundStyle(Color.accentColor)
                        .font(.caption)
                }
                ForEach(news.prefix(2)) { post in
                    Link(destination: post.url) {
                        Text(post.title + " ↗").font(.callout).foregroundStyle(Color.accentColor)
                            .multilineTextAlignment(.leading).lineLimit(nil)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Divider()
                if let checked = model.lastUpdateCheck {
                    Text("Last update check: \(shortDashboardTimestamp(checked))")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                } else {
                    Text("Last update check: Not yet checked")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: compact ? nil : .infinity, alignment: .topLeading)
        .fixedSize(horizontal: false, vertical: compact)
        .background(cardBackground)
    }

    private func summary(_ section: DashboardSection, value: String, caption: String, projects: Int? = nil) -> some View {
        Button {
            model.navigateFromOverview(to: section)
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: section.systemImage).foregroundStyle(Color.accentColor)
                    Spacer()
                    Text(value).font(.title2.monospacedDigit())
                }
                HStack(alignment: .firstTextBaseline) {
                    Text(localizedUIString(caption)).font(.caption).lineLimit(1)
                    Spacer(minLength: 4)
                    if let projects {
                        Text("Projects \(projects)")
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
            }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(cardBackground)
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func destination(_ title: String, section: DashboardSection) -> some View {
        Button(title) { model.navigateFromOverview(to: section) }
            .foregroundStyle(Color.accentColor).lineLimit(1)
    }
}

private struct AvailableReleaseNotesView: View {
    let version: String
    @State private var notes: String?

    var body: some View {
        Group {
            if let notes, !notes.isEmpty {
                RenderedMarkdown(markdown: notes)
                    // Release metadata must not trigger arbitrary remote image requests.
                    .markdownImageProvider(.asset)
                    .markdownInlineImageProvider(.asset)
                    .environment(\.openURL, OpenURLAction { url in
                        url.scheme == "https" ? .systemAction : .discarded
                    })
                    .markdownTextStyle { FontSize(NSFont.smallSystemFontSize) }
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if notes == nil {
                ProgressView().controlSize(.small)
            } else {
                Link("View Release Notes", destination: URL(string:
                    "https://github.com/automic-vault/automic-vault/releases/tag/"
                )!.appendingPathComponent(version))
                    .font(.caption)
            }
        }
        .task {
            let loaded = (try? await ReleaseNotes.load(version: version)) ?? ""
            guard !Task.isCancelled else { return }
            notes = loaded
        }
    }
}
