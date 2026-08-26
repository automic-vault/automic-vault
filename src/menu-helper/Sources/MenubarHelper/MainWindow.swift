import AppKit
import Darwin
import MenubarHelperCore
import Security
import SwiftUI
import UniformTypeIdentifiers

let automaticApprovalFeedbackDefaultsKey = "automaticApprovalFeedback"
let keepLauncherAccessForDetachedProcessesDefaultsKey = "keepLauncherAccessForDetachedProcesses"
private let directAccessDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/direct-secret-access.md#safer-alternatives"
)!
private let launcherBundleDocumentationURL = URL(
    string: "https://github.com/automic-vault/automic-vault/blob/main/docs/signed-cli-launchers.md"
)!

enum AutomaticApprovalFeedback: String, CaseIterable, Identifiable {
    case notification
    case menuBarFlash
    case none

    var id: Self { self }

    var title: String {
        switch self {
        case .notification: "Show Notification"
        case .none: "Show Nothing"
        case .menuBarFlash: "Flash Menu Bar"
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

    func updateDetectorFindings(_ findings: [DetectorFinding]) {
        model.updateDetectorFindings(findings)
    }

    func setAvailableUpdateVersion(_ version: String?) {
        model.availableUpdateVersion = version
    }

    func showAccessRequest(id: UUID) {
        model.showAccessRequest(id: id)
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
    @Published var selectedSection: DashboardSection = .detectors
    @Published private(set) var snapshot = DashboardSnapshot.empty
    @Published private(set) var isReloading = false
    @Published var isAddingSecret = false
    @Published var isRenamingSecret = false
    @Published var isCreatingLauncherBundle = false
    @Published private(set) var isBuildingLauncherBundle = false
    @Published var errorMessage: String?
    @Published var selectedItemID: String?
    @Published var searchText = "" {
        didSet { normalizeSelection() }
    }
    @Published private(set) var cliInstallState: CLIInstallState?
    @Published fileprivate var availableUpdateVersion: String?
    @Published private(set) var pendingBlessing: BlessedScriptReviewRequest?
    @Published private(set) var pendingBlessingLaunchers: [BlessedScriptLauncher] = []
    @Published private(set) var launcherBundles: [LauncherBundleEnrollment] = []
    @Published private(set) var pendingLauncherBundle: LauncherBundleCandidate?

    private var reloadTask: Task<Void, Never>?
    private var blessingCompletion: ((BlessedScriptReviewOutcome) -> Void)?

    init(snapshot: DashboardSnapshot = .empty, cliInstallState: CLIInstallState? = nil) {
        self.snapshot = snapshot
        self.cliInstallState = cliInstallState
        normalizeSelection()
    }

    var items: [DashboardItem] {
        items(for: selectedSection)
    }

    private var searchQuery: String {
        searchText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func items(for section: DashboardSection) -> [DashboardItem] {
        let base = switch section {
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
                        .joined(separator: "\n")
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
                let apps = $0.appPolicies.count == 1 ? "1 app" : "\($0.appPolicies.count) apps"
                return DashboardItem(
                    id: $0.id,
                    title: $0.displayName,
                    subtitle: "\(secrets) • \(apps)",
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
            snapshot.accessRequests.map {
                DashboardItem(
                    id: $0.id.uuidString,
                    title: "\($0.launcher ?? "Unknown app") used \($0.tool)",
                    subtitle: $0.decision,
                    detail: $0.reason,
                    date: $0.date
                )
            }
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
                    id: "touch-id-approval",
                    title: "Touch ID Approval",
                    subtitle: TouchIDApproval.isEnabled
                        ? "Approve on this Mac with Touch ID"
                        : "Require biometrics for Mac Approval",
                    detail: "Add an explicit biometric-only Approval surface on this Mac."
                ),
                DashboardItem(
                    id: "iphone-approval",
                    title: "iPhone Approval",
                    subtitle: PhoneApprovalCoordinator.shared.isEnabled
                        ? "All human Approvals use iPhone"
                        : "Approve away from agents on this Mac",
                    detail: "Move every human Approval for this Mac to iPhones on your iCloud Keychain account."
                ),
                DashboardItem(
                    id: "automatic-approval-feedback",
                    title: "Automic Authorization",
                    subtitle: "Choose subtle feedback or none",
                    detail: "Control visual feedback after policy authorizes an operation."
                ),
                DashboardItem(
                    id: "detached-process-access",
                    title: "Detached Processes",
                    subtitle: "Keep Launcher attribution after ancestry loss",
                    detail: "Allow an exact live process execution to retain gate-specific Launcher attribution after its parent chain exits."
                ),
                DashboardItem(
                    id: "verified-launcher-helpers",
                    title: "Verified Launcher Helpers",
                    subtitle: "Recognize signed CLIs sealed inside vendor apps",
                    detail: "Manage exact app and helper signing-identity associations."
                ),
                DashboardItem(
                    id: "gpg-signing",
                    title: "GPG Signing",
                    subtitle: "Authorize Git commit signing",
                    detail: "Store GPG signing credentials, configure Git, and select Verified Launchers that use an alternate key."
                ),
                DashboardItem(
                    id: "secret-name-access",
                    title: "Secret Name Access",
                    subtitle: "Apps allowed to run av list",
                    detail: "Manage verified apps that may list saved secret names without prompting."
                ),
                DashboardItem(
                    id: "about",
                    title: "About",
                    subtitle: "GUI environment details",
                    detail: "View details about the running Automic Vault app."
                ),
            ]
        }
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
        if let selectedItemID,
           let record = snapshot.accessRequests.first(where: { $0.id.uuidString == selectedItemID }) {
            return record
        }
        return snapshot.accessRequests.first
    }

    var selectedProxySession: ProxySessionSummary? {
        let sessions = ProxySessionViewModel.shared.sessions
        if let selectedItemID,
           let session = sessions.first(where: { $0.id.uuidString == selectedItemID }) {
            return session
        }
        return sessions.first
    }

    func count(for section: DashboardSection) -> Int {
        guard searchQuery.isEmpty else { return items(for: section).count }
        return switch section {
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
        selectedSection = section
        selectedItemID = nil
        normalizeSelection()
    }

    func select(_ item: DashboardItem) {
        selectedItemID = item.id
    }

    func showAccessRequest(id: UUID, records: [AccessRequestRecord] = loadAccessRequestRecords()) {
        snapshot.accessRequests = records
        guard snapshot.accessRequests.contains(where: { $0.id == id }) else { return }
        selectedSection = .secretUsage
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
        guard let request = pendingBlessing else { return }
        let declaration = request.declaration
        let script = BlessedScript(
            path: request.path,
            checksum: declaration.checksum,
            keys: declaration.keys,
            target: declaration.target,
            replaceExistingEnv: declaration.replaceExistingEnv,
            allowMissingKeys: declaration.allowMissingKeys,
            allowsCanonicalPathExecution: declaration.snapshotIncompatibleInterpreter != nil,
            capabilities: declaration.manifest.capabilities,
            launchers: pendingBlessingLaunchers,
            reviewedContents: request.scriptData
        )
        approveAuthorityChange(
            "Bless \(URL(fileURLWithPath: script.path).lastPathComponent)",
            detail: [
                "Path: \(script.path)",
                "Checksum: \(script.checksum)",
                "Target: \(script.target)",
                "Secret Names: \(script.keys.joined(separator: ", "))",
                "Access: \(script.capabilities.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value.title)" }.joined(separator: ", "))",
                "Launchers: \(script.launchers.map(\.bundleIdentifier).joined(separator: ", "))",
            ].joined(separator: "\n")
        ) { [weak self] in
            guard let self else { return }
            let status = saveBlessedScript(script)
            guard status == errSecSuccess else {
                self.errorMessage = "Could not bless script: \(status)"
                return
            }
            self.finishPendingBlessing(.approved)
            self.selectedItemID = script.path
            self.reload()
        }
    }

    func cancelPendingBlessing() {
        guard pendingBlessing != nil else { return }
        finishPendingBlessing(.denied)
    }

    func reviewChanges(to script: BlessedScript) {
        guard let previousContents = script.verifiedReviewedContents else {
            errorMessage = "The original reviewed contents are unavailable. Run `av bless` once to create a new review baseline."
            return
        }
        do {
            let scriptData = try readBlessedScript(path: script.path)
            let declaration = try blessedScriptDeclaration(data: scriptData)
            guard declaration.checksum != script.checksum else {
                reload()
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
            errorMessage = "Could not review changes: \(error.localizedDescription)"
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
                capabilities: script.capabilities,
                launchers: script.launchers + [launcher],
                blessedAt: script.blessedAt,
                reviewedContents: script.reviewedContents
            )
            self.approveAuthorityChange(
                "Add \(launcher.bundleIdentifier) to a Blessing",
                detail: [
                    "Script: \(script.path)",
                    "Checksum: \(script.checksum)",
                    "Secret Names: \(script.keys.joined(separator: ", "))",
                    "Access: \(script.capabilities.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value.title)" }.joined(separator: ", "))",
                ].joined(separator: "\n")
            ) {
                self.finishPolicyUpdate(saveBlessedScript(updated), error: "Could not add calling app")
            }
        }
    }

    func addSecretNameAccessApp() {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher else { return }
            self.approveAuthorityChange(
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
            capabilities: script.capabilities,
            launchers: launchers,
            blessedAt: script.blessedAt,
            reviewedContents: script.reviewedContents
        )
        finishPolicyUpdate(saveBlessedScript(updated), error: "Could not remove calling app")
    }

    func revoke(_ script: BlessedScript) {
        let status = removeBlessedScript(path: script.path)
        if status == errSecSuccess {
            selectedItemID = nil
            reload()
        } else {
            errorMessage = "Could not revoke blessing: \(status)"
        }
    }

    private func finishPendingBlessing(_ outcome: BlessedScriptReviewOutcome) {
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
        snapshot.accessRequests.filter { $0.tool == item.title }
    }

    func reload() {
        reloadTask?.cancel()
        isReloading = true
        reloadTask = Task {
            var (next, cliInstallState, launcherBundles) = await Task.detached(priority: .background) {
                (DashboardSnapshot.load(), currentCLIInstallState(), loadLauncherBundleEnrollments())
            }.value
            guard !Task.isCancelled else { return }
            next.detectorFindings = snapshot.detectorFindings
            snapshot = next
            self.cliInstallState = cliInstallState
            self.launcherBundles = launcherBundles
            normalizeSelection()
            isReloading = false
        }
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
                reload()
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
            errorMessage = "Could not revoke Launcher Bundle enrollment: \(status)"
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
                errorMessage = "The bundle was revoked, but could not be moved to Trash: \(error.localizedDescription)"
            }
            selectedItemID = nil
            reload()
        }
    }

    func updateDetectorFindings(_ findings: [DetectorFinding]) {
        snapshot.detectorFindings = findings
        normalizeSelection()
    }

    private func normalizeSelection() {
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
            reload()
            return true
        } else {
            errorMessage = "Could not save \(account): \(status)"
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
            reload()
            return true
        }
        errorMessage = "Could not update \(secret.account): \(status)"
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

    func addDirectAccessLauncher(_ selection: DirectAccessLauncherSelection, to secret: StoredSecret) {
        approveAuthorityChange(
            "Allow direct access to \(secret.account)",
            detail: "\(selection.launcher.bundleIdentifier) may use this Secret without future Approval."
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
            reload()
        } else {
            errorMessage = "Could not delete \(account): \(status)"
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
        reload()
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
            reload()
        } else {
            errorMessage = "Could not delete \(secret.account) Value: \(status)"
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
            reload()
            return true
        } else {
            errorMessage = "Could not rename \(account): \(status)"
            return false
        }
    }

    func installCLI() {
        do {
            try openCLIInstaller()
        } catch {
            errorMessage = "Could not open install command: \(error.localizedDescription)"
        }
    }

    func addApp(to gate: SecretGate) {
        chooseLauncher { [weak self] signing in
            guard let self, let signing else { return }
            guard let runtimeRequirement = signing.runtimeProtection.secretGateAdmissionRequirement else {
                showLauncherCannotBeAllowed(secretGateAdmissionError(
                    appName: signing.identifier,
                    protection: signing.runtimeProtection
                ))
                return
            }
            self.approveAuthorityChange(
                "Add \(signing.identifier) to \(gate.displayName)",
                detail: "Recognized read-only operations will be automically authorized."
            ) {
                let status = setSecretGateAppProtection(
                    requirement: signing.requirement,
                    protection: .readOnly,
                    for: gate,
                    runtimeRequirement: runtimeRequirement
                )
                if status == errSecSuccess {
                    self.errorMessage = nil
                    self.reload()
                } else {
                    self.errorMessage = "Could not allow \(signing.identifier): \(status)"
                }
            }
        }
    }

    func setDefaultProtection(_ protection: SecretGateProtection, for gate: SecretGate) {
        let update = { [weak self] in
            guard let self else { return }
            self.finishPolicyUpdate(
                setSecretGateDefaultProtection(protection, for: gate),
                error: "Could not update the default protection"
            )
        }
        guard protection.addsAuthority(over: gate.defaultProtection) else { update(); return }
        approveAuthorityChange(
            "Broaden \(gate.displayName) default to \(protection.title)",
            detail: protection.subtitle,
            perform: update
        )
    }

    func setProtection(_ protection: SecretGateProtection, for app: SecretGatePolicy, in gate: SecretGate) {
        let update = { [weak self] in
            guard let self else { return }
            self.finishPolicyUpdate(setSecretGateAppProtection(
                requirement: app.requirement,
                protection: protection,
                for: gate,
                runtimeRequirement: app.runtimeRequirement
            ),
            error: "Could not update \(app.bundleIdentifier)"
            )
        }
        guard protection.addsAuthority(over: app.protection) else { update(); return }
        approveAuthorityChange(
            "Broaden \(app.bundleIdentifier) to \(protection.title)",
            detail: protection.subtitle,
            perform: update
        )
    }

    func removeAppPolicy(_ app: SecretGatePolicy, from gate: SecretGate) {
        finishPolicyUpdate(
            removeSecretGateAppPolicy(app, from: gate),
            error: "Could not delete the Launcher-specific rule for \(app.bundleIdentifier)"
        )
    }

    private func finishPolicyUpdate(_ status: OSStatus, error: String) {
        if status == errSecSuccess {
            errorMessage = nil
            reload()
        } else {
            errorMessage = "\(error): \(status)"
        }
    }

    private func approveAuthorityChange(
        _ title: String,
        detail: String,
        perform: @escaping () -> Void
    ) {
        requestAuthorityChangeApproval(title: title, detail: detail) {
            if $0 { perform() }
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

private func blessedScriptStatus(_ script: BlessedScript) -> String {
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
    guard let bundledURL,
          expectedRevision != nil,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == 0,
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

func isCLIInstallCompletionURL(_ url: URL) -> Bool {
    url.scheme == "automic-vault"
        && url.host == "cli-installed"
        && url.path.isEmpty
        && url.user == nil
        && url.password == nil
        && url.port == nil
        && url.query == nil
        && url.fragment == nil
}

@MainActor
func openCLIInstaller() throws {
    guard let commandURL = Bundle.main.url(forResource: "install-av-cli", withExtension: "command"),
          FileManager.default.isExecutableFile(atPath: commandURL.path)
    else {
        throw CLIInstallerError.bundledCommandUnavailable
    }
    guard NSWorkspace.shared.open(commandURL) else {
        throw CLIInstallerError.couldNotOpenCommand
    }
}

private enum CLIInstallerError: LocalizedError {
    case bundledCommandUnavailable
    case couldNotOpenCommand

    var errorDescription: String? {
        switch self {
        case .bundledCommandUnavailable: "Bundled install command is unavailable."
        case .couldNotOpenCommand: "Could not open the install command."
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
    changedModel.reviewChanges(to: changedScript)
    guard changedModel.pendingBlessing?.scriptData == currentScriptData,
          changedModel.pendingBlessing?.previousContents == previousScriptData,
          blessedScriptDiff(previous: previousScriptData, current: currentScriptData)?.contains("- echo old") == true,
          blessedScriptDiff(previous: previousScriptData, current: currentScriptData)?.contains("+ echo current") == true
    else { return 1 }
    changedModel.cancelPendingBlessing()
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
    guard isCLIInstallCompletionURL(URL(string: "automic-vault://cli-installed")!),
          !isCLIInstallCompletionURL(URL(string: "automic-vault://cli-installed/extra")!),
          !isCLIInstallCompletionURL(URL(string: "automic-vault://cli-installed?revision=1")!),
          !isCLIInstallCompletionURL(URL(string: "https://cli-installed")!)
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
        "secret-name-access",
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
          model.selectedItem?.detail.contains("Remediation:") == true
    else { return 1 }
    model.showAccessRequest(id: accessRequest.id, records: [accessRequest])
    guard model.selectedSection == .secretUsage,
          model.selectedItemID == accessRequest.id.uuidString,
          model.selectedAccessRequest == accessRequest
    else { return 1 }
    return 0
}

enum DashboardSection: String, CaseIterable, Identifiable {
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
        case .detectors: "Detectors"
        case .doctor: "Doctor"
        case .hardenedTools: "Hardened Tools"
        case .secretGates: "Authorization Gates"
        case .blessedScripts: "Blessed Scripts"
        case .launcherBundles: "Launcher Bundles"
        case .allSecrets: "Secrets"
        case .proxySessions: "Active Proxies"
        case .secretUsage: "Authorization History"
        case .settings: "Settings"
        }
    }

    var systemImage: String {
        switch self {
        case .detectors: "sensor.tag.radiowaves.forward"
        case .doctor: "stethoscope"
        case .hardenedTools: "hammer"
        case .secretGates: "lock.shield"
        case .blessedScripts: "checkmark.seal"
        case .launcherBundles: "shippingbox"
        case .allSecrets: "key"
        case .proxySessions: "arrow.left.arrow.right.circle"
        case .secretUsage: "clock.arrow.circlepath"
        case .settings: "gearshape"
        }
    }
}

struct DashboardItem: Identifiable, Equatable {
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
        NavigationSplitView() {
            DashboardSidebarView(model: model)
                .navigationSplitViewColumnWidth(min: 186, ideal: 227, max: 250)
        } content: {
            DashboardListView(model: model)
                .navigationSplitViewColumnWidth(min: 168, ideal: 255)
                .toolbar {
                   if model.selectedSection == .allSecrets {
                        ToolbarItem {
                            Button {
                                model.isAddingSecret = true
                            } label: {
                                Image(systemName: "plus")
                            }
                            .help("Add Secret")
                        }
                    }
                    if model.selectedSection == .launcherBundles {
                        ToolbarItem {
                            Button {
                                model.isCreatingLauncherBundle = true
                            } label: {
                                Image(systemName: "plus")
                            }
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
                        Button {
                            model.addApp(to: gate)
                        } label: {
                            Image(systemName: "plus")
                        }
                        .help("Add Calling App")
                    }
                    if model.selectedSection == .blessedScripts {
                        Button {
                            if let script = model.selectedBlessedScript {
                                model.addApp(to: script)
                            }
                        } label: {
                            Image(systemName: "plus")
                        }
                        .help("Add Calling App")
                    }
                    if model.selectedSection == .settings,
                       model.selectedItem?.id == "secret-name-access" {
                        Button {
                            model.addSecretNameAccessApp()
                        } label: {
                            Image(systemName: "plus")
                        }
                        .help("Allow App to List Secret Names")
                    }
                    Button {
                        requestScan()
                        model.reload()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .help("Refresh")
                }
        }
        .searchable(text: $model.searchText, placement: .sidebar, prompt: "Search")
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
            if count > 0 {
                if section == .detectors, model.snapshot.flaggedDetectorCount > 0, model.selectedSection != .detectors {
                    DetectorCountPill(
                        count: count,
                        color: detectorSeverityLevel(model.snapshot.detectorFindings.map(\.severity)).color
                    )
                        .fixedSize()
                } else if section == .doctor, model.selectedSection != .doctor {
                    DetectorCountPill(count: count, color: .red)
                        .fixedSize()
                } else {
                    SidebarCountText(count: count)
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
                if model.isReloading {
                    ProgressView()
                        .controlSize(.large)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    EmptyListView(section: model.selectedSection)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
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

    private func rows(_ items: [DashboardItem]) -> some View {
        ForEach(items) { item in
            DashboardRow(item: item)
                .tag(item.id)
        }
    }
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
            } else if model.selectedSection == .launcherBundles,
                      let enrollment = model.selectedLauncherBundle {
                LauncherBundleDetailView(model: model, enrollment: enrollment)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .proxySessions,
                      let session = model.selectedProxySession {
                ProxySessionDetailView(session: session)
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
                } else if model.selectedItem?.id == "gpg-signing" {
                    GPGSigningSettingsView(onCredentialSaved: model.reload)
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
                    InfoBlock(title: model.selectedSection.title, text: item.detail)
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
                if let status = item.blessingStatus {
                    BlessingStatusPill(status: status)
                        .fixedSize()
                }
                if let kind = item.kind {
                    DetectorKindPill(kind: kind)
                        .fixedSize()
                }
                if item.isHardened, !item.isTriggered {
                    HardenedDetectorPill()
                        .fixedSize()
                }
                if let severity = item.severity {
                    Text(severity)
                        .font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 6)
                        .frame(height: 18)
                        .outlinedPill(detectorSeverityColor(severity))
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
        Text(emptyText)
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(.tertiary)
            .multilineTextAlignment(.center)
            .padding()
    }

    private var emptyText: String {
        switch section {
        case .detectors: "Detectors identify developer tool configurations that could expose secrets"
        case .doctor: "Doctor identifies problems with your Automic Vault installation and explains how to fix them"
        case .hardenedTools: "Hardened Tools secure developer tools with granular access to secrets"
        case .secretGates: "Authorization Gates control which operations Verified Launchers may perform through specific Tools"
        case .blessedScripts: "Blessed Scripts allow specific apps access to specific secrets and tools at defined access levels"
        case .launcherBundles: "Create a Verified Launcher from one unsigned Mach-O command-line tool"
        case .allSecrets: "Secrets are credentials stored securely in the macOS Data Protection Keychain"
        case .proxySessions: "Active `av proxy` sessions appear here while their target process is running"
        case .secretUsage: "Authorization History records requests and their authorization decisions"
        case .settings: "Settings control how Automic Vault behaves"
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

    private var records: [AccessRequestRecord] {
        let detail = "Proxy Session \(session.id.uuidString.lowercased())"
        return loadAccessRequestRecords().filter { $0.detail == detail }
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
                    text: "Already-authorized Launchers can use this new Value immediately: "
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
                Text("Allows already-approved apps to use this Secret while your Mac is locked, after the first unlock following a restart.")
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
    @State private var isConfirmingDirectAccess = false
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
                            Text(value.source == .global ? "Global Value" : escapedSecurityPath(value.source.displayName))
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
                Text("Allows already-approved apps to use this secret while your Mac is locked, after the first unlock following a restart.")
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
                    empty: "No Launchers have Direct Access to this Secret."
                ) {
                    model.removeDirectAccessLauncher($0, from: secret)
                }
                Button {
                    model.chooseDirectAccessLauncher { launcher in
                        guard let launcher else { return }
                        pendingDirectAccessLauncher = launcher
                        isConfirmingDirectAccess = true
                    }
                } label: {
                    Label("Allow Launcher…", systemImage: "app.badge.checkmark")
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
        .sheet(isPresented: $isConfirmingDirectAccess, onDismiss: {
            pendingDirectAccessLauncher = nil
        }) {
            if let selection = pendingDirectAccessLauncher {
                DirectAccessConfirmationView(
                    secretName: secret.account,
                    launcherName: selection.launcher.bundleIdentifier,
                    runtimeWarning: launcherRuntimeWarning(selection.runtimeRequirement)
                ) {
                    isConfirmingDirectAccess = false
                    model.addDirectAccessLauncher(selection, to: secret)
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
                    text: "Already-authorized Launchers can use this replacement immediately: "
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
    let confirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Label("This grants broad authority", systemImage: "exclamationmark.shield.fill")
                    .font(.headline)
                    .foregroundStyle(.orange)
                Text("The verified Launcher “\(launcherName)” will be able to apply \(secretName) to any Target and arguments it chooses through direct av inject requests.")
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
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") { confirm() }
                }
            }
        }
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
    let count: Int

    var body: some View {
        Text(count.formatted())
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
        "Auth tokens grant API access without a password. If they leak, another process can act as you until the token is revoked."
    case "credential fill", "credential oauth", "credential helpers":
        "Credential helpers can expose reusable Git credentials. A compromised helper or config can capture tokens and push or pull as you."
    case "credentials file":
        "Credentials files keep reusable keys on disk. Any process that can read them can authenticate to the linked service."
    case "legacy plugins":
        "Legacy plugins run code inside the tool. Old or writable plugins widen the path for unreviewed code execution."
    case "login cache":
        "Login caches store session material after sign-in. A readable cache can let another process reuse your cloud session."
    case "minimum release age":
        "Missing release-age protection allows brand-new packages immediately. That raises exposure to dependency hijacks and rushed malicious releases."
    case "mutable":
        "Mutable installs can be changed after installation. If an attacker edits them, future commands may run code you did not approve."
    case "persisted output", "persisted report":
        "Persisted output can leave discovered secrets in report files. Anyone with file access can recover those secrets later."
    case "plaintext secret":
        "Plaintext secrets are stored without OS-backed protection. Any local process with file access can copy and reuse them."
    case "registry credentials":
        "Registry credentials allow image pulls, pushes, or private registry access. If exposed, they can leak images or poison deployments."
    case "root access":
        "Root-equivalent access can modify system files and privileged workloads. Misuse can turn a local compromise into full host control."
    case "shell history":
        "Shell history can preserve secrets typed into commands. Those values remain readable long after the command finishes."
    case "system integrity":
        "System integrity controls protect privileged operations and trusted macOS components. Strong authentication and built-in macOS protections reduce opportunities for compromised code to gain root access or tamper with the system."
    default:
        "Sensitive local files can expose credentials or weaken a trust boundary. If another process can read or change them, it may impersonate you or run untrusted code."
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

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
                .tracking(0.7)
            Text(text)
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
                Text(referenceTitle)
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
        Text(badge.title)
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
                        capabilities: request.declaration.manifest.capabilities
                    )
                    launcherList(model.pendingBlessingLaunchers) {
                        model.removePendingBlessingLauncher($0)
                    }
                    Button {
                        model.addAppToPendingBlessing()
                    } label: {
                        Label("Add Calling App…", systemImage: "plus")
                    }
                    .buttonStyle(.bordered)
                    if request.declaration.manifest.capabilities.values.contains(.fullIncludingSecretDumps) {
                        InfoBlock(
                            title: "Full Access",
                            text: "This script requests access to operations that may reveal protected secret values."
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
            Divider()
            HStack {
                Button("Cancel", role: .cancel) { model.cancelPendingBlessing() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(request.declaration.snapshotIncompatibleInterpreter == nil ? "Bless Script" : "Bless Anyway") {
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
    let capabilities: [String: SecretGateProtection]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SecretGateField("Path", path)
            SecretGateField("SHA-256", checksum, monospaced: true)
            SecretGateField("Secrets", keys.joined(separator: ", "))
            SecretGateField(
                "Capabilities",
                capabilities.sorted(by: { $0.key < $1.key })
                    .map { "\($0.key): \($0.value.normalized(forGateID: $0.key).title)" }
                    .joined(separator: ", ")
            )
        }
    }
}

@MainActor
private func launcherList(
    _ launchers: [BlessedScriptLauncher],
    title: String = "Calling Apps",
    empty: String = "No calling apps endorsed.",
    remove: @escaping (BlessedScriptLauncher) -> Void
) -> some View {
    VStack(alignment: .leading, spacing: 10) {
        Text(title)
            .font(.system(size: 13, weight: .semibold))
        if launchers.isEmpty {
            Text(empty)
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
                Button {
                    remove(launcher)
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.plain)
                .help("Remove Launcher")
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
                Text("These verified apps may run av list without an approval window.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            launcherList(
                model.snapshot.secretNameAccessApps,
                title: "Always Allowed Apps",
                empty: "No apps are always allowed. Other apps must request approval."
            ) {
                model.removeSecretNameAccessApp($0)
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }
}

private struct IPhoneApprovalSettingsView: View {
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
                        ? "Human Approval may come from an eligible iPhone or Touch ID on this Mac."
                        : "Every human Approval for this Mac must come from an eligible iPhone.")
                    : "Keep agents with computer-use access away from their own Approval controls.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            Label(enabled ? "Enabled" : "Disabled", systemImage: enabled ? "iphone.and.arrow.forward" : "iphone.slash")
                .foregroundStyle(enabled ? .green : .secondary)
            Text(status).font(.caption).foregroundStyle(.secondary)

            InfoBlock(
                title: "Physical separation",
                text: "iPhone Mirroring and Show on Mac can expose phone controls to an agent. Disable them, or require Face ID or Touch ID in the iPhone app."
            )

            if enabled {
                Button("Disable iPhone Approval") {
                    isWorking = true
                    status = "Waiting for Approval on iPhone…"
                    PhoneApprovalCoordinator.shared.requestDisable { approved in
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

            Label(enabled ? "Enabled" : "Disabled", systemImage: "touchid")
                .foregroundStyle(enabled ? .green : .secondary)
            Text(status).font(.caption).foregroundStyle(.secondary)

            InfoBlock(
                title: "Explicit local authority",
                text: "Touch ID Approval works independently of relay availability and may coexist with iPhone Approval. It never accepts a password, Apple Watch, pointer, or keyboard action."
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
                Button("Enable Touch ID Approval") {
                    isWorking = true
                    status = PhoneApprovalCoordinator.shared.isEnabled
                        ? "Waiting for Approval on iPhone…"
                        : "Waiting for Touch ID…"
                    requestAuthorityChangeApproval(
                        title: "Enable Touch ID Approval",
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
    }
}

private struct AutomaticApprovalFeedbackSettingsView: View {
    @AppStorage(automaticApprovalFeedbackDefaultsKey)
    private var feedback = AutomaticApprovalFeedback.notification

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
            Text("Automic authorizations are recorded in Authorization History. Approval prompts and policy-denial notifications are unaffected.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct DetachedProcessAccessSettingsView: View {
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
                "Keep Launcher Access for Detached Processes",
                isOn: Binding(
                    get: { keepsLauncherAccess },
                    set: { enabled in
                        guard enabled else {
                            keepsLauncherAccess = false
                            return
                        }
                        requestAuthorityChangeApproval(
                            title: "Keep Launcher Access for Detached Processes",
                            detail: "A live process may retain Launcher authority after its verified parent chain exits."
                        ) { approved in
                            if approved { keepsLauncherAccess = true }
                        }
                    }
                )
            )
            Text("Off by default. When enabled, an exact signed process execution that participates in an automically authorized operation may continue using that Launcher’s current policy at the same Authorization Gate until the process or Automic Vault exits. New processes and other gates are not included.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            InfoBlock(
                title: "Security tradeoff",
                text: "This extends authority after the verified parent chain disappears. Intermediary processes that permit same-user code injection can pass that authority to injected code. An enrolled Launcher Bundle payload represents its own bundle without this setting."
            )
            Link("Learn about Launcher Bundles", destination: launcherBundleDocumentationURL)
                .font(.caption)
        }
    }
}

private struct VerifiedLauncherHelpersSettingsView: View {
    @State private var configuration = loadVerifiedLauncherHelperConfiguration()
    @State private var status = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Verified Launcher Helpers")
                    .font(.system(size: 24, weight: .semibold))
                Text("Allow exact vendor-signed CLIs sealed inside their vendor's app to represent that app as the Verified Launcher.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            helperRow(codexVerifiedLauncherHelper)
            Divider()
            helperRow(claudeCodeVerifiedLauncherHelper)
            InfoBlock(
                title: "Exact identities only",
                text: "Each association verifies both signing identities, binds the live helper to its on-disk executable, and confirms that exact executable is unmodified in the app's resource seal. Other bundled executables do not inherit the app's authority."
            )
            if !status.isEmpty {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func helperRow(_ helper: VerifiedLauncherHelper) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle(
                "\(helper.name) in \(helper.appName)",
                isOn: Binding(
                    get: { configuration.isEnabled(helper) },
                    set: { next in
                        guard next else {
                            persist(helper, enabled: false)
                            return
                        }
                        requestAuthorityChangeApproval(
                            title: "Enable \(helper.name) Launcher Helper",
                            detail: "Allow the exact signed \(helper.name) helper sealed inside \(helper.appName) to represent \(helper.appName) as the Verified Launcher."
                        ) { approved in
                            if approved { persist(helper, enabled: true) }
                        }
                    }
                )
            )
            Text("\(helper.helperSigningIdentifier) → \(helper.appBundleIdentifier)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
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

private struct GPGSigningSettingsView: View {
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
                text: "Run `gpg --list-secret-keys --keyid-format=long`, copy the signing key ID, then run `gpg --armor --export-secret-keys KEY_ID`. Add the complete PGP PRIVATE KEY BLOCK in the credential sheet. Automic Vault never displays a stored private key."
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
                empty: "No Launchers use the alternate key."
            ) { launcher in
                updateLaunchers(
                    configuration.alternateKeyLaunchers.filter {
                        $0.requirement != launcher.requirement
                    },
                    action: "Remove \(launcher.bundleIdentifier) from alternate GPG signing"
                )
            }

            Button("Add App…") {
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
        requestAuthorityChangeApproval(
            title: action,
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
    let privateKeyData = try runBundledGPGCommand(
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
    let output = try runBundledGPGCommand(
        arguments: ["__gpg-public-key"],
        input: Data(privateKey.utf8),
        mainExecutableURL: mainExecutableURL
    )
    guard let publicKey = String(data: output, encoding: .utf8) else {
        throw GPGSigningConfigurationError.credentialFailed("Public key is not valid UTF-8")
    }
    return publicKey
}

private func runBundledGPGCommand(
    arguments: [String],
    input inputData: Data,
    mainExecutableURL: URL?
) throws -> Data {
    let process = Process()
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
                Text("\(countLabel(gate.keyPatterns.count, "secret")) protected with \(countLabel(gate.appPolicies.count, "app override"))")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 10) {
                if gate.scriptPaths.isEmpty {
                    SecretGateField("Request", "Direct key access")
                } else {
                    SecretGateField("Scripts", gate.scriptPaths.joined(separator: ", "))
                }
                SecretGateField("Secrets", gate.keyPatterns.joined(separator: ", "))
                SecretGateField("Targets", gate.targetPaths.joined(separator: ", "))
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("App Access")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)

                VStack(spacing: 0) {
                    DefaultAppPolicyRow(gate: gate, protection: gate.defaultProtection) {
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
            Text(label.uppercased())
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
            ProtectionMenu(gate: gate, protection: app.protection, setProtection: setProtection)
                .frame(width: 132, alignment: .trailing)
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
    let setProtection: (SecretGateProtection) -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "square.stack.3d.up")
                .font(.system(size: 18))
                .frame(width: 34, height: 34)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(gate.defaultPolicyLabel)
                    .font(.system(size: 13, weight: .medium))
                Text("Requires Hardened Runtime")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            ProtectionMenu(gate: gate, protection: protection, setProtection: setProtection)
                .frame(width: 132, alignment: .trailing)
        }
        .padding(.vertical, 10)
    }
}

private struct ProtectionMenu: NSViewRepresentable {
    let gate: SecretGate
    let protection: SecretGateProtection
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
        button.setAccessibilityLabel("Protection level")
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
        let titles = gate.availableProtections.map(gate.protectionTitle)
        guard button.itemTitles != titles else { return }
        button.removeAllItems()
        for candidate in gate.availableProtections {
            button.addItem(withTitle: gate.protectionTitle(candidate))
            if #available(macOS 14.4, *) {
                button.lastItem?.subtitle = gate.protectionSubtitle(candidate)
            }
            if candidate == .fullExceptSecretDumps || candidate == .fullIncludingSecretDumps {
                let warning = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: "Warning")
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
        var parent: ProtectionMenu

        init(parent: ProtectionMenu) {
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

private struct LauncherSigning {
    let identifier: String
    let teamIdentifier: String
    let path: String
    let requirement: String
    let runtimeProtection: LauncherRuntimeProtection
}

struct DirectAccessLauncherSelection {
    let launcher: BlessedScriptLauncher
    let runtimeRequirement: LauncherRuntimeRequirement
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
        alert.messageText = "Allow \(signing.identifier)?"
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
        alert.addButton(withTitle: "Allow")
        alert.addButton(withTitle: "Cancel")
        completion(alert.runModal() == .alertFirstButtonReturn ? signing : nil)
    }
}

@MainActor
private func pickLauncher(_ completion: @escaping (LauncherSigning?) -> Void) {
    let panel = NSOpenPanel()
    panel.title = "Allow Launcher"
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
