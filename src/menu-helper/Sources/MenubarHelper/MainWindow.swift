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

struct BlessedScriptReviewRequest: Sendable {
    let path: String
    let declaration: BlessedScriptDeclaration
    let launcher: BlessedScriptLauncher?
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
        case "c":
            return NSApp.sendAction(#selector(NSText.copy(_:)), to: nil, from: self)
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
                    title: $0.id,
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
                + snapshot.blessedDotenvs.map(blessedDotenvItem)
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
        case .settings:
            [
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
        guard let id = selectedItem?.id else { return nil }
        return snapshot.blessedScripts.first { "script:\($0.path)" == id }
    }

    var selectedBlessedDotenv: BlessedDotenv? {
        guard let id = selectedItem?.id else { return nil }
        return snapshot.blessedDotenvs.first { "dotenv:\($0.id)" == id }
    }

    var selectedPendingBlessing: BlessedScriptReviewRequest? {
        guard pendingBlessing.map({ "script:\($0.path)" }) == selectedItem?.id else { return nil }
        return pendingBlessing
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

    func count(for section: DashboardSection) -> Int {
        guard searchQuery.isEmpty else { return items(for: section).count }
        return switch section {
        case .detectors: snapshot.detectorDisplayCount
        case .doctor: snapshot.doctorIssues.count
        case .hardenedTools: snapshot.hardenedTools.count
        case .secretGates: snapshot.secretGates.count
        case .blessedScripts:
            snapshot.blessedScripts.count + snapshot.blessedDotenvs.count
                + (pendingBlessing.map { pending in
                    snapshot.blessedScripts.contains { $0.path == pending.path } ? 0 : 1
                } ?? 0)
        case .launcherBundles: launcherBundles.count
        case .allSecrets: snapshot.secrets.count
        case .secretUsage: snapshot.accessRequests.count
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
        pendingBlessing = request
        let previouslyEndorsed = loadBlessedScripts()
            .first(where: { $0.path == request.path })?
            .launchers ?? []
        pendingBlessingLaunchers = launcherEndorsementsForReblessing(
            previouslyEndorsed: previouslyEndorsed,
            requestedLauncher: request.launcher
        )
        blessingCompletion = completion
        selectedSection = .blessedScripts
        selectedItemID = "script:\(request.path)"
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
            launchers: pendingBlessingLaunchers
        )
        let status = saveBlessedScript(script)
        guard status == errSecSuccess else {
            errorMessage = "Could not bless script: \(status)"
            return
        }
        finishPendingBlessing(.approved)
        selectedItemID = "script:\(script.path)"
        reload()
    }

    func cancelPendingBlessing() {
        guard pendingBlessing != nil else { return }
        finishPendingBlessing(.denied)
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
                blessedAt: script.blessedAt
            )
            self.finishPolicyUpdate(saveBlessedScript(updated), error: "Could not add calling app")
        }
    }

    func addApp(to dotenv: BlessedDotenv) {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher,
                  !dotenv.launchers.contains(where: { $0.requirement == launcher.requirement })
            else { return }
            let updated = BlessedDotenv(
                path: dotenv.path,
                checksum: dotenv.checksum,
                processes: dotenv.processes,
                launchers: dotenv.launchers + [launcher],
                blessedAt: dotenv.blessedAt
            )
            self.finishPolicyUpdate(saveBlessedDotenv(updated), error: "Could not add calling app")
        }
    }

    func addSecretNameAccessApp() {
        chooseLauncherApp { [weak self] launcher in
            guard let self, let launcher else { return }
            self.finishPolicyUpdate(
                allowSecretNameAccess(launcher),
                error: "Could not allow \(launcher.bundleIdentifier)"
            )
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
            blessedAt: script.blessedAt
        )
        finishPolicyUpdate(saveBlessedScript(updated), error: "Could not remove calling app")
    }

    func removeLauncher(_ launcher: BlessedScriptLauncher, from dotenv: BlessedDotenv) {
        let updated = BlessedDotenv(
            path: dotenv.path,
            checksum: dotenv.checksum,
            processes: dotenv.processes,
            launchers: dotenv.launchers.filter { $0.requirement != launcher.requirement },
            blessedAt: dotenv.blessedAt
        )
        finishPolicyUpdate(saveBlessedDotenv(updated), error: "Could not remove calling app")
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

    func revoke(_ dotenv: BlessedDotenv) {
        let status = removeBlessedDotenv(id: dotenv.id)
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
        finishPolicyUpdate(
            allowDirectAccess(
                to: secret.account,
                for: selection.launcher,
                runtimeRequirement: selection.runtimeRequirement
            ),
            error: "Could not allow \(selection.launcher.bundleIdentifier) to use \(secret.account)"
        )
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

    func setDefaultProtection(_ protection: SecretGateProtection, for gate: SecretGate) {
        finishPolicyUpdate(
            setSecretGateDefaultProtection(protection, for: gate),
            error: "Could not update the default protection"
        )
    }

    func setProtection(_ protection: SecretGateProtection, for app: SecretGatePolicy, in gate: SecretGate) {
        finishPolicyUpdate(
            setSecretGateAppProtection(
                requirement: app.requirement,
                protection: protection,
                for: gate,
                runtimeRequirement: app.runtimeRequirement
            ),
            error: "Could not update \(app.bundleIdentifier)"
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
    var info = stat()
    let isGone = script.path.withCString { lstat($0, &info) != 0 && errno == ENOENT }
    let currentChecksum = isGone ? nil : try? blessedScriptDeclaration(data: readBlessedScript(path: script.path)).checksum
    let status = isGone ? "Gone" : currentChecksum == script.checksum ? "Blessed" : "Changed"
    return DashboardItem(
        id: "script:\(script.path)",
        title: URL(fileURLWithPath: script.path).lastPathComponent,
        kind: "Script",
        subtitle: blessedScriptDirectory(script.path),
        detail: script.path,
        blessingStatus: status
    )
}

private func blessedScriptItems(
    _ blessed: [BlessedScript],
    pending: BlessedScriptReviewRequest?
) -> [DashboardItem] {
    let scripts = blessed.map(blessedScriptItem)
    guard let pending, !scripts.contains(where: { $0.id == "script:\(pending.path)" }) else { return scripts }
    return [
        DashboardItem(
            id: "script:\(pending.path)",
            title: URL(fileURLWithPath: pending.path).lastPathComponent,
            kind: "Script",
            subtitle: blessedScriptDirectory(pending.path),
            detail: pending.path,
            blessingStatus: "Pending review"
        )
    ] + scripts
}

private func blessedScriptDirectory(_ path: String) -> String {
    NSString(string: URL(fileURLWithPath: path).deletingLastPathComponent().path).abbreviatingWithTildeInPath
}

private func blessedDotenvItem(_ dotenv: BlessedDotenv) -> DashboardItem {
    let data = try? readBlessedScript(path: dotenv.path)
    let status = data.map(dotenvSchemaChecksum) == dotenv.checksum ? "Blessed" : "Stale"
    return DashboardItem(
        id: "dotenv:\(dotenv.id)",
        title: URL(fileURLWithPath: dotenv.path).deletingLastPathComponent().lastPathComponent,
        kind: "Dotenv",
        subtitle: status,
        detail: dotenv.path
    )
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
        secretGates: [],
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
    let appRowHeight = NSHostingView(rootView: ApprovedAppRow(
        app: appPolicy,
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
          appRowHeight < 140
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
        "automatic-approval-feedback",
        "detached-process-access",
        "secret-name-access",
        "about",
    ],
          model.selectedItemID == "automatic-approval-feedback",
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
                            if model.selectedPendingBlessing != nil {
                                model.addAppToPendingBlessing()
                            } else if let script = model.selectedBlessedScript {
                                model.addApp(to: script)
                            } else if let dotenv = model.selectedBlessedDotenv {
                                model.addApp(to: dotenv)
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
                List(selection: itemSelection) {
                    if model.selectedSection == .blessedScripts {
                        Section("Scripts") { rows(model.items.filter { $0.kind == "Script" }) }
                        Section("Dotenvs") { rows(model.items.filter { $0.kind == "Dotenv" }) }
                    } else {
                        rows(model.items)
                    }
                }
                .listStyle(.inset)
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
                      let pending = model.selectedPendingBlessing {
                BlessedScriptReviewView(model: model, request: pending)
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
            } else if model.selectedSection == .blessedScripts,
                      let dotenv = model.selectedBlessedDotenv {
                BlessedDotenvDetailView(model: model, dotenv: dotenv)
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
            } else if model.selectedSection == .settings {
                if model.selectedItem?.id == "automatic-approval-feedback" {
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
    @State private var signingKind = LauncherBundleSigningKind.adHoc
    @State private var signingIdentity: String?
    @State private var allowJIT = false
    @State private var allowUnsignedExecutableMemory = false
    @State private var disableLibraryValidation = false
    private let developerIDs = developerIDApplicationIdentities()

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
                            signingKind: signingKind,
                            signingIdentity: signingIdentity,
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

            Picker("Signing", selection: $signingKind) {
                Text("Automic Vault (Ad Hoc)").tag(LauncherBundleSigningKind.adHoc)
                Text("Developer ID").tag(LauncherBundleSigningKind.developerID)
            }
            .pickerStyle(.segmented)
            if signingKind == .developerID {
                Picker("Identity", selection: $signingIdentity) {
                    Text("Choose an identity").tag(String?.none)
                    ForEach(developerIDs, id: \.self) { Text($0).tag(Optional($0)) }
                }
                if developerIDs.isEmpty {
                    Text("No Developer ID Application identities were found.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
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
            && (signingKind == .adHoc || signingIdentity != nil)
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
            .foregroundStyle(.primary)
            .monospacedDigit()
            .padding(.horizontal, 8)
            .frame(height: 20)
            .background(color, in: Capsule())
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
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(URL(fileURLWithPath: request.path).lastPathComponent)
                    .font(.system(size: 24, weight: .semibold))
                Text("Review before granting durable script authority.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
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
            HStack {
                Button("Cancel", role: .cancel) { model.cancelPendingBlessing() }
                Spacer()
                Button(request.declaration.snapshotIncompatibleInterpreter == nil ? "Bless Script" : "Bless Anyway") {
                    model.approvePendingBlessing()
                }
                    .buttonStyle(.borderedProminent)
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
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
                Spacer()
                Button("Revoke Blessing", role: .destructive) { model.revoke(script) }
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }

    private var status: String {
        guard let data = try? readBlessedScript(path: script.path),
              let checksum = try? blessedScriptDeclaration(data: data).checksum
        else {
            return "Changed"
        }
        return checksum == script.checksum ? "Blessed" : "Changed"
    }
}

private struct BlessedDotenvDetailView: View {
    @ObservedObject var model: DashboardModel
    let dotenv: BlessedDotenv

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text(URL(fileURLWithPath: dotenv.path).deletingLastPathComponent().lastPathComponent)
                    .font(.system(size: 24, weight: .semibold))
                Text(status)
                    .font(.system(size: 13))
                    .foregroundStyle(status == "Blessed" ? .green : .orange)
            }
            VStack(alignment: .leading, spacing: 10) {
                SecretGateField("Path", dotenv.path)
                SecretGateField("SHA-256", dotenv.checksum, monospaced: true)
                SecretGateField("Secrets", declarations.map { "\($0.item) → \($0.secret)" }.joined(separator: ", "))
                ForEach(Array(dotenv.processes.enumerated()), id: \.offset) { index, process in
                    SecretGateField(
                        index == 0 ? "Entrypoint" : "Parent \(index)",
                        ([process.path] + process.arguments.dropFirst()).joined(separator: " ") + "\nwd: \(process.cwd)",
                        monospaced: true
                    )
                }
            }
            launcherList(dotenv.launchers) {
                model.removeLauncher($0, from: dotenv)
            }
            HStack {
                Spacer()
                Button("Revoke Blessing", role: .destructive) { model.revoke(dotenv) }
            }
            if let error = model.errorMessage {
                InfoBlock(title: "Error", text: error)
            }
        }
    }

    private var data: Data? { try? readBlessedScript(path: dotenv.path) }
    private var status: String { data.map(dotenvSchemaChecksum) == dotenv.checksum ? "Blessed" : "Stale" }
    private var declarations: [DotenvSecretDeclaration] {
        data.map(dotenvSchemaDeclarations) ?? []
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
                isOn: $keepsLauncherAccess
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
                Text(gate.id)
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
    let gate: SecretGate
    let setProtection: (SecretGateProtection) -> Void
    let remove: () -> Void
    @State private var isConfirmingDelete = false

    private var display: ApprovedAppDisplay {
        ApprovedAppDisplay(app)
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
            Text("This deletes the Launcher-specific rule. Future requests from this Verified Launcher at the \(gate.id) Authorization Gate will use the default \(gate.protectionTitle(gate.defaultProtection)) Access Level.")
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

    init(_ app: SecretGatePolicy) {
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
          let staticCode,
          SecStaticCodeCheckValidity(
              staticCode,
              SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode),
              nil
          ) == errSecSuccess
    else {
        return nil
    }

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
