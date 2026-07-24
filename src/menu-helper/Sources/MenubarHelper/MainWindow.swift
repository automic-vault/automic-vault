import AppKit
import Darwin
import MenubarHelperCore
import Security
import SwiftUI
import UniformTypeIdentifiers

struct BlessedScriptReviewRequest: Sendable {
    let path: String
    let declaration: BlessedScriptDeclaration
    let launcher: BlessedScriptLauncher
}

@MainActor
final class AutomicVaultMainWindowController: NSHostingController<DashboardRootView> {
    private let model = DashboardModel()

    init() {
        super.init(rootView: DashboardRootView(model: model))
    }

    @MainActor @preconcurrency required dynamic init?(coder: NSCoder) {
        super.init(coder: coder, rootView: DashboardRootView(model: model))
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

    func showAccessRequest(id: UUID) {
        model.showAccessRequest(id: id)
    }

    func showSecretGate(id: String) {
        model.showSecretGate(id: id)
    }

    func reviewBlessing(
        _ request: BlessedScriptReviewRequest,
        completion: @escaping (String?) -> Void
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
    @Published var errorMessage: String?
    @Published var selectedItemID: String?
    @Published var searchText = ""
    @Published private(set) var cliInstallState: CLIInstallState?
    @Published private(set) var pendingBlessing: BlessedScriptReviewRequest?
    @Published private(set) var pendingBlessingLaunchers: [BlessedScriptLauncher] = []

    private var reloadTask: Task<Void, Never>?
    private var detectorFindingsGeneration = 0
    private var blessingCompletion: ((String?) -> Void)?

    init(snapshot: DashboardSnapshot = .empty, cliInstallState: CLIInstallState? = nil) {
        self.snapshot = snapshot
        self.cliInstallState = cliInstallState
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
                        "Calling apps: \($0.appPolicies.map(\.bundleIdentifier).joined(separator: ", "))",
                    ].joined(separator: "\n")
                )
            }
        case .blessedScripts:
            blessedScriptItems(snapshot.blessedScripts, pending: pendingBlessing)
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
        }
        let query = searchQuery
        guard !query.isEmpty else { return base }
        return base.filter {
            $0.title.localizedCaseInsensitiveContains(query)
                || $0.kind?.localizedCaseInsensitiveContains(query) == true
                || $0.subtitle.localizedCaseInsensitiveContains(query)
                || $0.detail.localizedCaseInsensitiveContains(query)
        }
    }

    var selectedItem: DashboardItem? {
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

    var selectedPendingBlessing: BlessedScriptReviewRequest? {
        guard pendingBlessing?.path == selectedItem?.id else { return nil }
        return pendingBlessing
    }

    var selectedStoredSecret: StoredSecret? {
        if let selectedItemID,
           let secret = snapshot.secrets.first(where: { $0.account == selectedItemID }) {
            return secret
        }
        return snapshot.secrets.first
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
            snapshot.blessedScripts.count
                + (pendingBlessing.map { pending in
                    snapshot.blessedScripts.contains { $0.path == pending.path } ? 0 : 1
                } ?? 0)
        case .allSecrets: snapshot.secrets.count
        case .secretUsage: snapshot.accessRequests.count
        }
    }

    func selectSection(_ section: DashboardSection) {
        selectedSection = section
        selectedItemID = nil
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

    func reviewBlessing(
        _ request: BlessedScriptReviewRequest,
        completion: @escaping (String?) -> Void
    ) {
        guard pendingBlessing == nil else {
            completion("another script blessing is already awaiting review")
            return
        }
        pendingBlessing = request
        pendingBlessingLaunchers = [request.launcher]
        blessingCompletion = completion
        selectedSection = .blessedScripts
        selectedItemID = request.path
    }

    func approvePendingBlessing() {
        guard let request = pendingBlessing, !pendingBlessingLaunchers.isEmpty else { return }
        let declaration = request.declaration
        let script = BlessedScript(
            path: request.path,
            checksum: declaration.checksum,
            keys: declaration.keys,
            target: declaration.target,
            replaceExistingEnv: declaration.replaceExistingEnv,
            allowMissingKeys: declaration.allowMissingKeys,
            capabilities: declaration.manifest.capabilities,
            launchers: pendingBlessingLaunchers
        )
        let status = saveBlessedScript(script)
        guard status == errSecSuccess else {
            errorMessage = "Could not bless script: \(status)"
            return
        }
        finishPendingBlessing(nil)
        selectedItemID = script.path
        reload()
    }

    func cancelPendingBlessing() {
        guard pendingBlessing != nil else { return }
        finishPendingBlessing("script blessing was cancelled")
    }

    func addAppToPendingBlessing() {
        guard let launcher = chooseLauncherApp(),
              !pendingBlessingLaunchers.contains(where: { $0.requirement == launcher.requirement })
        else { return }
        pendingBlessingLaunchers.append(launcher)
    }

    func removePendingBlessingLauncher(_ launcher: BlessedScriptLauncher) {
        pendingBlessingLaunchers.removeAll { $0.requirement == launcher.requirement }
    }

    func addApp(to script: BlessedScript) {
        guard let launcher = chooseLauncherApp(),
              !script.launchers.contains(where: { $0.requirement == launcher.requirement })
        else { return }
        let updated = BlessedScript(
            path: script.path,
            checksum: script.checksum,
            keys: script.keys,
            target: script.target,
            replaceExistingEnv: script.replaceExistingEnv,
            allowMissingKeys: script.allowMissingKeys,
            capabilities: script.capabilities,
            launchers: script.launchers + [launcher],
            blessedAt: script.blessedAt
        )
        finishPolicyUpdate(saveBlessedScript(updated), error: "Could not add calling app")
    }

    func removeLauncher(_ launcher: BlessedScriptLauncher, from script: BlessedScript) {
        let launchers = script.launchers.filter { $0.requirement != launcher.requirement }
        guard !launchers.isEmpty else {
            errorMessage = "A blessed script must allow at least one calling app."
            return
        }
        let updated = BlessedScript(
            path: script.path,
            checksum: script.checksum,
            keys: script.keys,
            target: script.target,
            replaceExistingEnv: script.replaceExistingEnv,
            allowMissingKeys: script.allowMissingKeys,
            capabilities: script.capabilities,
            launchers: launchers,
            blessedAt: script.blessedAt
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

    private func finishPendingBlessing(_ error: String?) {
        let completion = blessingCompletion
        blessingCompletion = nil
        pendingBlessing = nil
        pendingBlessingLaunchers = []
        completion?(error)
    }

    private func chooseLauncherApp() -> BlessedScriptLauncher? {
        let panel = NSOpenPanel()
        panel.title = "Allow Calling App"
        panel.prompt = "Allow"
        panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        panel.allowedContentTypes = [.applicationBundle]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url, url.pathExtension == "app",
              let signing = appBundleSigning(url)
        else {
            return nil
        }
        return BlessedScriptLauncher(
            bundleIdentifier: Bundle(url: url)?.bundleIdentifier ?? url.lastPathComponent,
            requirement: signing.requirement
        )
    }

    func accessRequests(for item: DashboardItem) -> [AccessRequestRecord] {
        snapshot.accessRequests.filter { $0.tool == item.title }
    }

    func reload() {
        reloadTask?.cancel()
        isReloading = true
        let findingsGeneration = detectorFindingsGeneration
        reloadTask = Task {
            var (next, cliInstallState) = await Task.detached(priority: .background) {
                (DashboardSnapshot.load(), currentCLIInstallState())
            }.value
            guard !Task.isCancelled else { return }
            if findingsGeneration != detectorFindingsGeneration {
                next.detectorFindings = snapshot.detectorFindings
            }
            snapshot = next
            self.cliInstallState = cliInstallState
            if selectedItemID.map({ id in !items.contains { $0.id == id } }) == true {
                selectedItemID = nil
            }
            isReloading = false
        }
    }

    func updateDetectorFindings(_ findings: [DetectorFinding]) {
        detectorFindingsGeneration += 1
        snapshot.detectorFindings = findings
        if selectedItemID.map({ id in !items.contains { $0.id == id } }) == true {
            selectedItemID = nil
        }
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

    func deleteSelectedSecret() {
        guard selectedSection == .allSecrets, let account = selectedItem?.id else { return }
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
            errorMessage = "Could not create install command: \(error.localizedDescription)"
        }
    }

    func addApp(to gate: SecretGate) {
        let panel = NSOpenPanel()
        panel.title = "Allow Calling App"
        panel.prompt = "Allow"
        panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        panel.allowedContentTypes = [.applicationBundle]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard url.pathExtension == "app" else {
            errorMessage = "Choose a .app bundle."
            return
        }
        guard let requirement = appBundleSigning(url)?.requirement else {
            errorMessage = "Could not read code signing identity for \(url.lastPathComponent)."
            return
        }
        let status = setSecretGateAppProtection(requirement: requirement, protection: .readOnly, for: gate)
        if status == errSecSuccess {
            errorMessage = nil
            reload()
        } else {
            errorMessage = "Could not allow \(url.lastPathComponent): \(status)"
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
            setSecretGateAppProtection(requirement: app.requirement, protection: protection, for: gate),
            error: "Could not update \(app.bundleIdentifier)"
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
    let currentChecksum = try? blessedScriptDeclaration(data: readBlessedScript(path: script.path)).checksum
    let status = currentChecksum == script.checksum ? "Blessed" : "Changed"
    return DashboardItem(
        id: script.path,
        title: URL(fileURLWithPath: script.path).lastPathComponent,
        subtitle: status,
        detail: script.path
    )
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
            subtitle: "Pending review",
            detail: pending.path
        )
    ] + scripts
}

private func detectorSeveritySortPriority(_ severity: String?) -> Int {
    severity.map(isMediumDetectorSeverity) == true ? 1 : 0
}

private let installedAVCLIPath = "/usr/local/bin/av"

enum CLIInstallState: Sendable {
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

private func installCLICommand(bundleAVPath: String) -> String {
    """
    #!/bin/sh
    trap 'status=$?; set +x; printf '\\''\\nPress Return to close this window.'\\''; read _; exit "$status"' 0
    set -e
    set -x
    bundle_av=\(shellQuoted(bundleAVPath))
    sudo install "$bundle_av" \(installedAVCLIPath)
    /usr/bin/open -g -b com.automicvault 'automic-vault://cli-installed' || printf '%s\n' 'Installed av, but could not notify Automic Vault.' >&2
    """
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
    guard let bundledAVURL else {
        throw CLIInstallerError.bundledExecutableUnavailable
    }
    let commandURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("install-av-cli-\(UUID().uuidString)")
        .appendingPathExtension("command")
    try installCLICommand(bundleAVPath: bundledAVURL.path)
        .write(to: commandURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: commandURL.path)
    guard NSWorkspace.shared.open(commandURL) else {
        throw CLIInstallerError.couldNotOpenCommand
    }
}

private enum CLIInstallerError: LocalizedError {
    case bundledExecutableUnavailable
    case couldNotOpenCommand

    var errorDescription: String? {
        switch self {
        case .bundledExecutableUnavailable: "Bundled av executable is unavailable."
        case .couldNotOpenCommand: "Could not open the install command."
        }
    }
}

private func shellQuoted(_ value: String) -> String {
    "'\(value.replacingOccurrences(of: "'", with: "'\"'\"'"))'"
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
            StoredSecret(account: "AWS_TOKEN", accessibility: .afterFirstUnlock),
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
        setProtection: { _ in }
    ).frame(width: 500)).fittingSize.height
    let secretDetailHeight = model.selectedStoredSecret.map {
        NSHostingView(rootView: StoredSecretDetailView(model: model, secret: $0)).fittingSize.height
    }
    guard DashboardSection.allCases.last == .doctor,
          model.count(for: .detectors) == 3,
          model.count(for: .doctor) == 1,
          model.count(for: .hardenedTools) == 2,
          model.count(for: .allSecrets) == 2,
          model.count(for: .secretUsage) == 1,
          model.selectedStoredSecret?.accessibility == .afterFirstUnlock,
          gateHeight > 0,
          secretDetailHeight.map({ $0 > 0 }) == true,
          appRowHeight < 140
    else { return 1 }
    guard model.items.first(where: { $0.id == "aws" })?.isHardened == true,
          model.items.first(where: { $0.id == "git" })?.isHardened == false
    else { return 1 }
    guard model.items.first(where: { $0.id == "aws" })?.subtitle == "Hardened.",
          model.items.first(where: { $0.id == "gh" })?.subtitle == "Hardener available.",
          model.items.first(where: { $0.id == "git" })?.subtitle == "Detector only."
    else { return 1 }
    model.searchText = "aws"
    guard model.count(for: .detectors) == 1,
          model.count(for: .doctor) == 1,
          model.count(for: .hardenedTools) == 1,
          model.count(for: .allSecrets) == 1
    else { return 1 }
    let cliInstallCommand = installCLICommand(bundleAVPath: "/tmp/Automic Vault.app/Contents/MacOS/av")
    guard shellQuoted("/tmp/Automic Vault's av") == "'/tmp/Automic Vault'\"'\"'s av'",
          !cliInstallCommand.contains("launchctl"),
          let installRange = cliInstallCommand.range(of: "sudo install \"$bundle_av\" /usr/local/bin/av"),
          let notificationRange = cliInstallCommand.range(of: "/usr/bin/open -g -b com.automicvault 'automic-vault://cli-installed'"),
          installRange.lowerBound < notificationRange.lowerBound,
          isCLIInstallCompletionURL(URL(string: "automic-vault://cli-installed")!),
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
    model.searchText = ""
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
    case allSecrets
    case secretUsage
    case doctor

    var id: String { rawValue }

    var title: String {
        switch self {
        case .detectors: "Detectors"
        case .doctor: "Doctor"
        case .hardenedTools: "Hardened Tools"
        case .secretGates: "Secret Gates"
        case .blessedScripts: "Blessed Scripts"
        case .allSecrets: "Secrets"
        case .secretUsage: "Secret Usage"
        }
    }

    var systemImage: String {
        switch self {
        case .detectors: "sensor.tag.radiowaves.forward"
        case .doctor: "stethoscope"
        case .hardenedTools: "hammer"
        case .secretGates: "lock.shield"
        case .blessedScripts: "checkmark.seal"
        case .allSecrets: "key"
        case .secretUsage: "clock.arrow.circlepath"
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
    let isTriggered: Bool
    let isHardened: Bool
    let date: Date?

    init(id: String, title: String, kind: String? = nil, subtitle: String, detail: String, documentation: String = "", hardenerDocumentation: String? = nil, severity: String? = nil, isTriggered: Bool = false, isHardened: Bool = false, date: Date? = nil) {
        self.id = id
        self.title = title
        self.kind = kind
        self.subtitle = subtitle
        self.detail = detail
        self.documentation = documentation
        self.hardenerDocumentation = hardenerDocumentation
        self.severity = severity
        self.isTriggered = isTriggered
        self.isHardened = isHardened
        self.date = date
    }
}

struct DashboardRootView: View {
    @ObservedObject var model: DashboardModel

    var body: some View {
        NavigationSplitView() {
            DashboardSidebarView(model: model)
                .navigationSplitViewColumnWidth(min: 186, ideal: 215, max: 250)
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
                }
                .scrollEdgeEffectStyle(.soft, for: .top) // doesn't work :(
        } detail: {
            DashboardDetailView(model: model)
                .navigationSplitViewColumnWidth(min: 320, ideal: 320)
                .toolbar {
                    Spacer()
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
                            }
                        } label: {
                            Image(systemName: "plus")
                        }
                        .help("Add Calling App")
                    }
                    Button {
                        model.reload()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .help("Refresh")
                }
        }
        .searchable(text: $model.searchText, placement: .sidebar, prompt: "Search")
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
        Group {
            if model.items.isEmpty && !model.isReloading {
                EmptyListView(section: model.selectedSection)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: itemSelection) {
                    rows(model.items)
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
            model.selectedItem?.id
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
            } else if model.selectedSection == .secretUsage, let record = model.selectedAccessRequest {
                SecretUsageDetailView(record: record)
                    .padding(.horizontal, 22)
                    .padding(.top, 32)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if model.selectedSection == .detectors, let item = model.selectedItem {
                ReferenceDetailView(
                    item: item,
                    summary: detectorSummary(for: item),
                    referenceTitle: "Detector Reference",
                    fallbackDocumentation: "No detector documentation is bundled for this item.",
                    badge: item.isTriggered
                        ? ReferenceBadge(title: "Flagged", color: detectorSeverityColor(item.severity))
                        : ReferenceBadge(title: "No Vulnerabilities Detected", color: .green)
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
            if let account = model.selectedItem?.id {
                RenameSecretView(model: model, account: account)
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
    }

    private var emptyText: String {
        switch section {
        case .detectors: "No flagged detectors"
        case .doctor: "No doctor issues"
        case .hardenedTools: "No hardened tools"
        case .secretGates: "No configured gates"
        case .blessedScripts: "No blessed scripts"
        case .allSecrets: "No stored secrets"
        case .secretUsage: "No secret usage logged"
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
            Toggle("Available While Locked", isOn: $isAvailableWhileLocked)
                .toggleStyle(.switch)
            Text("Allows already-approved apps to use this secret while your Mac is locked, after the first unlock following a restart.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
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
                text: "Secret value is hidden.\n\(secret.subtitle)"
            )

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

            HStack {
                Button { model.isRenamingSecret = true } label: {
                    Label("Rename Secret", systemImage: "pencil")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                Button { model.deleteSelectedSecret() } label: {
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
    }

    private var availabilityBinding: Binding<Bool> {
        Binding {
            isAvailableWhileLocked
        } set: { isAvailable in
            let previous = isAvailableWhileLocked
            isAvailableWhileLocked = isAvailable
            let accessibility: StoredSecretAccessibility = isAvailable
                ? .afterFirstUnlock
                : .whenUnlocked
            if !model.setAccessibility(accessibility, for: secret) {
                isAvailableWhileLocked = previous
            }
        }
    }
}

private struct RenameSecretView: View {
    @ObservedObject var model: DashboardModel
    @State private var account: String
    @Environment(\.dismiss) private var dismiss

    init(model: DashboardModel, account: String) {
        self.model = model
        _account = State(initialValue: account)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Rename Secret")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(.primary)
            TextField("Name", text: $account)
                .textFieldStyle(.roundedBorder)
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
        "System Integrity Protection prevents even root processes from modifying protected macOS components. Disabling any part of it weakens a machine-wide security boundary."
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
                        .lineLimit(3)
                    referenceBadge
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
                Text("No access requests logged for this tool.")
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

private struct SecretUsageDetailView: View {
    let record: AccessRequestRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Secret Usage")
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
                Text(record.command.isEmpty ? record.target : record.command)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                Text(record.reason)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 3) {
                    AccessMetaLine("Launcher", record.launcher ?? "unknown")
                    AccessMetaLine("Approved by", record.approvalSourceLabel)
                    AccessMetaLine("Keys", record.keys.isEmpty ? "(none)" : record.keys.joined(separator: ", "))
                    AccessMetaLine("Caller", record.callerPath)
                    AccessMetaLine("Target", record.target)
                    AccessMetaLine("Working directory", record.cwd)
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
        case "Auto": .cyan
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
            HStack {
                Button("Cancel", role: .cancel) { model.cancelPendingBlessing() }
                Spacer()
                Button("Bless Script") { model.approvePendingBlessing() }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.pendingBlessingLaunchers.isEmpty)
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
                    .map { "\($0.key): \($0.value.title)" }
                    .joined(separator: ", ")
            )
        }
    }
}

@MainActor
private func launcherList(
    _ launchers: [BlessedScriptLauncher],
    remove: @escaping (BlessedScriptLauncher) -> Void
) -> some View {
    VStack(alignment: .leading, spacing: 10) {
        Text("Calling Apps")
            .font(.system(size: 13, weight: .semibold))
        ForEach(launchers, id: \.requirement) { launcher in
            HStack {
                Text(launcher.bundleIdentifier)
                    .textSelection(.enabled)
                Spacer()
                Button {
                    remove(launcher)
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.plain)
                .help("Remove Calling App")
            }
            .padding(10)
            .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
        }
    }
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
                            setProtection: { model.setProtection($0, for: app, in: gate) }
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
                Text("Default protection")
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
            button.lastItem?.subtitle = gate.protectionSubtitle(candidate)
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
        if let signing = url.flatMap(appBundleSigning) {
            signingSummary = "Team \(signing.teamIdentifier)"
        } else {
            signingSummary = "Signing identity unavailable"
        }
    }
}

private struct AppBundleSigning {
    let teamIdentifier: String
    let requirement: String
}

private func appBundleSigning(_ url: URL) -> AppBundleSigning? {
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
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
    guard let requirementText = requirementText(requirement) else {
        return nil
    }
    return AppBundleSigning(
        teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier] as? String ?? "unknown",
        requirement: requirementText
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
