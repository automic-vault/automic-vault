import CryptoKit
import Darwin
import Foundation
import Security

public let automicVaultKeychainService = "com.automicvault.isotope"
public let secretGatePoliciesKeychainService = "com.automicvault.gate-policies"
public let secretGatePoliciesKeychainAccount = "SecretGatePoliciesV2"
public let secretNameAccessKeychainService = "com.automicvault.secret-name-access"
public let secretNameAccessKeychainAccount = "SecretNameAccessV1"
public let directAccessKeychainService = "com.automicvault.direct-secret-access"
public let directAccessKeychainAccount = "DirectAccessRulesV1"
public let accessRequestLogDefaultsKey = "AccessRequestLog"
public let accessRequestLogKeychainService = "com.automicvault.access-log"
private let accessRequestLogLock = NSLock()
private let canonicalKeychainAccessGroup = "ZU76A67LGU.com.automicvault"

public struct DashboardSnapshot: Equatable, Sendable {
    public var detectors: [DetectorMetadata]
    public var detectorFindings: [DetectorFinding]
    public var hardenedTools: [HardenedTool]
    public var hardeners: [HardenerMetadata]
    public var secretGates: [SecretGate]
    public var blessedScripts: [BlessedScript]
    public var secretNameAccessApps: [BlessedScriptLauncher]
    public var secrets: [StoredSecret]
    public var accessRequests: [AccessRequestRecord]
    public var doctorIssues: [DoctorIssue]

    public init(
        detectors: [DetectorMetadata],
        detectorFindings: [DetectorFinding],
        hardenedTools: [HardenedTool],
        hardeners: [HardenerMetadata] = [],
        secretGates: [SecretGate],
        blessedScripts: [BlessedScript] = [],
        secretNameAccessApps: [BlessedScriptLauncher] = [],
        secrets: [StoredSecret],
        accessRequests: [AccessRequestRecord] = [],
        doctorIssues: [DoctorIssue] = []
    ) {
        self.detectors = detectors
        self.detectorFindings = detectorFindings
        self.hardenedTools = hardenedTools
        self.hardeners = hardeners
        self.secretGates = secretGates
        self.blessedScripts = blessedScripts
        self.secretNameAccessApps = secretNameAccessApps
        self.secrets = secrets
        self.accessRequests = accessRequests
        self.doctorIssues = doctorIssues
    }

    public static let empty = DashboardSnapshot(
        detectors: [],
        detectorFindings: [],
        hardenedTools: [],
        hardeners: [],
        secretGates: [],
        blessedScripts: [],
        secretNameAccessApps: [],
        secrets: [],
        accessRequests: [],
        doctorIssues: []
    )

    public var flaggedDetectorCount: Int {
        Set(detectorFindings.map(\.source)).count
    }

    public var detectorDisplayCount: Int {
        flaggedDetectorCount == 0 ? detectors.count : flaggedDetectorCount
    }

    public static func load(
        avExecutableURL: URL = defaultAVExecutableURL(),
        stubDirectory: URL = URL(fileURLWithPath: "/usr/local/bin", isDirectory: true),
        ghCLIURL: URL? = URL(fileURLWithPath: "/opt/homebrew/opt/gh-cli/bin/gh"),
        policyService: String = secretGatePoliciesKeychainService
    ) -> DashboardSnapshot {
        let hardenerMetadata = loadHardenerMetadata(avExecutableURL: avExecutableURL)
        _ = initializeSecretGatePolicies(hardeners: hardenerMetadata, service: policyService)
        let hardenedTools = loadHardenedTools(
            in: stubDirectory,
            ghCLIURL: ghCLIURL,
            metadata: hardenerMetadata
        )
        let secrets = loadStoredSecrets(directAccessRules: loadDirectAccessRules())
        return DashboardSnapshot(
            detectors: loadDetectorMetadata(avExecutableURL: avExecutableURL),
            detectorFindings: scanDetectorFindings(avExecutableURL: avExecutableURL),
            hardenedTools: hardenedTools,
            hardeners: hardenerMetadata,
            secretGates: loadSecretGates(hardeners: hardenerMetadata, service: policyService),
            blessedScripts: loadBlessedScripts(),
            secretNameAccessApps: loadSecretNameAccessApps(),
            secrets: secrets,
            accessRequests: loadAccessRequestRecords(),
            doctorIssues: loadDoctorIssues(avExecutableURL: avExecutableURL)
        )
    }
}

public struct DoctorIssue: Equatable, Sendable, Identifiable {
    public let hardener: String
    public let kind: String
    public let command: String?
    public let message: String
    public let remediation: String
    public let stubPath: String?
    public let targetPath: String?
    public let resolvedPath: String?

    public var id: String {
        [hardener, command, kind, message, stubPath, targetPath, resolvedPath]
            .compactMap(\.self)
            .joined(separator: "\u{1f}")
    }

    public init(
        hardener: String,
        kind: String,
        command: String? = nil,
        message: String,
        remediation: String,
        stubPath: String? = nil,
        targetPath: String? = nil,
        resolvedPath: String? = nil
    ) {
        self.hardener = hardener
        self.kind = kind
        self.command = command
        self.message = message
        self.remediation = remediation
        self.stubPath = stubPath
        self.targetPath = targetPath
        self.resolvedPath = resolvedPath
    }
}

public struct DetectorMetadata: Codable, Equatable, Sendable {
    public let name: String
    public let homepage: String
    public let docsURL: String
    public let documentation: String

    public var displayName: DetectorDisplayName {
        detectorDisplayName(name)
    }

    public init(name: String, homepage: String, docsURL: String, documentation: String = "") {
        self.name = name
        self.homepage = homepage
        self.docsURL = docsURL
        self.documentation = documentation
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.homepage = try container.decode(String.self, forKey: .homepage)
        self.docsURL = try container.decode(String.self, forKey: .docsURL)
        self.documentation = try container.decodeIfPresent(String.self, forKey: .documentation) ?? ""
    }

    enum CodingKeys: String, CodingKey {
        case name
        case homepage
        case docsURL = "docs_url"
        case documentation
    }
}

public struct DetectorDisplayName: Equatable, Sendable {
    public let packageName: String
    public let kind: String?

    public init(packageName: String, kind: String? = nil) {
        self.packageName = packageName
        self.kind = kind
    }
}

public func detectorDisplayName(_ name: String) -> DetectorDisplayName {
    splitDetectorDisplayNames[name] ?? DetectorDisplayName(packageName: name, kind: "plaintext secret")
}

private let splitDetectorDisplayNames: [String: DetectorDisplayName] = [
    "aws-cli-credentials-file": DetectorDisplayName(packageName: "aws-cli", kind: "credentials file"),
    "aws-cli-legacy-plugins": DetectorDisplayName(packageName: "aws-cli", kind: "legacy plugins"),
    "aws-cli-login-cache": DetectorDisplayName(packageName: "aws-cli", kind: "login cache"),
    "cariddi-persisted-output": DetectorDisplayName(packageName: "cariddi", kind: "persisted output"),
    "cariddi-shell-history": DetectorDisplayName(packageName: "cariddi", kind: "shell history"),
    "docker-credential-helpers": DetectorDisplayName(packageName: "docker", kind: "credential helpers"),
    "docker-registry-credentials": DetectorDisplayName(packageName: "docker", kind: "registry credentials"),
    "docker-root-access": DetectorDisplayName(packageName: "docker", kind: "root access"),
    "gh-cli-hosts-token": DetectorDisplayName(packageName: "gh-cli", kind: "hosts token"),
    "gh-cli-keychain-access": DetectorDisplayName(packageName: "gh-cli", kind: "keychain access"),
    "git-credential-fill": DetectorDisplayName(packageName: "git", kind: "credential fill"),
    "git-credential-oauth": DetectorDisplayName(packageName: "git", kind: "credential oauth"),
    "git-credentials-file": DetectorDisplayName(packageName: "git", kind: "credentials file"),
    "homebrew": DetectorDisplayName(packageName: "homebrew", kind: "mutable"),
    "pnpm-auth-token": DetectorDisplayName(packageName: "pnpm", kind: "auth token"),
    "pnpm-minimum-release-age": DetectorDisplayName(packageName: "pnpm", kind: "minimum release age"),
    "secretlint-persisted-report": DetectorDisplayName(packageName: "secretlint", kind: "persisted report"),
    "secretlint-shell-history": DetectorDisplayName(packageName: "secretlint", kind: "shell history"),
    "sip": DetectorDisplayName(packageName: "SIP", kind: "system integrity"),
    "sudo": DetectorDisplayName(packageName: "sudo", kind: "system integrity"),
]

public struct DetectorFinding: Codable, Equatable, Sendable {
    public let source: String
    public let severity: String
    public let homepage: String?
    public let explanation: String?
    public let solution: String?
    public let affected: [AffectedFile]
    public let docsURL: String?

    enum CodingKeys: String, CodingKey {
        case source
        case severity
        case homepage
        case explanation
        case solution
        case affected
        case docsURL = "docs_url"
    }
}

public struct AffectedFile: Codable, Equatable, Sendable {
    public let path: String
    public let line: Int?
}

public struct HardenedTool: Equatable, Sendable {
    public let name: String
    public let stubPath: String?
    public let targetPath: String?
    public let documentation: String

    public init(name: String, stubPath: String? = nil, targetPath: String?, documentation: String = "") {
        self.name = name
        self.stubPath = stubPath
        self.targetPath = targetPath
        self.documentation = documentation
    }
}

public struct HardenerMetadata: Codable, Equatable, Sendable {
    public let name: String
    public let documentation: String
    public let hardened: Bool
    public let stubPath: String?
    public let targetPath: String?
    public let secretGate: SecretGateDescriptor?

    public init(
        name: String,
        documentation: String = "",
        hardened: Bool = false,
        stubPath: String? = nil,
        targetPath: String? = nil,
        secretGate: SecretGateDescriptor? = nil
    ) {
        self.name = name
        self.documentation = documentation
        self.hardened = hardened
        self.stubPath = stubPath
        self.targetPath = targetPath
        self.secretGate = secretGate
    }

    enum CodingKeys: String, CodingKey {
        case name
        case documentation
        case hardened
        case stubPath = "stub_path"
        case targetPath = "target_path"
        case secretGate = "secret_gate"
    }
}

public struct SecretGateDescriptor: Codable, Equatable, Sendable {
    public let id: String
    public let keyPatterns: [String]
    public let routes: [SecretGateRoute]

    public init(id: String, keyPatterns: [String], routes: [SecretGateRoute]) {
        self.id = id
        self.keyPatterns = keyPatterns
        self.routes = routes
    }

    enum CodingKeys: String, CodingKey {
        case id
        case keyPatterns = "key_patterns"
        case routes
    }
}

public struct SecretGateRoute: Codable, Equatable, Sendable {
    public let operation: String
    public let scriptPath: String?
    public let targetPath: String
    public let callerIdentifiers: [String]
    public let keyPatterns: [String]
    public let replaceExistingEnv: Bool
    public let allowMissingKeys: Bool

    public init(
        operation: String,
        scriptPath: String?,
        targetPath: String,
        callerIdentifiers: [String],
        keyPatterns: [String],
        replaceExistingEnv: Bool,
        allowMissingKeys: Bool
    ) {
        self.operation = operation
        self.scriptPath = scriptPath
        self.targetPath = targetPath
        self.callerIdentifiers = callerIdentifiers
        self.keyPatterns = keyPatterns
        self.replaceExistingEnv = replaceExistingEnv
        self.allowMissingKeys = allowMissingKeys
    }

    enum CodingKeys: String, CodingKey {
        case operation
        case scriptPath = "script_path"
        case targetPath = "target_path"
        case callerIdentifiers = "caller_identifiers"
        case keyPatterns = "key_patterns"
        case replaceExistingEnv = "replace_existing_env"
        case allowMissingKeys = "allow_missing_keys"
    }
}

public enum SecretGateProtection: String, Codable, CaseIterable, Identifiable, Sendable {
    case noAccess
    case readOnly
    case readOnlyAndLocalWrites
    case readOnlyAndUpdates
    case fullExceptSecretDumps
    case fullIncludingSecretDumps

    public var id: String { rawValue }

    public func normalized(forGateID gateID: String) -> Self {
        gateID == "brew" && self == .readOnly ? .readOnlyAndUpdates : self
    }

    public var title: String {
        switch self {
        case .noAccess: "Approval Required"
        case .readOnly: "Read Only"
        case .readOnlyAndLocalWrites: "Local Write"
        case .readOnlyAndUpdates: "Read & Update"
        case .fullExceptSecretDumps: "Write Access"
        case .fullIncludingSecretDumps: "Full Access"
        }
    }

    public var subtitle: String {
        switch self {
        case .noAccess: "Every operation requires approval"
        case .readOnly: "Recognized read-only operations are automically authorized"
        case .readOnlyAndLocalWrites:
            "Recognized read-only and local-write operations are automically authorized"
        case .readOnlyAndUpdates:
            "Recognized read-only operations and `brew update` are automically authorized; installs and upgrades require approval"
        case .fullExceptSecretDumps:
            "Recognized read and write operations are automically authorized; sensitive secret operations require approval"
        case .fullIncludingSecretDumps:
            "Every recognized operation is automically authorized; unknown operations require approval"
        }
    }

    public func allows(_ classification: SecretGateRequestClassification) -> Bool {
        switch self {
        case .noAccess:
            false
        case .readOnly:
            classification == .readOnly
        case .readOnlyAndLocalWrites:
            classification == .readOnly || classification == .localWrite
        case .readOnlyAndUpdates:
            classification == .readOnly || classification == .update
        case .fullExceptSecretDumps:
            classification != .secretDump && classification != .unknown
        case .fullIncludingSecretDumps:
            classification != .unknown
        }
    }
}

public enum SecretGateRequestClassification: CaseIterable, Sendable {
    case readOnly
    case localWrite
    case update
    case mutating
    case secretDump
    case unknown
}

public struct SecretGatePolicy: Equatable, Sendable {
    public let bundleIdentifier: String
    public let requirement: String
    public let protection: SecretGateProtection
    public let runtimeRequirement: LauncherRuntimeRequirement

    public var requiresHardenedRuntime: Bool { runtimeRequirement != .legacyUnchecked }

    public init(
        bundleIdentifier: String,
        requirement: String,
        protection: SecretGateProtection,
        requiresHardenedRuntime: Bool = false
    ) {
        self.init(
            bundleIdentifier: bundleIdentifier,
            requirement: requirement,
            protection: protection,
            runtimeRequirement: requiresHardenedRuntime ? .hardened : .legacyUnchecked
        )
    }

    public init(
        bundleIdentifier: String,
        requirement: String,
        protection: SecretGateProtection,
        runtimeRequirement: LauncherRuntimeRequirement
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.requirement = requirement
        self.protection = protection
        self.runtimeRequirement = runtimeRequirement
    }
}

public enum LauncherRuntimeProtection: Equatable, Sendable {
    case hardened
    case hardenedWithLibraryValidationDisabled
    case hardenedRuntimeMissing
    case unsafeEntitlements([String])

    public var secretGateAdmissionRequirement: LauncherRuntimeRequirement? {
        switch self {
        case .hardened:
            .hardened
        case .hardenedWithLibraryValidationDisabled:
            .hardenedAllowingLibraryValidationDisabled
        case .hardenedRuntimeMissing, .unsafeEntitlements:
            nil
        }
    }

    public var allowsSecretGateAccess: Bool { secretGateAdmissionRequirement != nil }
}

public enum LauncherRuntimeRequirement: String, Codable, Equatable, Sendable {
    case legacyUnchecked
    case hardened
    case hardenedAllowingLibraryValidationDisabled

    public func allows(_ protection: LauncherRuntimeProtection) -> Bool {
        switch self {
        case .legacyUnchecked:
            true
        case .hardened:
            protection == .hardened
        case .hardenedAllowingLibraryValidationDisabled:
            protection == .hardened || protection == .hardenedWithLibraryValidationDisabled
        }
    }
}

private let libraryValidationEntitlement = "com.apple.security.cs.disable-library-validation"

private let blockedLauncherRuntimeEntitlements: Set<String> = [
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.get-task-allow",
]

public func launcherRuntimeProtection(
    signatureFlags: UInt32,
    enabledEntitlements: Set<String>
) -> LauncherRuntimeProtection {
    guard signatureFlags & SecCodeSignatureFlags.runtime.rawValue != 0 else {
        return .hardenedRuntimeMissing
    }
    let blocked = enabledEntitlements.intersection(blockedLauncherRuntimeEntitlements)
    if !blocked.isEmpty {
        let relevant = blocked.union(
            enabledEntitlements.contains(libraryValidationEntitlement)
                ? [libraryValidationEntitlement]
                : []
        )
        return .unsafeEntitlements(relevant.sorted())
    }
    return enabledEntitlements.contains(libraryValidationEntitlement)
        ? .hardenedWithLibraryValidationDisabled
        : .hardened
}

public func launcherRuntimeProtection(
    signingInformation: [CFString: Any]
) -> LauncherRuntimeProtection {
    let signatureFlags = (signingInformation[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
    let entitlements = signingInformation[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
    let enabledEntitlements = Set(entitlements.compactMap { key, value in
        (value as? NSNumber)?.boolValue == true ? key : nil
    })
    return launcherRuntimeProtection(
        signatureFlags: signatureFlags,
        enabledEntitlements: enabledEntitlements
    )
}

public struct SecretGate: Equatable, Identifiable, Sendable {
    public let id: String
    public let keyPatterns: [String]
    public let routes: [SecretGateRoute]
    public let defaultProtection: SecretGateProtection
    public let appPolicies: [SecretGatePolicy]

    public init(
        id: String,
        keyPatterns: [String],
        routes: [SecretGateRoute],
        defaultProtection: SecretGateProtection,
        appPolicies: [SecretGatePolicy]
    ) {
        self.id = id
        self.keyPatterns = keyPatterns
        self.routes = routes
        self.defaultProtection = defaultProtection
        self.appPolicies = appPolicies
    }

    public var scriptPaths: [String] { routes.compactMap(\.scriptPath).uniqueSorted() }
    public var targetPaths: [String] { routes.map(\.targetPath).uniqueSorted() }
    public var defaultPolicyLabel: String { appPolicies.isEmpty ? "All Apps" : "All Other Apps" }

    public var availableProtections: [SecretGateProtection] {
        if id == "brew" {
            return [.noAccess, .readOnlyAndUpdates, .fullExceptSecretDumps]
        }
        if keyPatterns.isEmpty {
            return [.noAccess, .readOnly, .fullExceptSecretDumps]
        }
        if id == "gh" {
            return [
                .noAccess,
                .readOnly,
                .readOnlyAndLocalWrites,
                .fullExceptSecretDumps,
                .fullIncludingSecretDumps,
            ]
        }
        return [.noAccess, .readOnly, .fullExceptSecretDumps, .fullIncludingSecretDumps]
    }

    public var initialProtection: SecretGateProtection {
        id == "brew" ? .readOnlyAndUpdates : .readOnly
    }

    public func normalizedProtection(_ protection: SecretGateProtection) -> SecretGateProtection {
        var protection = protection
        if keyPatterns.isEmpty, protection == .fullIncludingSecretDumps {
            protection = .fullExceptSecretDumps
        }
        if id != "gh", protection == .readOnlyAndLocalWrites {
            protection = .readOnly
        }
        if !keyPatterns.isEmpty, protection == .readOnlyAndUpdates {
            protection = .readOnly
        }
        return protection.normalized(forGateID: id)
    }

    public func protectionTitle(_ protection: SecretGateProtection) -> String {
        let protection = normalizedProtection(protection)
        return keyPatterns.isEmpty && protection == .fullExceptSecretDumps ? "Full Access" : protection.title
    }

    public func protectionSubtitle(_ protection: SecretGateProtection) -> String {
        let protection = normalizedProtection(protection)
        return keyPatterns.isEmpty && protection == .fullExceptSecretDumps
            ? "Every recognized operation is automically authorized; unknown operations require approval"
            : protection.subtitle
    }
}

public enum StoredSecretAccessibility: Equatable, Sendable {
    case whenUnlocked
    case afterFirstUnlock

    public var isAvailableWhileLocked: Bool {
        self == .afterFirstUnlock
    }

    fileprivate var keychainValue: CFString {
        switch self {
        case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
        }
    }

    fileprivate init(keychainValue: Any?) {
        self = keychainValue as? String == kSecAttrAccessibleAfterFirstUnlock as String
            ? .afterFirstUnlock
            : .whenUnlocked
    }
}

public struct StoredSecret: Equatable, Sendable {
    public let account: String
    public let accessibility: StoredSecretAccessibility
    public let keychainProperties: [String]
    public let directAccessLaunchers: [BlessedScriptLauncher]

    public init(
        account: String,
        accessibility: StoredSecretAccessibility = .whenUnlocked,
        keychainProperties: [String] = [],
        directAccessLaunchers: [BlessedScriptLauncher] = []
    ) {
        self.account = account
        self.accessibility = accessibility
        self.keychainProperties = keychainProperties
        self.directAccessLaunchers = directAccessLaunchers
    }

    public var subtitle: String {
        keychainProperties.isEmpty ? "Keychain secret" : keychainProperties.joined(separator: " • ")
    }
}

public struct AccessRequestRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let date: Date
    public let tool: String
    public let command: String
    public let decision: String
    public let approvalSource: String?
    public let reason: String
    public let launcher: String?
    public let callerPath: String
    public let target: String
    public let cwd: String
    public let keys: [String]
    public let detail: String?

    public init(
        id: UUID = UUID(),
        date: Date,
        tool: String,
        command: String,
        decision: String,
        approvalSource: String? = nil,
        reason: String,
        launcher: String?,
        callerPath: String,
        target: String,
        cwd: String,
        keys: [String],
        detail: String?
    ) {
        self.id = id
        self.date = date
        self.tool = tool
        self.command = command
        self.decision = decision
        self.approvalSource = approvalSource
        self.reason = reason
        self.launcher = launcher
        self.callerPath = callerPath
        self.target = target
        self.cwd = cwd
        self.keys = keys
        self.detail = detail
    }

    public var approvalSourceLabel: String {
        if let approvalSource, !approvalSource.isEmpty {
            return switch approvalSource.lowercased() {
            case "auto", "automatic", "policy": "Policy"
            case "manual", "human": "Human"
            default: approvalSource
            }
        }
        if reason.localizedCaseInsensitiveContains("auto") || reason.localizedCaseInsensitiveContains("reused") {
            return "Policy"
        }
        if reason.localizedCaseInsensitiveContains("prompt") {
            return "Human"
        }
        return "Unknown"
    }
}

struct ScanReport: Codable {
    let findings: [DetectorFinding]
}

struct DetectorReport: Codable {
    let detectors: [DetectorMetadata]
}

struct HardenerReport: Codable {
    let hardeners: [HardenerMetadata]
}

private struct DoctorReport: Codable {
    let results: [DoctorResult]
}

private struct DoctorResult: Codable {
    let name: String
    let issues: [WireDoctorIssue]
}

private struct WireDoctorIssue: Codable {
    let kind: String
    let command: String?
    let message: String
    let remediation: String
    let stubPath: String?
    let targetPath: String?
    let resolvedPath: String?

    enum CodingKeys: String, CodingKey {
        case kind
        case command
        case message
        case remediation
        case stubPath = "stub_path"
        case targetPath = "target_path"
        case resolvedPath = "resolved_path"
    }
}

public func detectorFindings(from scanJSON: Data) throws -> [DetectorFinding] {
    try JSONDecoder().decode(ScanReport.self, from: scanJSON).findings
}

public func detectorMetadata(from detectorsJSON: Data) throws -> [DetectorMetadata] {
    try JSONDecoder().decode(DetectorReport.self, from: detectorsJSON).detectors
}

public func hardenerMetadata(from hardenersJSON: Data) throws -> [HardenerMetadata] {
    try JSONDecoder().decode(HardenerReport.self, from: hardenersJSON).hardeners
}

public func doctorIssues(from doctorJSON: Data, loginShellPATHAvailable: Bool = true) throws -> [DoctorIssue] {
    var issues = try JSONDecoder().decode(DoctorReport.self, from: doctorJSON).results.flatMap { result in
        result.issues.map {
            DoctorIssue(
                hardener: result.name,
                kind: $0.kind,
                command: $0.command,
                message: $0.message,
                remediation: $0.remediation,
                stubPath: $0.stubPath,
                targetPath: $0.targetPath,
                resolvedPath: $0.resolvedPath
            )
        }
    }
    guard !loginShellPATHAvailable else { return issues }
    issues.removeAll { $0.kind == "stub_not_first_on_path" }
    issues.append(DoctorIssue(
        hardener: "PATH",
        kind: "login_shell_path_unavailable",
        message: "Unable to inspect the login-shell PATH",
        remediation: "Ensure the configured login shell starts successfully, then refresh Doctor."
    ))
    return issues
}

public func hardenerNameReferencedByDocumentation(_ documentation: String) -> String? {
    guard let range = documentation.range(
        of: #"av[ \t\r\n]+harden[ \t\r\n]+[A-Za-z0-9_-]+"#,
        options: .regularExpression
    ) else {
        return nil
    }
    return documentation[range].split(whereSeparator: \.isWhitespace).last.map(String.init)
}

public func loadHardenedTools(
    in directory: URL,
    ghCLIURL: URL? = URL(fileURLWithPath: "/opt/homebrew/opt/gh-cli/bin/gh"),
    metadata: [HardenerMetadata] = []
) -> [HardenedTool] {
    _ = directory
    _ = ghCLIURL
    return metadata.filter(\.hardened).map {
        HardenedTool(
            name: $0.name,
            stubPath: $0.stubPath,
            targetPath: $0.targetPath,
            documentation: $0.documentation
        )
    }
        .uniquedByName()
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
}

public func loadSecretGates(
    hardeners: [HardenerMetadata] = [],
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> [SecretGate] {
    let loadedRecords = loadSecretGatePolicyRecords(service: service, account: account)
    let records: [SecretGatePolicyRecord] = switch loadedRecords {
    case .success(let records): records
    case .failure: []
    }
    let policiesAreReadable = if case .success = loadedRecords { true } else { false }
    return hardeners.compactMap { hardener -> SecretGate? in
        guard let descriptor = hardener.secretGate,
              hardener.hardened || descriptor.routes
                .compactMap(\.scriptPath)
                .contains(where: FileManager.default.fileExists(atPath:))
        else { return nil }
        let gateRecords = records.filter { $0.gateID == descriptor.id }
        let prototype = SecretGate(
            id: descriptor.id,
            keyPatterns: descriptor.keyPatterns.uniqueSorted(),
            routes: descriptor.routes,
            defaultProtection: .noAccess,
            appPolicies: []
        )
        return SecretGate(
            id: prototype.id,
            keyPatterns: prototype.keyPatterns,
            routes: prototype.routes,
            defaultProtection: prototype.normalizedProtection(
                gateRecords.last(where: { $0.requirement == nil })?.protection
                    ?? (policiesAreReadable ? prototype.initialProtection : .noAccess)
            ),
            appPolicies: gateRecords.compactMap { record in
                record.requirement.map {
                    SecretGatePolicy(
                        bundleIdentifier: appIdentifier(from: $0) ?? "unknown",
                        requirement: $0,
                        protection: prototype.normalizedProtection(record.protection),
                        runtimeRequirement: record.resolvedRuntimeRequirement
                    )
                }
            }.uniqueSorted()
        )
    }
    .sorted { $0.id.localizedStandardCompare($1.id) == .orderedAscending }
}

public func normalizedExecutablePath(_ path: String) -> String {
    normalizedExecutablePath(path) {
        try? FileManager.default.destinationOfSymbolicLink(atPath: $0)
    }
}

func normalizedExecutablePath(_ path: String, symlinkDestination: (String) -> String?) -> String {
    let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
    if let path = normalizedHomebrewCellarExecutablePath(standardized) {
        return path
    }

    let url = URL(fileURLWithPath: standardized)
    guard url.deletingLastPathComponent().path == "/opt/homebrew/bin",
          let destination = symlinkDestination(standardized)
    else {
        return standardized
    }

    let resolved = destination.hasPrefix("/")
        ? URL(fileURLWithPath: destination).standardizedFileURL.path
        : url.deletingLastPathComponent().appendingPathComponent(destination).standardizedFileURL.path
    guard resolved != standardized else { return standardized }
    return normalizedExecutablePath(resolved, symlinkDestination: symlinkDestination)
}

private func normalizedHomebrewCellarExecutablePath(_ path: String) -> String? {
    let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
    guard components.count == 8,
          components[0] == "/",
          components[1] == "opt",
          components[2] == "homebrew",
          components[3] == "Cellar",
          components[6] == "bin"
    else {
        return nil
    }
    return "/opt/homebrew/opt/\(components[4])/bin/\(components[7])"
}

public func setSecretGateDefaultProtection(
    _ protection: SecretGateProtection,
    for gate: SecretGate,
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    let protection = gate.normalizedProtection(protection)
    return setSecretGatePolicyRecord(
        SecretGatePolicyRecord(gateID: gate.id, requirement: nil, protection: protection),
        service: service,
        account: account
    )
}

public func setSecretGateAppProtection(
    requirement: String,
    protection: SecretGateProtection,
    for gate: SecretGate,
    requiresHardenedRuntime: Bool = true,
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    setSecretGateAppProtection(
        requirement: requirement,
        protection: protection,
        for: gate,
        runtimeRequirement: requiresHardenedRuntime ? .hardened : .legacyUnchecked,
        service: service,
        account: account
    )
}

public func setSecretGateAppProtection(
    requirement: String,
    protection: SecretGateProtection,
    for gate: SecretGate,
    runtimeRequirement: LauncherRuntimeRequirement,
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    let protection = gate.normalizedProtection(protection)
    return setSecretGatePolicyRecord(
        SecretGatePolicyRecord(
            gateID: gate.id,
            requirement: requirement,
            protection: protection,
            runtimeRequirement: runtimeRequirement
        ),
        service: service,
        account: account
    )
}

public func removeSecretGateAppPolicy(
    _ policy: SecretGatePolicy,
    from gate: SecretGate,
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    let loaded: [SecretGatePolicyRecord]
    switch loadSecretGatePolicyRecords(service: service, account: account) {
    case .success(let records): loaded = records
    case .failure(let status): return status
    }
    let records = loaded.filter {
        !($0.gateID == gate.id && $0.requirement == policy.requirement)
    }
    return saveSecretGatePolicyRecords(records, service: service, account: account)
}

public func secretGateProtection(
    for requirement: String?,
    in gate: SecretGate
) -> (protection: SecretGateProtection, source: String) {
    if let requirement, let policy = gate.appPolicies.first(where: { $0.requirement == requirement }) {
        return (policy.protection, policy.bundleIdentifier)
    }
    return (gate.defaultProtection, gate.defaultPolicyLabel)
}

private struct SecretGatePolicyRecord: Codable, Equatable {
    let gateID: String
    let requirement: String?
    let protection: SecretGateProtection
    let requiresHardenedRuntime: Bool?
    let runtimeRequirement: LauncherRuntimeRequirement?

    var resolvedRuntimeRequirement: LauncherRuntimeRequirement {
        runtimeRequirement ?? (requiresHardenedRuntime == true ? .hardened : .legacyUnchecked)
    }

    init(
        gateID: String,
        requirement: String?,
        protection: SecretGateProtection,
        runtimeRequirement: LauncherRuntimeRequirement? = nil
    ) {
        self.gateID = gateID
        self.requirement = requirement
        self.protection = protection
        self.requiresHardenedRuntime = runtimeRequirement.map { $0 != .legacyUnchecked }
        self.runtimeRequirement = runtimeRequirement
    }
}

private enum SecretGatePolicyRecordsLoad {
    case success([SecretGatePolicyRecord])
    case failure(OSStatus)
}

private func loadSecretGatePolicyRecords(
    service: String,
    account: String
) -> SecretGatePolicyRecordsLoad {
    let data: Data
    switch loadKeychainDataResult(service: service, account: account) {
    case .success(let loaded): data = loaded
    case .notFound: return .success([])
    case .failure(let status): return .failure(status)
    }
    do {
        return .success(try JSONDecoder().decode([SecretGatePolicyRecord].self, from: data))
    } catch {
        return .failure(errSecDecode)
    }
}

@discardableResult
public func initializeSecretGatePolicies(
    hardeners: [HardenerMetadata],
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    var records: [SecretGatePolicyRecord]
    switch loadSecretGatePolicyRecords(service: service, account: account) {
    case .success(let loaded): records = loaded
    case .failure(let status): return status
    }
    let gates = loadSecretGates(hardeners: hardeners, service: service, account: account)
    for gate in gates where !records.contains(where: { $0.gateID == gate.id && $0.requirement == nil }) {
        records.append(SecretGatePolicyRecord(
            gateID: gate.id,
            requirement: nil,
            protection: gate.initialProtection
        ))
    }
    return saveSecretGatePolicyRecords(records, service: service, account: account)
}

private func saveSecretGatePolicyRecords(
    _ records: [SecretGatePolicyRecord],
    service: String,
    account: String
) -> OSStatus {
    if records.isEmpty {
        let status = deleteStoredSecret(account: account, service: service)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
    do {
        let sorted = records.sorted {
            [$0.gateID, $0.requirement ?? ""].joined(separator: "\u{1f}")
                .localizedStandardCompare([$1.gateID, $1.requirement ?? ""].joined(separator: "\u{1f}")) == .orderedAscending
        }
        return saveKeychainData(
            try JSONEncoder().encode(sorted),
            service: service,
            account: account,
            accessibility: .afterFirstUnlock
        )
    } catch {
        return errSecParam
    }
}

private func setSecretGatePolicyRecord(
    _ record: SecretGatePolicyRecord,
    service: String,
    account: String
) -> OSStatus {
    var records: [SecretGatePolicyRecord]
    switch loadSecretGatePolicyRecords(service: service, account: account) {
    case .success(let loaded): records = loaded
    case .failure(let status): return status
    }
    records.removeAll { $0.gateID == record.gateID && $0.requirement == record.requirement }
    records.append(record)
    return saveSecretGatePolicyRecords(records, service: service, account: account)
}

public func loadSecretNameAccessApps(
    service: String = secretNameAccessKeychainService,
    account: String = secretNameAccessKeychainAccount
) -> [BlessedScriptLauncher] {
    guard case .success(let apps) = loadSecretNameAccessAppsResult(service: service, account: account)
    else { return [] }
    return apps.sorted { $0.bundleIdentifier.localizedStandardCompare($1.bundleIdentifier) == .orderedAscending }
}

public func allowSecretNameAccess(
    _ app: BlessedScriptLauncher,
    service: String = secretNameAccessKeychainService,
    account: String = secretNameAccessKeychainAccount
) -> OSStatus {
    var apps: [BlessedScriptLauncher]
    switch loadSecretNameAccessAppsResult(service: service, account: account) {
    case .success(let loaded): apps = loaded
    case .failure(let status): return status
    }
    apps.removeAll { $0.requirement == app.requirement }
    apps.append(app)
    return saveSecretNameAccessApps(apps, service: service, account: account)
}

public func removeSecretNameAccess(
    _ app: BlessedScriptLauncher,
    service: String = secretNameAccessKeychainService,
    account: String = secretNameAccessKeychainAccount
) -> OSStatus {
    let apps: [BlessedScriptLauncher]
    switch loadSecretNameAccessAppsResult(service: service, account: account) {
    case .success(let loaded): apps = loaded
    case .failure(let status): return status
    }
    return saveSecretNameAccessApps(
        apps.filter { $0.requirement != app.requirement },
        service: service,
        account: account
    )
}

private enum SecretNameAccessAppsLoad {
    case success([BlessedScriptLauncher])
    case failure(OSStatus)
}

private func loadSecretNameAccessAppsResult(
    service: String,
    account: String
) -> SecretNameAccessAppsLoad {
    switch loadKeychainDataResult(service: service, account: account) {
    case .notFound:
        return .success([])
    case .failure(let status):
        return .failure(status)
    case .success(let data):
        guard let apps = try? JSONDecoder().decode([BlessedScriptLauncher].self, from: data)
        else { return .failure(errSecDecode) }
        return .success(apps)
    }
}

private func saveSecretNameAccessApps(
    _ apps: [BlessedScriptLauncher],
    service: String,
    account: String
) -> OSStatus {
    if apps.isEmpty {
        let status = deleteStoredSecret(account: account, service: service)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
    guard let data = try? JSONEncoder().encode(apps.sorted {
        $0.bundleIdentifier.localizedStandardCompare($1.bundleIdentifier) == .orderedAscending
    }) else { return errSecParam }
    return saveKeychainData(
        data,
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    )
}

public func loadAccessRequestRecords(
    defaults: UserDefaults? = nil,
    key: String = accessRequestLogDefaultsKey,
    service: String = accessRequestLogKeychainService
) -> [AccessRequestRecord] {
    if let defaults {
        return decodeAccessRequestRecords(defaults.data(forKey: key))
    }
    switch loadKeychainDataResult(service: service, account: key) {
    case .success(let data):
        return decodeAccessRequestRecords(data)
    case .failure:
        return []
    case .notFound:
        let legacy = decodeAccessRequestRecords(UserDefaults.standard.data(forKey: key))
        guard !legacy.isEmpty,
              let data = try? JSONEncoder().encode(legacy),
              saveKeychainData(
                  data,
                  service: service,
                  account: key,
                  accessibility: .afterFirstUnlock
              ) == errSecSuccess
        else { return legacy }
        UserDefaults.standard.removeObject(forKey: key)
        _ = UserDefaults.standard.synchronize()
        return legacy
    }
}

private func decodeAccessRequestRecords(_ data: Data?) -> [AccessRequestRecord] {
    guard let data,
          let records = try? JSONDecoder().decode([AccessRequestRecord].self, from: data)
    else {
        return []
    }
    return Array(records.prefix(50))
}

@discardableResult
public func appendAccessRequestRecord(
    _ record: AccessRequestRecord,
    defaults: UserDefaults? = nil,
    key: String = accessRequestLogDefaultsKey,
    service: String = accessRequestLogKeychainService
) -> Bool {
    accessRequestLogLock.lock()
    defer { accessRequestLogLock.unlock() }
    let records = Array(
        ([record] + loadAccessRequestRecords(defaults: defaults, key: key, service: service)).prefix(50)
    )
    guard let data = try? JSONEncoder().encode(records) else { return false }
    if let defaults {
        defaults.set(data, forKey: key)
        guard defaults.synchronize() else { return false }
    } else {
        guard saveKeychainData(
            data,
            service: service,
            account: key,
            accessibility: .afterFirstUnlock
        ) == errSecSuccess else {
            return false
        }
    }
    return loadAccessRequestRecords(defaults: defaults, key: key, service: service).first?.id == record.id
}

public func loadStoredSecrets(
    service: String = automicVaultKeychainService,
    directAccessRules: [DirectAccessRule] = []
) -> [StoredSecret] {
    let directAccess = Dictionary(grouping: directAccessRules, by: \.secretName)
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    addCanonicalAccessGroup(to: &query)
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let items = result as? [[String: Any]]
    else {
        return []
    }
    return items.compactMap { item in
        guard let account = item[kSecAttrAccount as String] as? String else { return nil }
        return StoredSecret(
            account: account,
            accessibility: StoredSecretAccessibility(
                keychainValue: item[kSecAttrAccessible as String]
            ),
            keychainProperties: keychainProperties(for: item, dataProtection: true),
            directAccessLaunchers: (directAccess[account] ?? [])
                .map(\.launcher)
                .sorted {
                    $0.bundleIdentifier.localizedStandardCompare($1.bundleIdentifier) == .orderedAscending
                }
        )
    }
    .sorted { $0.account.localizedStandardCompare($1.account) == .orderedAscending }
}

public func storedSecretExists(account: String, service: String = automicVaultKeychainService) -> Bool {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    addCanonicalAccessGroup(to: &query)
    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
}

private func keychainProperties(for item: [String: Any], dataProtection: Bool) -> [String] {
    [
        dataProtection ? "Data Protection Enabled" : nil,
        isSynchronizable(item[kSecAttrSynchronizable as String]) ? "iCloud On" : "iCloud Off",
        accessibleLabel(item[kSecAttrAccessible as String]),
    ].compactMap(\.self)
}

private func isSynchronizable(_ value: Any?) -> Bool {
    if let value = value as? Bool {
        return value
    }
    if let value = value as? NSNumber {
        return value.boolValue
    }
    return false
}

private func accessibleLabel(_ value: Any?) -> String? {
    guard let value = value as? String else { return nil }
    let whenUnlocked = kSecAttrAccessibleWhenUnlocked as String
    let afterFirstUnlock = kSecAttrAccessibleAfterFirstUnlock as String
    let passcodeSetThisDeviceOnly = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String
    let whenUnlockedThisDeviceOnly = kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
    let afterFirstUnlockThisDeviceOnly = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
    return switch value {
    case whenUnlocked:
        "When Unlocked"
    case afterFirstUnlock:
        "After First Unlock"
    case passcodeSetThisDeviceOnly:
        "Passcode Set, This Device Only"
    case whenUnlockedThisDeviceOnly:
        "When Unlocked, This Device Only"
    case afterFirstUnlockThisDeviceOnly:
        "After First Unlock, This Device Only"
    default:
        nil
    }
}

public func saveStoredSecret(
    account: String,
    value: String,
    accessibility: StoredSecretAccessibility = .whenUnlocked,
    service: String = automicVaultKeychainService
) -> OSStatus {
    saveKeychainData(
        Data(value.utf8),
        service: service,
        account: account,
        accessibility: accessibility
    )
}

public func saveStoredSecretIfAbsentOrEqual(
    account: String,
    value: String,
    service: String = automicVaultKeychainService
) -> OSStatus {
    saveKeychainDataIfAbsentOrEqual(
        Data(value.utf8),
        service: service,
        account: account
    )
}

public func setStoredSecretAccessibility(
    account: String,
    accessibility: StoredSecretAccessibility,
    service: String = automicVaultKeychainService
) -> OSStatus {
    setKeychainAccessibility(accessibility, service: service, account: account)
}

public func renameStoredSecret(account: String, to newAccount: String, service: String = automicVaultKeychainService) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    return SecItemUpdate(query as CFDictionary, [kSecAttrAccount as String: newAccount] as CFDictionary)
}

public func renameStoredSecretRevokingDirectAccess(
    account: String,
    to newAccount: String,
    service: String = automicVaultKeychainService,
    directAccessService: String = directAccessKeychainService,
    directAccessAccount: String = directAccessKeychainAccount
) -> OSStatus {
    let status = revokeDirectAccess(
        to: account,
        service: directAccessService,
        account: directAccessAccount
    )
    guard status == errSecSuccess else { return status }
    return renameStoredSecret(account: account, to: newAccount, service: service)
}

public func deleteStoredSecret(account: String, service: String = automicVaultKeychainService) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    return SecItemDelete(query as CFDictionary)
}

public func deleteStoredSecretRevokingDirectAccess(
    account: String,
    service: String = automicVaultKeychainService,
    directAccessService: String = directAccessKeychainService,
    directAccessAccount: String = directAccessKeychainAccount
) -> OSStatus {
    let status = revokeDirectAccess(
        to: account,
        service: directAccessService,
        account: directAccessAccount
    )
    guard status == errSecSuccess else { return status }
    return deleteStoredSecret(account: account, service: service)
}

public func loadStoredSecret(account: String, service: String = automicVaultKeychainService) -> String? {
    guard let data = loadKeychainData(service: service, account: account) else { return nil }
    return String(data: data, encoding: .utf8)
}

private func loadKeychainData(service: String, account: String) -> Data? {
    guard case .success(let data) = loadKeychainDataResult(service: service, account: account) else {
        return nil
    }
    return data
}

enum KeychainDataLoad {
    case success(Data)
    case notFound
    case failure(OSStatus)
}

func loadKeychainDataResult(service: String, account: String) -> KeychainDataLoad {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnData as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return .notFound }
    guard status == errSecSuccess, let data = result as? Data else { return .failure(status) }
    return .success(data)
}

@discardableResult
public func migrateBackgroundKeychainItems(
    policyService: String = secretGatePoliciesKeychainService,
    policyAccount: String = secretGatePoliciesKeychainAccount,
    accessLogService: String = accessRequestLogKeychainService,
    accessLogAccount: String = accessRequestLogDefaultsKey,
    secretNameAccessService: String = secretNameAccessKeychainService,
    secretNameAccessAccount: String = secretNameAccessKeychainAccount,
    directAccessService: String = directAccessKeychainService,
    directAccessAccount: String = directAccessKeychainAccount
) -> OSStatus {
    for (service, account) in [
        (policyService, policyAccount),
        (accessLogService, accessLogAccount),
        (secretNameAccessService, secretNameAccessAccount),
        (directAccessService, directAccessAccount),
    ] {
        let status = setKeychainAccessibility(.afterFirstUnlock, service: service, account: account)
        if status != errSecSuccess && status != errSecItemNotFound {
            return status
        }
    }
    return errSecSuccess
}

public struct DirectAccessRule: Codable, Equatable, Sendable {
    public let secretName: String
    public let launcher: BlessedScriptLauncher
    public let runtimeRequirement: LauncherRuntimeRequirement

    public init(
        secretName: String,
        launcher: BlessedScriptLauncher,
        runtimeRequirement: LauncherRuntimeRequirement = .hardened
    ) {
        self.secretName = secretName
        self.launcher = launcher
        self.runtimeRequirement = runtimeRequirement
    }

    private enum CodingKeys: String, CodingKey {
        case secretName
        case launcher
        case runtimeRequirement
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        secretName = try container.decode(String.self, forKey: .secretName)
        launcher = try container.decode(BlessedScriptLauncher.self, forKey: .launcher)
        runtimeRequirement = try container.decodeIfPresent(
            LauncherRuntimeRequirement.self,
            forKey: .runtimeRequirement
        ) ?? .hardened
    }
}

public func loadDirectAccessRules(
    service: String = directAccessKeychainService,
    account: String = directAccessKeychainAccount
) -> [DirectAccessRule] {
    guard case .success(let rules) = loadDirectAccessRulesResult(service: service, account: account)
    else { return [] }
    return rules.sorted(by: directAccessRulePrecedes)
}

public func allowDirectAccess(
    to secretName: String,
    for launcher: BlessedScriptLauncher,
    runtimeRequirement: LauncherRuntimeRequirement = .hardened,
    service: String = directAccessKeychainService,
    account: String = directAccessKeychainAccount
) -> OSStatus {
    guard !secretName.isEmpty, !launcher.requirement.isEmpty else { return errSecParam }
    var rules: [DirectAccessRule]
    switch loadDirectAccessRulesResult(service: service, account: account) {
    case .success(let loaded): rules = loaded
    case .failure(let status): return status
    }
    rules.removeAll {
        $0.secretName == secretName && $0.launcher.requirement == launcher.requirement
    }
    rules.append(DirectAccessRule(
        secretName: secretName,
        launcher: launcher,
        runtimeRequirement: runtimeRequirement
    ))
    return saveDirectAccessRules(rules, service: service, account: account)
}

public func removeDirectAccess(
    to secretName: String,
    for launcher: BlessedScriptLauncher,
    service: String = directAccessKeychainService,
    account: String = directAccessKeychainAccount
) -> OSStatus {
    mutateDirectAccessRules(service: service, account: account) { rules in
        rules.removeAll { rule in
            rule.secretName == secretName && rule.launcher.requirement == launcher.requirement
        }
    }
}

public func revokeDirectAccess(
    to secretName: String,
    service: String = directAccessKeychainService,
    account: String = directAccessKeychainAccount
) -> OSStatus {
    mutateDirectAccessRules(service: service, account: account) { rules in
        rules.removeAll { $0.secretName == secretName }
    }
}

public func directAccessAllows(
    secretNames: [String],
    launcherRequirement: String,
    runtimeProtection: LauncherRuntimeProtection,
    rules: [DirectAccessRule]
) -> Bool {
    guard !secretNames.isEmpty, !launcherRequirement.isEmpty else { return false }
    return Set(secretNames).allSatisfy { secretName in
        rules.contains {
            $0.secretName == secretName
                && $0.launcher.requirement == launcherRequirement
                && $0.runtimeRequirement.allows(runtimeProtection)
        }
    }
}

private enum DirectAccessRulesLoad {
    case success([DirectAccessRule])
    case failure(OSStatus)
}

private func loadDirectAccessRulesResult(service: String, account: String) -> DirectAccessRulesLoad {
    switch loadKeychainDataResult(service: service, account: account) {
    case .notFound:
        return .success([])
    case .failure(let status):
        return .failure(status)
    case .success(let data):
        do {
            return .success(try JSONDecoder().decode([DirectAccessRule].self, from: data))
        } catch {
            return .failure(errSecDecode)
        }
    }
}

private func mutateDirectAccessRules(
    service: String,
    account: String,
    mutate: (inout [DirectAccessRule]) -> Void
) -> OSStatus {
    var rules: [DirectAccessRule]
    switch loadDirectAccessRulesResult(service: service, account: account) {
    case .success(let loaded): rules = loaded
    case .failure(let status): return status
    }
    mutate(&rules)
    return saveDirectAccessRules(rules, service: service, account: account)
}

private func saveDirectAccessRules(
    _ rules: [DirectAccessRule],
    service: String,
    account: String
) -> OSStatus {
    if rules.isEmpty {
        let status = deleteStoredSecret(account: account, service: service)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
    do {
        return saveKeychainData(
            try JSONEncoder().encode(rules.sorted(by: directAccessRulePrecedes)),
            service: service,
            account: account,
            accessibility: .afterFirstUnlock
        )
    } catch {
        return errSecParam
    }
}

private func directAccessRulePrecedes(_ lhs: DirectAccessRule, _ rhs: DirectAccessRule) -> Bool {
    [lhs.secretName, lhs.launcher.bundleIdentifier, lhs.launcher.requirement]
        .joined(separator: "\u{1f}")
        .localizedStandardCompare(
            [rhs.secretName, rhs.launcher.bundleIdentifier, rhs.launcher.requirement]
                .joined(separator: "\u{1f}")
        ) == .orderedAscending
}

private func setKeychainAccessibility(
    _ accessibility: StoredSecretAccessibility,
    service: String,
    account: String
) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    return SecItemUpdate(
        query as CFDictionary,
        [kSecAttrAccessible as String: accessibility.keychainValue] as CFDictionary
    )
}

func saveKeychainData(
    _ data: Data,
    service: String,
    account: String,
    accessibility: StoredSecretAccessibility = .whenUnlocked
) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    let attributes: [String: Any] = [
        kSecValueData as String: data,
        kSecAttrAccessible as String: accessibility.keychainValue,
    ]
    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    if status != errSecItemNotFound {
        return status
    }
    var addQuery = query
    addQuery[kSecValueData as String] = data
    addQuery[kSecAttrAccessible as String] = accessibility.keychainValue
    return SecItemAdd(addQuery as CFDictionary, nil)
}

func saveKeychainDataIfAbsentOrEqual(
    _ data: Data,
    service: String,
    account: String
) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
        kSecValueData as String: data,
        kSecAttrAccessible as String: StoredSecretAccessibility.whenUnlocked.keychainValue,
    ]
    addCanonicalAccessGroup(to: &query)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecDuplicateItem else { return status }
    guard case .success(let existing) = loadKeychainDataResult(service: service, account: account),
          existing == data
    else {
        return errSecDuplicateItem
    }
    return errSecSuccess
}

private func addCanonicalAccessGroup(to query: inout [String: Any]) {
    // Swift package tests are not signed as the app and cannot claim its group.
    guard Bundle.main.bundleIdentifier == "com.automicvault" else { return }
    query[kSecAttrAccessGroup as String] = canonicalKeychainAccessGroup
}

func appIdentifier(from requirement: String) -> String? {
    guard let range = requirement.range(of: "identifier ") else { return nil }
    let rest = requirement[range.upperBound...]
    if rest.first == "\"" {
        let quoted = rest.dropFirst()
        guard let end = quoted.firstIndex(of: "\"") else { return nil }
        return String(quoted[..<end])
    }
    let identifier = rest.prefix { !$0.isWhitespace }
    return identifier.isEmpty ? nil : String(identifier)
}

public func codeSigningTeamIdentifier(from requirement: String) -> String? {
    guard let range = requirement.range(of: #"certificate leaf[subject.OU] = ""#) else { return nil }
    let rest = requirement[range.upperBound...]
    guard let end = rest.firstIndex(of: "\"") else { return nil }
    return String(rest[..<end])
}

private extension Array where Element == HardenedTool {
    func uniquedByName() -> [HardenedTool] {
        var seen = Set<String>()
        return filter { seen.insert($0.name).inserted }
    }
}

private extension Array where Element == String {
    func uniqueSorted() -> [String] {
        Array(Set(self)).sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }
}

private extension Array where Element == SecretGatePolicy {
    func uniqueSorted() -> [SecretGatePolicy] {
        var seen = Set<String>()
        return filter { seen.insert($0.requirement).inserted }
            .sorted {
                [$0.bundleIdentifier, $0.requirement].joined(separator: "\u{1f}")
                    .localizedStandardCompare([$1.bundleIdentifier, $1.requirement].joined(separator: "\u{1f}")) == .orderedAscending
            }
    }
}

func scanDetectorFindings(avExecutableURL: URL) -> [DetectorFinding] {
    loadJSON(avExecutableURL: avExecutableURL, arguments: ["scan", "--json"])
        .flatMap { try? detectorFindings(from: $0) } ?? []
}

public func loadDetectorMetadata(avExecutableURL: URL) -> [DetectorMetadata] {
    loadJSON(avExecutableURL: avExecutableURL, arguments: ["detectors", "--json"])
        .flatMap { try? detectorMetadata(from: $0) } ?? []
}

public func loadHardenerMetadata(avExecutableURL: URL) -> [HardenerMetadata] {
    loadJSON(avExecutableURL: avExecutableURL, arguments: ["hardeners", "--json"])
        .flatMap { try? hardenerMetadata(from: $0) } ?? []
}

public func loadDoctorIssues(avExecutableURL: URL) -> [DoctorIssue] {
    let shellPATH = loginShellPATH()
    var environment = ProcessInfo.processInfo.environment
    if let shellPATH {
        environment["PATH"] = shellPATH
    }
    let data = loadJSON(
        avExecutableURL: avExecutableURL,
        arguments: ["doctor", "--json"],
        acceptedTerminationStatuses: [0, 1],
        environment: environment
    )
    return data.flatMap {
        try? doctorIssues(from: $0, loginShellPATHAvailable: shellPATH != nil)
    } ?? (shellPATH == nil ? [DoctorIssue(
        hardener: "PATH",
        kind: "login_shell_path_unavailable",
        message: "Unable to inspect the login-shell PATH",
        remediation: "Ensure the configured login shell starts successfully, then refresh Doctor."
    )] : [])
}

func loadJSON(
    avExecutableURL: URL,
    arguments: [String],
    acceptedTerminationStatuses: Set<Int32> = [0],
    environment: [String: String]? = nil
) -> Data? {
    let process = Process()
    process.executableURL = avExecutableURL
    process.arguments = arguments
    if let environment {
        process.environment = environment
    }

    let output = Pipe()
    process.standardOutput = output
    process.standardError = Pipe()

    do {
        try process.run()
    } catch {
        return nil
    }

    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard acceptedTerminationStatuses.contains(process.terminationStatus) else { return nil }
    return data
}

func loginShellPATH() -> String? {
    guard let record = getpwuid(getuid()),
          let shellPointer = record.pointee.pw_shell,
          let shell = String(validatingCString: shellPointer),
          !shell.isEmpty
    else { return nil }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: shell)
    process.arguments = ["-lic", "/usr/bin/printenv PATH"]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = Pipe()
    do {
        try process.run()
    } catch {
        return nil
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    return loginShellPATH(from: data)
}

func loginShellPATH(from data: Data) -> String? {
    guard let output = String(data: data, encoding: .utf8) else { return nil }
    var path: Substring?
    for outputLine in output.split(whereSeparator: \.isNewline) {
        var line = outputLine
        while line.hasPrefix("\u{1B}]") {
            guard let terminator = line.firstIndex(of: "\u{07}") else { return nil }
            line = line[line.index(after: terminator)...]
        }
        if line.hasPrefix("/") {
            path = line
        }
    }
    return path.map(String.init)
}

public func defaultAVExecutableURL() -> URL {
    if let bundled = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("av"),
       FileManager.default.isExecutableFile(atPath: bundled.path)
    {
        return bundled
    }
    return URL(fileURLWithPath: "/usr/local/bin/av")
}
