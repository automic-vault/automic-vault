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
public let touchIDApprovalKeychainService = "com.automicvault.touch-id-approval"
public let touchIDApprovalKeychainAccount = "TouchIDApprovalV1"
public let accessRequestLogDefaultsKey = "AccessRequestLog"
public let accessRequestLogKeychainService = "com.automicvault.access-log"
private let secretMutationKeychainService = "com.automicvault.secret-mutations"
private let secretMutationKeychainAccount = "PendingSecretMutationV1"
private let secretMutationLock = NSLock()
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
        Set(detectorFindings.flatMap(\.detectors)).count
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
        _ = resumePendingSecretMutation()
        let hardening = loadDashboardHardening(avExecutableURL: avExecutableURL)
        let hardenerMetadata = hardening.hardeners
        let secrets = loadStoredSecrets(directAccessRules: loadDirectAccessRules())
        let gateDescriptors = dashboardSecretGateDescriptors(
            hardeners: hardenerMetadata,
            catalog: hardening.secretGates,
            storedSecretNames: Set(secrets.map(\.account))
        )
        _ = initializeSecretGatePolicies(descriptors: gateDescriptors, service: policyService)
        let hardenedTools = loadHardenedTools(
            in: stubDirectory,
            ghCLIURL: ghCLIURL,
            metadata: hardenerMetadata
        )
        return DashboardSnapshot(
            detectors: hardening.detectors,
            detectorFindings: [],
            hardenedTools: hardenedTools,
            hardeners: hardenerMetadata,
            secretGates: loadSecretGates(descriptors: gateDescriptors, service: policyService),
            blessedScripts: loadBlessedScripts(),
            secretNameAccessApps: loadSecretNameAccessApps(),
            secrets: secrets,
            accessRequests: loadAccessRequestRecords(),
            doctorIssues: hardening.doctorIssues
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
    public let watchScopes: [DetectorWatchScope]

    public var displayName: DetectorDisplayName {
        detectorDisplayName(name)
    }

    public init(
        name: String,
        homepage: String,
        docsURL: String,
        documentation: String = "",
        watchScopes: [DetectorWatchScope] = []
    ) {
        self.name = name
        self.homepage = homepage
        self.docsURL = docsURL
        self.documentation = documentation
        self.watchScopes = watchScopes
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.homepage = try container.decode(String.self, forKey: .homepage)
        self.docsURL = try container.decode(String.self, forKey: .docsURL)
        self.documentation = try container.decodeIfPresent(String.self, forKey: .documentation) ?? ""
        self.watchScopes = try container.decodeIfPresent([DetectorWatchScope].self, forKey: .watchScopes) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case name
        case homepage
        case docsURL = "docs_url"
        case documentation
        case watchScopes = "watch_scopes"
    }
}

public struct DetectorWatchScope: Codable, Equatable, Sendable {
    public let path: String
    public let recursive: Bool

    public init(path: String, recursive: Bool) {
        self.path = path
        self.recursive = recursive
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
    public let detectors: [String]

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        source = try container.decode(String.self, forKey: .source)
        severity = try container.decode(String.self, forKey: .severity)
        homepage = try container.decodeIfPresent(String.self, forKey: .homepage)
        explanation = try container.decodeIfPresent(String.self, forKey: .explanation)
        solution = try container.decodeIfPresent(String.self, forKey: .solution)
        affected = try container.decodeIfPresent([AffectedFile].self, forKey: .affected) ?? []
        docsURL = try container.decodeIfPresent(String.self, forKey: .docsURL)
        detectors = try container.decodeIfPresent([String].self, forKey: .detectors) ?? [source]
    }

    enum CodingKeys: String, CodingKey {
        case source
        case severity
        case homepage
        case explanation
        case solution
        case affected
        case docsURL = "docs_url"
        case detectors
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

public enum SecretGateProtection: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
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

    public var targetAuthorizationHistoryDescription: String {
        switch self {
        case .hardened:
            "Hardened Runtime"
        case .hardenedWithLibraryValidationDisabled:
            "Hardened Runtime; library validation disabled; third-party code can run inside the Target"
        case .hardenedRuntimeMissing:
            "Hardened Runtime not enabled; Secret may be exposed to debugging or process-memory inspection"
        case .unsafeEntitlements(let entitlements):
            "Hardened Runtime weakened by \(entitlements.joined(separator: ", ")); Secret may be exposed to injected or debugging code"
        }
    }
}

public enum LauncherRuntimeRequirement: String, Codable, Hashable, Sendable {
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
    let liveStatus = signingInformation[kSecCodeInfoStatus] as? NSNumber
    let signatureFlags = liveStatus
        ?? (signingInformation[kSecCodeInfoFlags] as? NSNumber)
    let isPlatformCode = signingInformation[kSecCodeInfoPlatformIdentifier] is NSNumber
        || (liveStatus?.uint32Value ?? 0) & SecCodeStatus.platform.rawValue != 0
    let entitlements = signingInformation[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
    let enabledEntitlements = Set(entitlements.compactMap { key, value in
        (value as? NSNumber)?.boolValue == true ? key : nil
    })
    return launcherRuntimeProtection(
        signatureFlags: (signatureFlags?.uint32Value ?? 0) |
            (isPlatformCode
                ? SecCodeSignatureFlags.runtime.rawValue
                : 0),
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
    public var displayName: String { id == "node" ? "npm" : id }
    public var authorizationGateName: String {
        id == "node" ? "npm Authorization Gate" : "\(id.uppercased()) Authorization Gate"
    }

    public var availableProtections: [SecretGateProtection] {
        if id == "gpg-signing" {
            return [.noAccess, .readOnlyAndLocalWrites]
        }
        if id == "brew" {
            return [.noAccess, .readOnlyAndUpdates, .fullExceptSecretDumps]
        }
        if keyPatterns.isEmpty {
            return [.noAccess, .readOnly, .fullExceptSecretDumps]
        }
        if id == "gh" || id == "docker" {
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
        if id == "gpg-signing" || id == "kubectl" { return .noAccess }
        return id == "brew" ? .readOnlyAndUpdates : .readOnly
    }

    public func normalizedProtection(_ protection: SecretGateProtection) -> SecretGateProtection {
        if id == "gpg-signing" {
            return protection.allows(.localWrite) ? .readOnlyAndLocalWrites : .noAccess
        }
        var protection = protection
        if keyPatterns.isEmpty, protection == .fullIncludingSecretDumps {
            protection = .fullExceptSecretDumps
        }
        if id != "gh" && id != "docker" && id != "gpg-signing",
           protection == .readOnlyAndLocalWrites
        {
            protection = .readOnly
        }
        if !keyPatterns.isEmpty, protection == .readOnlyAndUpdates {
            protection = .readOnly
        }
        return protection.normalized(forGateID: id)
    }

    public func protectionTitle(_ protection: SecretGateProtection) -> String {
        let protection = normalizedProtection(protection)
        if id == "gpg-signing" {
            return protection == .readOnlyAndLocalWrites ? "Allow Signing" : "Approval Required"
        }
        return keyPatterns.isEmpty && protection == .fullExceptSecretDumps ? "Full Access" : protection.title
    }

    public func protectionSubtitle(_ protection: SecretGateProtection) -> String {
        let protection = normalizedProtection(protection)
        if id == "gpg-signing" {
            return protection == .readOnlyAndLocalWrites
                ? "Recognized GPG signing requests are automically authorized"
                : "Every GPG signing request requires approval"
        }
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

public enum StoredSecretValueSource: Codable, Equatable, Hashable, Sendable {
    case global
    case projectDirectory(String)

    public var displayName: String {
        switch self {
        case .global: "Global Value"
        case .projectDirectory(let path): path
        }
    }
}

public struct StoredSecretValue: Equatable, Identifiable, Sendable {
    public let source: StoredSecretValueSource
    public let keychainAccount: String
    public let accessibility: StoredSecretAccessibility
    public let keychainProperties: [String]
    public var id: String { keychainAccount }

    public init(
        source: StoredSecretValueSource,
        keychainAccount: String,
        accessibility: StoredSecretAccessibility,
        keychainProperties: [String]
    ) {
        self.source = source
        self.keychainAccount = keychainAccount
        self.accessibility = accessibility
        self.keychainProperties = keychainProperties
    }
}

public struct StoredSecret: Equatable, Sendable {
    public let account: String
    public let accessibility: StoredSecretAccessibility
    public let keychainProperties: [String]
    public let directAccessLaunchers: [BlessedScriptLauncher]
    public let values: [StoredSecretValue]

    public init(
        account: String,
        accessibility: StoredSecretAccessibility = .whenUnlocked,
        keychainProperties: [String] = [],
        directAccessLaunchers: [BlessedScriptLauncher] = [],
        values: [StoredSecretValue] = []
    ) {
        self.account = account
        self.accessibility = accessibility
        self.keychainProperties = keychainProperties
        self.directAccessLaunchers = directAccessLaunchers
        self.values = values
    }

    public var hasConsistentAccessibility: Bool {
        values.allSatisfy { $0.accessibility == accessibility }
    }

    public var subtitle: String {
        let storage = keychainProperties.isEmpty ? "Keychain secret" : keychainProperties.joined(separator: " • ")
        return values.count > 1 ? "\(values.count) values • \(storage)" : storage
    }
}

public struct AccessRequestRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let date: Date
    public let tool: String
    public let command: String
    public let displayCommand: String?
    public let decision: String
    public let approvalSource: String?
    public let reason: String
    public let launcher: String?
    public let callerPath: String
    public let target: String
    public let targetRuntimeProtection: String?
    public let cwd: String
    public let keys: [String]
    public let detail: String?
    public let secretValueSources: [String: String]?

    public init(
        id: UUID = UUID(),
        date: Date,
        tool: String,
        command: String,
        displayCommand: String? = nil,
        decision: String,
        approvalSource: String? = nil,
        reason: String,
        launcher: String?,
        callerPath: String,
        target: String,
        targetRuntimeProtection: String? = nil,
        cwd: String,
        keys: [String],
        detail: String?,
        secretValueSources: [String: String]? = nil
    ) {
        self.id = id
        self.date = date
        self.tool = tool
        self.command = command
        self.displayCommand = displayCommand
        self.decision = decision
        self.approvalSource = approvalSource
        self.reason = reason
        self.launcher = launcher
        self.callerPath = callerPath
        self.target = target
        self.targetRuntimeProtection = targetRuntimeProtection
        self.cwd = cwd
        self.keys = keys
        self.detail = detail
        self.secretValueSources = secretValueSources
    }

    public var commandForDisplay: String {
        displayCommand ?? "\(tool.isEmpty ? "tool" : tool) <arguments hidden>"
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

public func escapedSecurityPath(_ path: String) -> String {
    var escaped = ""
    escaped.reserveCapacity(path.utf8.count)
    for scalar in path.unicodeScalars {
        switch scalar.value {
        case 0x5C: escaped += #"\\"#
        case 0x09: escaped += #"\t"#
        case 0x0A: escaped += #"\n"#
        case 0x0D: escaped += #"\r"#
        default:
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator:
                escaped += #"\u{"# + String(scalar.value, radix: 16, uppercase: true) + "}"
            default:
                escaped.unicodeScalars.append(scalar)
            }
        }
    }
    return escaped
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

struct DashboardHardening: Sendable {
    let hardeners: [HardenerMetadata]
    let detectors: [DetectorMetadata]
    let secretGates: [SecretGateDescriptor]
    let doctorIssues: [DoctorIssue]
}

private struct DashboardHardeningReport: Codable {
    let hardeners: [HardenerMetadata]
    let detectors: [DetectorMetadata]
    let secretGates: [SecretGateDescriptor]
    let results: [DoctorResult]

    private enum CodingKeys: String, CodingKey {
        case hardeners
        case detectors
        case secretGates = "secret_gates"
        case results
    }
}

private struct SecretGateReport: Codable {
    let secretGates: [SecretGateDescriptor]

    enum CodingKeys: String, CodingKey {
        case secretGates = "secret_gates"
    }
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

func dashboardHardening(
    from dashboardJSON: Data,
    loginShellPATHAvailable: Bool = true
) throws -> DashboardHardening {
    let report = try JSONDecoder().decode(DashboardHardeningReport.self, from: dashboardJSON)
    return DashboardHardening(
        hardeners: report.hardeners,
        detectors: report.detectors,
        secretGates: try validatedSecretGateDescriptors(report.secretGates),
        doctorIssues: doctorIssues(
            from: report.results,
            loginShellPATHAvailable: loginShellPATHAvailable
        )
    )
}

public func secretGateDescriptors(from secretGatesJSON: Data) throws -> [SecretGateDescriptor] {
    let gates = try JSONDecoder().decode(SecretGateReport.self, from: secretGatesJSON).secretGates
    return try validatedSecretGateDescriptors(gates)
}

private func validatedSecretGateDescriptors(
    _ gates: [SecretGateDescriptor]
) throws -> [SecretGateDescriptor] {
    guard !gates.isEmpty,
          Set(gates.map(\.id)).count == gates.count,
          gates.allSatisfy({ gate in
              !gate.id.isEmpty && !gate.routes.isEmpty && gate.routes.allSatisfy {
                  !$0.operation.isEmpty
                      && $0.targetPath.hasPrefix("/")
                      && !$0.callerIdentifiers.isEmpty
              }
          })
    else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: [],
            debugDescription: "Secret Gate catalog is empty, duplicated, or invalid"
        ))
    }
    return gates
}

public func doctorIssues(from doctorJSON: Data, loginShellPATHAvailable: Bool = true) throws -> [DoctorIssue] {
    let results = try JSONDecoder().decode(DoctorReport.self, from: doctorJSON).results
    return doctorIssues(from: results, loginShellPATHAvailable: loginShellPATHAvailable)
}

private func doctorIssues(
    from results: [DoctorResult],
    loginShellPATHAvailable: Bool
) -> [DoctorIssue] {
    var issues = results.flatMap { result in
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
    issues.removeAll {
        $0.kind.hasSuffix("_command_shadowed") || [
            "agent_cli_signature_invalid",
            "agent_cli_unavailable",
            "isotope_not_first_on_path",
            "launcher_bundle_not_first_on_path",
            "stub_not_first_on_path",
        ].contains($0.kind)
    }
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
    loadSecretGates(
        descriptors: dashboardSecretGateDescriptors(hardeners: hardeners, catalog: []),
        service: service,
        account: account
    )
}

public func dashboardSecretGateDescriptors(
    hardeners: [HardenerMetadata],
    catalog: [SecretGateDescriptor],
    storedSecretNames: Set<String> = []
) -> [SecretGateDescriptor] {
    let hardenerGateIDs = Set(hardeners.compactMap { $0.secretGate?.id })
    let activeHardenerGates = hardeners.compactMap { hardener -> SecretGateDescriptor? in
        guard let descriptor = hardener.secretGate,
              hardener.hardened || descriptor.routes
                .compactMap(\.scriptPath)
                .contains(where: FileManager.default.fileExists(atPath:))
        else { return nil }
        return descriptor
    }
    return activeHardenerGates + catalog.filter {
        !hardenerGateIDs.contains($0.id)
            && ($0.id != "gpg-signing"
                || storedSecretNames.contains(gpgDefaultPrivateKeySecretName)
                || storedSecretNames.contains(gpgAlternatePrivateKeySecretName))
    }
}

public func loadSecretGates(
    descriptors: [SecretGateDescriptor],
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> [SecretGate] {
    let loadedRecords = loadSecretGatePolicyRecords(service: service, account: account)
    return descriptors.map {
        loadedSecretGate(from: $0, policyRecords: loadedRecords)
    }
    .sorted { $0.id.localizedStandardCompare($1.id) == .orderedAscending }
}

private func loadedSecretGate(
    from descriptor: SecretGateDescriptor,
    policyRecords loadedRecords: SecretGatePolicyRecordsLoad
) -> SecretGate {
    let records: [SecretGatePolicyRecord] = switch loadedRecords {
    case .success(let records): records
    case .failure: []
    }
    let policiesAreReadable = if case .success = loadedRecords { true } else { false }
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

public func reloadSecretGatePolicy(
    for gate: SecretGate,
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> SecretGate {
    let descriptor = SecretGateDescriptor(
        id: gate.id,
        keyPatterns: gate.keyPatterns,
        routes: gate.routes
    )
    return loadedSecretGate(
        from: descriptor,
        policyRecords: loadSecretGatePolicyRecords(service: service, account: account)
    )
}

public func reloadDashboardAuthorizationState(
    from snapshot: DashboardSnapshot,
    blessedScripts: [BlessedScript] = loadBlessedScripts(),
    secretNameAccessApps: [BlessedScriptLauncher] = loadSecretNameAccessApps(),
    secrets: [StoredSecret]? = nil,
    reloadGatePolicy: (SecretGate) -> SecretGate = { reloadSecretGatePolicy(for: $0) }
) -> DashboardSnapshot {
    var refreshed = snapshot
    refreshed.blessedScripts = blessedScripts
    refreshed.secretNameAccessApps = secretNameAccessApps
    refreshed.secrets = secrets ?? loadStoredSecrets(directAccessRules: loadDirectAccessRules())
    refreshed.secretGates = snapshot.secretGates.map(reloadGatePolicy)
    return refreshed
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

@discardableResult
public func removeSecretGatePolicies(
    forLauncherRequirement requirement: String,
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    let records: [SecretGatePolicyRecord]
    switch loadSecretGatePolicyRecords(service: service, account: account) {
    case .success(let loaded): records = loaded.filter { $0.requirement != requirement }
    case .failure(let status): return status
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
    initializeSecretGatePolicies(
        descriptors: dashboardSecretGateDescriptors(hardeners: hardeners, catalog: []),
        service: service,
        account: account
    )
}

@discardableResult
public func initializeSecretGatePolicies(
    descriptors: [SecretGateDescriptor],
    service: String = secretGatePoliciesKeychainService,
    account: String = secretGatePoliciesKeychainAccount
) -> OSStatus {
    var records: [SecretGatePolicyRecord]
    switch loadSecretGatePolicyRecords(service: service, account: account) {
    case .success(let loaded): records = loaded
    case .failure(let status): return status
    }
    let gates = loadSecretGates(descriptors: descriptors, service: service, account: account)
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

@discardableResult
public func removeSecretNameAccess(
    forLauncherRequirement requirement: String,
    service: String = secretNameAccessKeychainService,
    account: String = secretNameAccessKeychainAccount
) -> OSStatus {
    let apps: [BlessedScriptLauncher]
    switch loadSecretNameAccessAppsResult(service: service, account: account) {
    case .success(let loaded): apps = loaded.filter { $0.requirement != requirement }
    case .failure(let status): return status
    }
    return saveSecretNameAccessApps(apps, service: service, account: account)
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

private let projectValueAccountPrefix = "AVProjectValueV1:"

private struct StoredSecretAccount {
    let secretName: String
    let source: StoredSecretValueSource
}

public func storedSecretKeychainAccount(
    secretName: String,
    source: StoredSecretValueSource
) -> String {
    guard case .projectDirectory(let path) = source else { return secretName }
    return projectValueAccountPrefix
        + Data(secretName.utf8).base64EncodedString()
        + ":"
        + Data(path.utf8).base64EncodedString()
}

private func parseStoredSecretAccount(_ account: String) -> StoredSecretAccount? {
    guard account.hasPrefix(projectValueAccountPrefix) else {
        return StoredSecretAccount(secretName: account, source: .global)
    }
    let encoded = account.dropFirst(projectValueAccountPrefix.count)
    let parts = encoded.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2,
          let nameData = Data(base64Encoded: String(parts[0])),
          let pathData = Data(base64Encoded: String(parts[1])),
          let name = String(data: nameData, encoding: .utf8),
          let path = String(data: pathData, encoding: .utf8),
          !name.isEmpty,
          path.hasPrefix("/")
    else { return nil }
    return StoredSecretAccount(secretName: name, source: .projectDirectory(path))
}

public func loadStoredSecrets(
    service: String = automicVaultKeychainService,
    directAccessRules: [DirectAccessRule] = []
) -> [StoredSecret] {
    guard case .success(let secrets) = loadStoredSecretsResult(
        service: service,
        directAccessRules: directAccessRules
    ) else { return [] }
    return secrets
}

public enum StoredSecretsLoad: Sendable {
    case success([StoredSecret])
    case failure(OSStatus)
}

public func loadStoredSecretsResult(
    service: String = automicVaultKeychainService,
    directAccessRules: [DirectAccessRule] = []
) -> StoredSecretsLoad {
    loadStoredSecretsResult(
        service: service,
        directAccessRules: directAccessRules,
        accessibility: nil
    )
}

public func loadStoredSecretsForUseResult(
    service: String = automicVaultKeychainService,
    directAccessRules: [DirectAccessRule] = []
) -> StoredSecretsLoad {
    retryLockedSecretInventory { accessibility in
        loadStoredSecretsResult(
            service: service,
            directAccessRules: directAccessRules,
            accessibility: accessibility
        )
    }
}

func retryLockedSecretInventory(
    _ load: (StoredSecretAccessibility?) -> StoredSecretsLoad
) -> StoredSecretsLoad {
    let result = load(nil)
    if case .failure(errSecInteractionNotAllowed) = result {
        return load(.afterFirstUnlock)
    }
    return result
}

private func loadStoredSecretsResult(
    service: String,
    directAccessRules: [DirectAccessRule],
    accessibility: StoredSecretAccessibility?
) -> StoredSecretsLoad {
    let directAccess = Dictionary(grouping: directAccessRules, by: \.secretName)
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    if let accessibility {
        query[kSecAttrAccessible as String] = accessibility.keychainValue
    }
    addCanonicalAccessGroup(to: &query)
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return .success([]) }
    guard status == errSecSuccess,
          let items = result as? [[String: Any]]
    else { return .failure(status == errSecSuccess ? errSecDecode : status) }
    var values: [(String, StoredSecretValue)] = []
    for item in items {
        guard let account = item[kSecAttrAccount as String] as? String,
              let parsed = parseStoredSecretAccount(account)
        else { return .failure(errSecDecode) }
        values.append((parsed.secretName, StoredSecretValue(
            source: parsed.source,
            keychainAccount: account,
            accessibility: StoredSecretAccessibility(
                keychainValue: item[kSecAttrAccessible as String]
            ),
            keychainProperties: keychainProperties(for: item, dataProtection: true)
        )))
    }
    let grouped = Dictionary(grouping: values, by: \.0)
    let secrets = grouped.compactMap { account, entries -> StoredSecret? in
        let values = entries.map(\.1).sorted { lhs, rhs in
            switch (lhs.source, rhs.source) {
            case (.global, .projectDirectory): true
            case (.projectDirectory, .global): false
            default: lhs.source.displayName.localizedStandardCompare(rhs.source.displayName) == .orderedAscending
                }
        }
        guard Set(values.map(\.source)).count == values.count else { return nil }
        let first = values[0]
        return StoredSecret(
            account: account,
            accessibility: first.accessibility,
            keychainProperties: first.keychainProperties,
            directAccessLaunchers: (directAccess[account] ?? [])
                .map(\.launcher)
                .sorted {
                    $0.bundleIdentifier.localizedStandardCompare($1.bundleIdentifier) == .orderedAscending
                },
            values: values
        )
    }
    .sorted { $0.account.localizedStandardCompare($1.account) == .orderedAscending }
    guard secrets.count == grouped.count else {
        return .failure(errSecDecode)
    }
    return .success(secrets)
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

public enum ProjectDirectoryValidationError: Error, LocalizedError, Equatable {
    case notAbsolute
    case unavailable
    case notDirectory
    case notCanonical(String)
    case filesystemIdentityUnavailable
    case filesystemRoot
    case filesystemCycle

    public var errorDescription: String? {
        switch self {
        case .notAbsolute: "project directory must be absolute"
        case .unavailable: "project directory does not exist"
        case .notDirectory: "project directory must be a directory"
        case .notCanonical(let path): "project directory must be canonical: \(path)"
        case .filesystemIdentityUnavailable: "project directory filesystem is unavailable"
        case .filesystemRoot: "project directory cannot be a filesystem root"
        case .filesystemCycle: "project directory ancestry contains a filesystem cycle"
        }
    }
}

private func canonicalDirectory(_ path: String) throws -> (path: String, device: UInt64) {
    guard path.hasPrefix("/") else { throw ProjectDirectoryValidationError.notAbsolute }
    var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard realpath(path, &resolved) != nil else { throw ProjectDirectoryValidationError.unavailable }
    let end = resolved.firstIndex(of: 0) ?? resolved.endIndex
    guard let canonical = String(
        data: Data(resolved[..<end].map { UInt8(bitPattern: $0) }),
        encoding: .utf8
    ) else { throw ProjectDirectoryValidationError.unavailable }
    let attributes: [FileAttributeKey: Any]
    do {
        attributes = try FileManager.default.attributesOfItem(atPath: canonical)
    } catch {
        throw ProjectDirectoryValidationError.unavailable
    }
    guard attributes[.type] as? FileAttributeType == .typeDirectory else {
        throw ProjectDirectoryValidationError.notDirectory
    }
    guard let device = attributes[.systemNumber] as? NSNumber else {
        throw ProjectDirectoryValidationError.filesystemIdentityUnavailable
    }
    return (canonical, device.uint64Value)
}

public func validateCanonicalProjectDirectory(_ path: String) throws -> String {
    let directory = try canonicalDirectory(path)
    guard directory.path == path else {
        throw ProjectDirectoryValidationError.notCanonical(directory.path)
    }
    guard path != "/" else { throw ProjectDirectoryValidationError.filesystemRoot }
    let parent = URL(fileURLWithPath: path, isDirectory: true)
        .deletingLastPathComponent().path
    guard parent != path else { throw ProjectDirectoryValidationError.filesystemRoot }
    let parentDirectory = try canonicalDirectory(parent)
    guard parentDirectory.device == directory.device else {
        throw ProjectDirectoryValidationError.filesystemRoot
    }
    return path
}

public func canonicalProjectDirectory(_ path: String) throws -> String {
    let directory = try canonicalDirectory(path)
    _ = try validateCanonicalProjectDirectory(directory.path)
    return directory.path
}

func physicalDirectoryAncestors(
    _ path: String,
    parentPath: (String) -> String = {
        URL(fileURLWithPath: $0, isDirectory: true).deletingLastPathComponent().path
    },
    canonicalize: (String) throws -> (path: String, device: UInt64)
) throws -> [String] {
    let start = try canonicalize(path)
    guard start.path == path else {
        throw ProjectDirectoryValidationError.notCanonical(start.path)
    }
    var result = [start.path]
    var seen = Set(result)
    var current = start.path
    while true {
        guard current != "/" else { break }
        let parent = parentPath(current)
        guard parent != current else { break }
        let parentDirectory = try canonicalize(parent)
        guard parentDirectory.device == start.device else { break }
        guard seen.insert(parentDirectory.path).inserted else {
            throw ProjectDirectoryValidationError.filesystemCycle
        }
        result.append(parentDirectory.path)
        current = parentDirectory.path
    }
    return result
}

public func physicalDirectoryAncestors(_ path: String) throws -> [String] {
    try physicalDirectoryAncestors(path, canonicalize: canonicalDirectory)
}

public enum StoredSecretSelectionError: Error, LocalizedError, Equatable {
    case inconsistentAvailability(String)

    public var errorDescription: String? {
        switch self {
        case .inconsistentAvailability(let name):
            "secret \(name) has inconsistent availability and must be repaired"
        }
    }
}

public func resolveStoredSecretValues(
    names: [String],
    cwd: String,
    secrets: [StoredSecret]
) throws -> [String: StoredSecretValue] {
    guard !names.isEmpty else { return [:] }
    let rank = Dictionary(
        uniqueKeysWithValues: try physicalDirectoryAncestors(cwd).enumerated().map { ($1, $0) }
    )
    let byName = Dictionary(uniqueKeysWithValues: secrets.map { ($0.account, $0) })
    var selected: [String: StoredSecretValue] = [:]
    for name in names {
        guard let secret = byName[name] else { continue }
        guard secret.hasConsistentAccessibility else {
            throw StoredSecretSelectionError.inconsistentAvailability(name)
        }
        let project = secret.values.compactMap { value -> (Int, StoredSecretValue)? in
            guard case .projectDirectory(let path) = value.source,
                  let rank = rank[path]
            else { return nil }
            return (rank, value)
        }.min { $0.0 < $1.0 }?.1
        selected[name] = project ?? secret.values.first { $0.source == .global }
    }
    return selected
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
    source: StoredSecretValueSource = .global,
    service: String = automicVaultKeychainService
) -> OSStatus {
    saveKeychainData(
        Data(value.utf8),
        service: service,
        account: storedSecretKeychainAccount(secretName: account, source: source),
        accessibility: accessibility
    )
}

public func saveStoredSecretIfAbsentOrEqual(
    account: String,
    value: String,
    service: String = automicVaultKeychainService
) -> OSStatus {
    let secrets: [StoredSecret]
    switch loadStoredSecretsResult(service: service) {
    case .success(let loaded): secrets = loaded
    case .failure(let status): return status
    }
    let existing = secrets.first { $0.account == account }
    guard existing?.hasConsistentAccessibility != false else { return errSecDecode }
    return saveKeychainDataIfAbsentOrEqual(
        Data(value.utf8),
        service: service,
        account: account,
        accessibility: existing?.accessibility ?? .whenUnlocked
    )
}

public func setStoredSecretAccessibility(
    account: String,
    accessibility: StoredSecretAccessibility,
    service: String = automicVaultKeychainService
) -> OSStatus {
    let secrets: [StoredSecret]
    switch loadStoredSecretsResult(service: service) {
    case .success(let loaded): secrets = loaded
    case .failure(let status): return status
    }
    guard let secret = secrets.first(where: { $0.account == account }) else { return errSecItemNotFound }
    guard secret.values.count > 1 else {
        return setKeychainAccessibility(
            accessibility,
            service: service,
            account: secret.values[0].keychainAccount
        )
    }
    return beginPendingSecretMutation(
        .setAccessibility(account: account, accessibility: accessibility),
        service: service
    )
}

public func renameStoredSecret(account: String, to newAccount: String, service: String = automicVaultKeychainService) -> OSStatus {
    let secrets: [StoredSecret]
    switch loadStoredSecretsResult(service: service) {
    case .success(let loaded): secrets = loaded
    case .failure(let status): return status
    }
    guard !secrets.contains(where: { $0.account == newAccount }),
          let secret = secrets.first(where: { $0.account == account })
    else { return secrets.contains(where: { $0.account == newAccount }) ? errSecDuplicateItem : errSecItemNotFound }
    guard secret.hasConsistentAccessibility else { return errSecDecode }
    guard secret.values.count > 1 else {
        return renameStoredSecretValue(
            secret.values[0],
            to: newAccount,
            service: service
        )
    }
    return beginPendingSecretMutation(
        .rename(account: account, newAccount: newAccount),
        service: service
    )
}

private enum PendingSecretMutation: Codable, Equatable {
    case rename(account: String, newAccount: String)
    case setAccessibility(account: String, accessibility: StoredSecretAccessibility)
    case delete(account: String)

    var affectedNames: Set<String> {
        switch self {
        case .rename(let account, let newAccount): [account, newAccount]
        case .setAccessibility(let account, _): [account]
        case .delete(let account): [account]
        }
    }
}

private enum PendingSecretMutationLoad {
    case none
    case success(PendingSecretMutation)
    case failure(OSStatus)
}

extension StoredSecretAccessibility: Codable {}

// ponytail: one journal serializes rare multi-value mutations; add per-Secret journals only if contention appears.
private func beginPendingSecretMutation(
    _ mutation: PendingSecretMutation,
    service: String
) -> OSStatus {
    secretMutationLock.lock()
    defer { secretMutationLock.unlock() }
    let journalAccount = secretMutationJournalAccount(for: service)
    switch loadPendingSecretMutation(service: service) {
    case .none: break
    case .success: return errSecInteractionNotAllowed
    case .failure(let status): return status
    }
    guard let data = try? JSONEncoder().encode(mutation) else { return errSecParam }
    let status = saveKeychainData(
        data,
        service: secretMutationKeychainService,
        account: journalAccount,
        accessibility: .afterFirstUnlock
    )
    guard status == errSecSuccess else { return status }
    guard case .success(let persisted) = loadPendingSecretMutation(service: service),
          persisted == mutation
    else { return errSecDecode }
    return resumePendingSecretMutationUnlocked(service: service)
}

private func secretMutationJournalAccount(for service: String) -> String {
    guard service != automicVaultKeychainService else { return secretMutationKeychainAccount }
    return secretMutationKeychainAccount + ":" + Data(service.utf8).base64EncodedString()
}

private func loadPendingSecretMutation(service: String) -> PendingSecretMutationLoad {
    switch loadKeychainDataResult(
        service: secretMutationKeychainService,
        account: secretMutationJournalAccount(for: service)
    ) {
    case .notFound:
        return .none
    case .failure(let status):
        return .failure(status)
    case .success(let data):
        guard let mutation = try? JSONDecoder().decode(PendingSecretMutation.self, from: data)
        else { return .failure(errSecDecode) }
        return .success(mutation)
    }
}

public func pendingSecretMutationNames() -> Set<String>? {
    secretMutationLock.lock()
    defer { secretMutationLock.unlock() }
    return switch loadPendingSecretMutation(service: automicVaultKeychainService) {
    case .none: []
    case .success(let mutation): mutation.affectedNames
    case .failure: nil
    }
}

@discardableResult
public func resumePendingSecretMutation(
    service: String = automicVaultKeychainService
) -> OSStatus {
    secretMutationLock.lock()
    defer { secretMutationLock.unlock() }
    return resumePendingSecretMutationUnlocked(service: service)
}

private func resumePendingSecretMutationUnlocked(service: String) -> OSStatus {
    let journalAccount = secretMutationJournalAccount(for: service)
    let mutation: PendingSecretMutation
    switch loadPendingSecretMutation(service: service) {
    case .none: return errSecSuccess
    case .success(let loaded): mutation = loaded
    case .failure(let status): return status
    }

    let status: OSStatus
    switch mutation {
    case .setAccessibility(let account, let accessibility):
        let secrets: [StoredSecret]
        switch loadStoredSecretsResult(service: service) {
        case .success(let loaded): secrets = loaded
        case .failure(let status): return status
        }
        guard let secret = secrets.first(where: { $0.account == account }) else { return errSecItemNotFound }
        status = secret.values.reduce(errSecSuccess) { result, value in
            guard result == errSecSuccess, value.accessibility != accessibility else { return result }
            return setKeychainAccessibility(
                accessibility,
                service: service,
                account: value.keychainAccount
            )
        }
    case .rename(let account, let newAccount):
        let secrets: [StoredSecret]
        switch loadStoredSecretsResult(service: service) {
        case .success(let loaded): secrets = loaded
        case .failure(let status): return status
        }
        let old = secrets.first { $0.account == account }
        let newSources = Set(
            secrets.first(where: { $0.account == newAccount })?.values.map(\.source) ?? []
        )
        guard old?.values.contains(where: { newSources.contains($0.source) }) != true else {
            return errSecDuplicateItem
        }
        status = old?.values.reduce(errSecSuccess) { result, value in
            guard result == errSecSuccess else { return result }
            return renameStoredSecretValue(value, to: newAccount, service: service)
        } ?? errSecSuccess
    case .delete(let account):
        let secrets: [StoredSecret]
        switch loadStoredSecretsResult(service: service) {
        case .success(let loaded): secrets = loaded
        case .failure(let status): return status
        }
        status = secrets.first(where: { $0.account == account })
            .map { deleteStoredSecretValues($0, service: service) } ?? errSecSuccess
    }
    guard status == errSecSuccess else { return status }
    return deleteStoredSecretValue(
        secretName: journalAccount,
        source: .global,
        service: secretMutationKeychainService
    )
}

private func renameStoredSecretValue(
    _ value: StoredSecretValue,
    to newAccount: String,
    service: String
) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: value.keychainAccount,
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    return SecItemUpdate(
        query as CFDictionary,
        [kSecAttrAccount as String: storedSecretKeychainAccount(
            secretName: newAccount,
            source: value.source
        )] as CFDictionary
    )
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
    let secrets: [StoredSecret]
    switch loadStoredSecretsResult(service: service) {
    case .success(let loaded): secrets = loaded
    case .failure(let status): return status
    }
    guard let secret = secrets.first(where: { $0.account == account }) else { return errSecItemNotFound }
    guard secret.values.count > 1 else {
        return deleteStoredSecretValue(
            secretName: account,
            source: secret.values[0].source,
            service: service
        )
    }
    return beginPendingSecretMutation(.delete(account: account), service: service)
}

private func deleteStoredSecretValues(_ secret: StoredSecret, service: String) -> OSStatus {
    for value in secret.values {
        let status = deleteStoredSecretValue(
            secretName: secret.account,
            source: value.source,
            service: service
        )
        guard status == errSecSuccess else { return status }
    }
    return errSecSuccess
}

public func deleteStoredSecretValue(
    secretName: String,
    source: StoredSecretValueSource,
    service: String = automicVaultKeychainService
) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: storedSecretKeychainAccount(secretName: secretName, source: source),
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    return SecItemDelete(query as CFDictionary)
}

public func deleteStoredSecretValueRevokingDirectAccessIfLast(
    secretName: String,
    source: StoredSecretValueSource,
    service: String = automicVaultKeychainService,
    directAccessService: String = directAccessKeychainService,
    directAccessAccount: String = directAccessKeychainAccount
) -> OSStatus {
    let secrets: [StoredSecret]
    switch loadStoredSecretsResult(service: service) {
    case .success(let loaded): secrets = loaded
    case .failure(let status): return status
    }
    guard let secret = secrets.first(where: { $0.account == secretName }),
          secret.values.contains(where: { $0.source == source })
    else { return errSecItemNotFound }
    if secret.values.count == 1 {
        let status = revokeDirectAccess(
            to: secretName,
            service: directAccessService,
            account: directAccessAccount
        )
        guard status == errSecSuccess else { return status }
    }
    return deleteStoredSecretValue(secretName: secretName, source: source, service: service)
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

public func loadStoredSecret(
    account: String,
    source: StoredSecretValueSource = .global,
    service: String = automicVaultKeychainService
) -> String? {
    let keychainAccount = storedSecretKeychainAccount(secretName: account, source: source)
    guard let data = loadKeychainData(service: service, account: keychainAccount) else { return nil }
    return String(data: data, encoding: .utf8)
}

public enum StoredSecretValueLoad: Equatable, Sendable {
    case success(String)
    case notFound
    case failure(OSStatus)
    case invalidUTF8
}

public func loadStoredSecretValue(
    _ value: StoredSecretValue,
    service: String = automicVaultKeychainService
) -> StoredSecretValueLoad {
    switch loadKeychainDataResult(service: service, account: value.keychainAccount) {
    case .success(let data):
        guard let text = String(data: data, encoding: .utf8) else { return .invalidUTF8 }
        return .success(text)
    case .notFound:
        return .notFound
    case .failure(let status):
        return .failure(status)
    }
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

public func touchIDApprovalIsEnabled(
    service: String = touchIDApprovalKeychainService,
    account: String = touchIDApprovalKeychainAccount
) -> Bool {
    guard case .success(let data) = loadKeychainDataResult(service: service, account: account)
    else { return false }
    return data == Data([1])
}

@discardableResult
public func setTouchIDApprovalEnabled(
    _ enabled: Bool,
    service: String = touchIDApprovalKeychainService,
    account: String = touchIDApprovalKeychainAccount
) -> OSStatus {
    if enabled {
        return saveKeychainData(
            Data([1]),
            service: service,
            account: account,
            accessibility: .afterFirstUnlock
        )
    }
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
    addCanonicalAccessGroup(to: &query)
    let status = SecItemDelete(query as CFDictionary)
    return status == errSecItemNotFound ? errSecSuccess : status
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
    directAccessAccount: String = directAccessKeychainAccount,
    gpgSigningService: String = gpgSigningConfigurationService,
    gpgSigningAccount: String = gpgSigningConfigurationAccount
) -> OSStatus {
    for (service, account) in [
        (policyService, policyAccount),
        (accessLogService, accessLogAccount),
        (secretNameAccessService, secretNameAccessAccount),
        (directAccessService, directAccessAccount),
        (gpgSigningService, gpgSigningAccount),
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

@discardableResult
public func removeDirectAccess(
    forLauncherRequirement requirement: String,
    service: String = directAccessKeychainService,
    account: String = directAccessKeychainAccount
) -> OSStatus {
    mutateDirectAccessRules(service: service, account: account) { rules in
        rules.removeAll { $0.launcher.requirement == requirement }
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

public enum DirectAccessRulesLoad {
    case success([DirectAccessRule])
    case failure(OSStatus)
}

public func loadDirectAccessRulesResult(
    service: String = directAccessKeychainService,
    account: String = directAccessKeychainAccount
) -> DirectAccessRulesLoad {
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
    account: String,
    accessibility: StoredSecretAccessibility = .whenUnlocked
) -> OSStatus {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
        kSecValueData as String: data,
        kSecAttrAccessible as String: accessibility.keychainValue,
    ]
    addCanonicalAccessGroup(to: &query)
    return verifyKeychainDataAfterConditionalAdd(
        status: SecItemAdd(query as CFDictionary, nil),
        expected: data
    ) {
        loadKeychainDataResult(service: service, account: account)
    }
}

func verifyKeychainDataAfterConditionalAdd(
    status: OSStatus,
    expected: Data,
    load: () -> KeychainDataLoad
) -> OSStatus {
    guard status == errSecSuccess || status == errSecDuplicateItem else { return status }
    // A successful add is not sufficient: mutation success means the final stored bytes were verified.
    switch load() {
    case .success(let existing):
        return existing == expected ? errSecSuccess : errSecDuplicateItem
    case .notFound:
        return errSecItemNotFound
    case .failure(let status):
        return status
    }
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

public func loadDetectorMetadata(avExecutableURL: URL) -> [DetectorMetadata] {
    loadJSON(avExecutableURL: avExecutableURL, arguments: ["detectors", "--json"])
        .flatMap { try? detectorMetadata(from: $0) } ?? []
}

public func loadHardenerMetadata(avExecutableURL: URL) -> [HardenerMetadata] {
    loadJSON(avExecutableURL: avExecutableURL, arguments: ["hardeners", "--json"])
        .flatMap { try? hardenerMetadata(from: $0) } ?? []
}

func loadDashboardHardening(avExecutableURL: URL) -> DashboardHardening {
    if let data = loadJSON(
        avExecutableURL: avExecutableURL,
        arguments: ["__dashboard-hardening-json"]
    ), let report = try? dashboardHardening(from: data, loginShellPATHAvailable: false) {
        return report
    }
    let hardeners = loadHardenerMetadata(avExecutableURL: avExecutableURL)
    let secretGates = (try? loadSecretGateDescriptors(avExecutableURL: avExecutableURL)) ?? []
    let detectors = loadDetectorMetadata(avExecutableURL: avExecutableURL)
    let doctorIssues = loadDoctorIssues(avExecutableURL: avExecutableURL)
    return DashboardHardening(
        hardeners: hardeners,
        detectors: detectors,
        secretGates: secretGates,
        doctorIssues: doctorIssues
    )
}

public func loadSecretGateDescriptors(avExecutableURL: URL) throws -> [SecretGateDescriptor] {
    guard let data = loadJSON(avExecutableURL: avExecutableURL, arguments: ["__secret-gates-json"]) else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: [],
            debugDescription: "Secret Gate catalog is unavailable"
        ))
    }
    return try secretGateDescriptors(from: data)
}

public func loadDoctorIssues(avExecutableURL: URL) -> [DoctorIssue] {
    let data = loadJSON(
        avExecutableURL: avExecutableURL,
        arguments: ["doctor", "--json"],
        acceptedTerminationStatuses: [0, 1]
    )
    return data.flatMap {
        try? doctorIssues(from: $0, loginShellPATHAvailable: false)
    } ?? [DoctorIssue(
        hardener: "Doctor",
        kind: "doctor_unavailable",
        message: "Doctor results are unavailable",
        remediation: "Run `av doctor` in Terminal to inspect the failure."
    )]
}

func loadJSON(
    avExecutableURL: URL,
    arguments: [String],
    acceptedTerminationStatuses: Set<Int32> = [0]
) -> Data? {
    let process = Process()
    process.executableURL = avExecutableURL
    process.arguments = arguments
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

public func defaultAVExecutableURL() -> URL {
    if let bundled = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("av"),
       FileManager.default.isExecutableFile(atPath: bundled.path)
    {
        return bundled
    }
    return URL(fileURLWithPath: "/usr/local/bin/av")
}
