import Foundation
import Security

private let verifiedLauncherHelpersKeychainService = "com.automicvault.verified-launcher-helpers"
private let verifiedLauncherHelpersKeychainAccount = "VerifiedLauncherHelpersV1"

public struct VerifiedLauncherHelper: Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let appName: String
    public let appBundleIdentifier: String
    public let appTeamIdentifier: String
    public let helperSigningIdentifier: String
    public let helperTeamIdentifier: String

    public init(
        id: String,
        name: String,
        appName: String,
        appBundleIdentifier: String,
        appTeamIdentifier: String,
        helperSigningIdentifier: String,
        helperTeamIdentifier: String
    ) {
        self.id = id
        self.name = name
        self.appName = appName
        self.appBundleIdentifier = appBundleIdentifier
        self.appTeamIdentifier = appTeamIdentifier
        self.helperSigningIdentifier = helperSigningIdentifier
        self.helperTeamIdentifier = helperTeamIdentifier
    }
}

public let codexVerifiedLauncherHelper = VerifiedLauncherHelper(
    id: "codex",
    name: "Codex CLI",
    appName: "ChatGPT",
    appBundleIdentifier: "com.openai.codex",
    appTeamIdentifier: "2DC432GLL2",
    helperSigningIdentifier: "codex",
    helperTeamIdentifier: "2DC432GLL2"
)

public let claudeCodeVerifiedLauncherHelper = VerifiedLauncherHelper(
    id: "claude-code",
    name: "Claude Code",
    appName: "Claude",
    appBundleIdentifier: "com.anthropic.claudefordesktop",
    appTeamIdentifier: "Q6L2SF6YDW",
    helperSigningIdentifier: "com.anthropic.claude-code",
    helperTeamIdentifier: "Q6L2SF6YDW"
)

public let verifiedLauncherHelpers = [
    codexVerifiedLauncherHelper,
    claudeCodeVerifiedLauncherHelper,
]

public struct VerifiedLauncherHelperConfiguration: Codable, Equatable, Sendable {
    public var disabledHelperIDs: Set<String>

    public init(disabledHelperIDs: Set<String> = []) {
        self.disabledHelperIDs = disabledHelperIDs
    }

    public func isEnabled(_ helper: VerifiedLauncherHelper) -> Bool {
        !disabledHelperIDs.contains(helper.id)
    }
}

public func loadVerifiedLauncherHelperConfiguration() -> VerifiedLauncherHelperConfiguration {
    loadVerifiedLauncherHelperConfiguration(
        service: verifiedLauncherHelpersKeychainService,
        account: verifiedLauncherHelpersKeychainAccount
    )
}

func loadVerifiedLauncherHelperConfiguration(
    service: String,
    account: String
) -> VerifiedLauncherHelperConfiguration {
    switch loadKeychainDataResult(service: service, account: account) {
    case .notFound:
        return VerifiedLauncherHelperConfiguration()
    case .failure:
        return failClosedVerifiedLauncherHelperConfiguration
    case .success(let data):
        return decodeVerifiedLauncherHelperConfiguration(data)
    }
}

func decodeVerifiedLauncherHelperConfiguration(
    _ data: Data
) -> VerifiedLauncherHelperConfiguration {
    (try? JSONDecoder().decode(
        VerifiedLauncherHelperConfiguration.self,
        from: data
    )) ?? failClosedVerifiedLauncherHelperConfiguration
}

@discardableResult
public func saveVerifiedLauncherHelperConfiguration(
    _ configuration: VerifiedLauncherHelperConfiguration
) -> OSStatus {
    saveVerifiedLauncherHelperConfiguration(
        configuration,
        service: verifiedLauncherHelpersKeychainService,
        account: verifiedLauncherHelpersKeychainAccount
    )
}

@discardableResult
func saveVerifiedLauncherHelperConfiguration(
    _ configuration: VerifiedLauncherHelperConfiguration,
    service: String,
    account: String
) -> OSStatus {
    guard let data = try? JSONEncoder().encode(configuration) else { return errSecParam }
    return saveKeychainData(
        data,
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    )
}

private let failClosedVerifiedLauncherHelperConfiguration = VerifiedLauncherHelperConfiguration(
    disabledHelperIDs: Set(verifiedLauncherHelpers.map(\.id))
)
