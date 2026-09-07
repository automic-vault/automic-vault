import Foundation
import Security

private let verifiedLauncherHelpersKeychainService = "com.automicvault.verified-launcher-helpers"
private let verifiedLauncherHelpersKeychainAccount = "VerifiedLauncherHelpersV1"

public struct VerifiedLauncherHelper: Identifiable, Codable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let appName: String
    public let appBundleIdentifier: String
    public let appTeamIdentifier: String
    public let helperSigningIdentifier: String
    public let helperTeamIdentifier: String
    public let relativePath: String?

    public init(
        id: String,
        name: String,
        appName: String,
        appBundleIdentifier: String,
        appTeamIdentifier: String,
        helperSigningIdentifier: String,
        helperTeamIdentifier: String,
        relativePath: String? = nil
    ) {
        self.id = id
        self.name = name
        self.appName = appName
        self.appBundleIdentifier = appBundleIdentifier
        self.appTeamIdentifier = appTeamIdentifier
        self.helperSigningIdentifier = helperSigningIdentifier
        self.helperTeamIdentifier = helperTeamIdentifier
        self.relativePath = relativePath
    }

    public func hasSameSigningAssociation(as other: Self) -> Bool {
        appBundleIdentifier == other.appBundleIdentifier
            && appTeamIdentifier == other.appTeamIdentifier
            && helperSigningIdentifier == other.helperSigningIdentifier
            && helperTeamIdentifier == other.helperTeamIdentifier
            && (relativePath == nil || other.relativePath == nil || relativePath == other.relativePath)
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
    public var userApprovedHelpers: [VerifiedLauncherHelper]

    public init(
        disabledHelperIDs: Set<String> = [],
        userApprovedHelpers: [VerifiedLauncherHelper] = []
    ) {
        self.disabledHelperIDs = disabledHelperIDs
        self.userApprovedHelpers = userApprovedHelpers
    }

    public func isEnabled(_ helper: VerifiedLauncherHelper) -> Bool {
        guard let helper = catalogHelper(matching: helper) else { return false }
        return !disabledHelperIDs.contains(helper.id)
    }

    public var helpers: [VerifiedLauncherHelper] {
        verifiedLauncherHelpers + userApprovedHelpers
    }

    public func catalogHelper(matching discovered: VerifiedLauncherHelper) -> VerifiedLauncherHelper? {
        helpers.first { $0.hasSameSigningAssociation(as: discovered) }
    }

    public mutating func enable(_ helpers: [VerifiedLauncherHelper]) {
        for discovered in helpers {
            let isValid = verifiedLauncherHelpers.contains(discovered)
                || isValidUserApprovedHelper(discovered)
            guard isValid else { continue }
            if let helper = catalogHelper(matching: discovered) {
                disabledHelperIDs.remove(helper.id)
            } else {
                userApprovedHelpers.append(discovered)
                disabledHelperIDs.remove(discovered.id)
            }
        }
        userApprovedHelpers.sort { $0.id < $1.id }
    }

    private enum CodingKeys: String, CodingKey {
        case disabledHelperIDs
        case userApprovedHelpers
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        disabledHelperIDs = try container.decodeIfPresent(
            Set<String>.self,
            forKey: .disabledHelperIDs
        ) ?? []
        userApprovedHelpers = try container.decodeIfPresent(
            [VerifiedLauncherHelper].self,
            forKey: .userApprovedHelpers
        ) ?? []
        guard isValidVerifiedLauncherHelperConfiguration(self) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid user-approved Launcher helper catalog")
            )
        }
    }
}

public func userApprovedVerifiedLauncherHelperID(_ helper: VerifiedLauncherHelper) -> String {
    "user:" + [
        helper.appTeamIdentifier,
        helper.appBundleIdentifier,
        helper.helperTeamIdentifier,
        helper.helperSigningIdentifier,
        helper.relativePath ?? "",
    ].map { "\($0.utf8.count):\($0)" }.joined()
}

@concurrent
public func discoverVerifiedLauncherHelpers(in appURL: URL) async -> [VerifiedLauncherHelper] {
    let appURL = appURL.standardizedFileURL.resolvingSymlinksInPath()
    guard appURL.pathExtension.caseInsensitiveCompare("app") == .orderedSame,
          let appBundle = Bundle(url: appURL),
          let appBundleIdentifier = appBundle.bundleIdentifier,
          let appExecutableURL = appBundle.executableURL?.standardizedFileURL.resolvingSymlinksInPath(),
          let appCode = staticCode(at: appURL),
          validateAppBundleMainExecutable(appCode) == errSecSuccess,
          let appSigning = signingIdentity(appCode),
          let appTeamIdentifier = appSigning.teamIdentifier,
          let developerIDRequirement = developerIDRequirement()
    else { return [] }

    let contentsURL = appURL.appendingPathComponent("Contents", isDirectory: true)
    guard let enumerator = FileManager.default.enumerator(
        at: contentsURL,
        includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
        options: [],
        errorHandler: { _, _ in true }
    ) else { return [] }

    var helpers: [VerifiedLauncherHelper] = []
    while let candidate = enumerator.nextObject() as? URL {
        guard !Task.isCancelled else { return [] }
        guard let values = try? candidate.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              values.isRegularFile == true,
              values.isSymbolicLink != true,
              FileManager.default.isExecutableFile(atPath: candidate.path)
        else { continue }

        let executableURL = candidate.standardizedFileURL.resolvingSymlinksInPath()
        guard executableURL != appExecutableURL,
              let helperCode = staticCode(at: executableURL),
              SecStaticCodeCheckValidity(
                  helperCode,
                  SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
                  developerIDRequirement
              ) == errSecSuccess,
              validateAppBundleResource(appCode, resourceURL: executableURL) == errSecSuccess,
              let helperSigning = signingIdentity(helperCode),
              let helperTeamIdentifier = helperSigning.teamIdentifier,
              launcherRuntimeProtection(signingInformation: helperSigning.information)
                  .allowsSecretGateAccess
        else { continue }

        guard let relativePath = verifiedLauncherHelperRelativePath(
            for: executableURL,
            inside: appURL
        ) else { continue }
        var helper = VerifiedLauncherHelper(
            id: "",
            name: helperDisplayName(executableURL, inside: appURL),
            appName: appDisplayName(appBundle, url: appURL),
            appBundleIdentifier: appBundleIdentifier,
            appTeamIdentifier: appTeamIdentifier,
            helperSigningIdentifier: helperSigning.identifier,
            helperTeamIdentifier: helperTeamIdentifier,
            relativePath: relativePath
        )
        helper = VerifiedLauncherHelper(
            id: userApprovedVerifiedLauncherHelperID(helper),
            name: helper.name,
            appName: helper.appName,
            appBundleIdentifier: helper.appBundleIdentifier,
            appTeamIdentifier: helper.appTeamIdentifier,
            helperSigningIdentifier: helper.helperSigningIdentifier,
            helperTeamIdentifier: helper.helperTeamIdentifier,
            relativePath: helper.relativePath
        )
        if !helpers.contains(where: { $0.id == helper.id }) { helpers.append(helper) }
    }
    return helpers.sorted {
        let order = $0.name.localizedCaseInsensitiveCompare($1.name)
        return order == .orderedSame
            ? ($0.relativePath ?? "") < ($1.relativePath ?? "")
            : order == .orderedAscending
    }
}

func verifiedLauncherHelperRelativePath(for executableURL: URL, inside appURL: URL) -> String? {
    let appURL = appURL.standardizedFileURL.resolvingSymlinksInPath()
    let executableURL = executableURL.standardizedFileURL.resolvingSymlinksInPath()
    let prefix = appURL.path + "/"
    guard executableURL.path.hasPrefix(prefix) else { return nil }
    return String(executableURL.path.dropFirst(prefix.count))
}

private func isValidUserApprovedHelper(_ helper: VerifiedLauncherHelper) -> Bool {
    guard helper.id == userApprovedVerifiedLauncherHelperID(helper),
          !helper.name.isEmpty,
          !helper.appName.isEmpty,
          !helper.appBundleIdentifier.isEmpty,
          !helper.appTeamIdentifier.isEmpty,
          !helper.helperSigningIdentifier.isEmpty,
          !helper.helperTeamIdentifier.isEmpty,
          let relativePath = helper.relativePath,
          !relativePath.isEmpty,
          !relativePath.hasPrefix("/")
    else { return false }
    return !relativePath.split(separator: "/", omittingEmptySubsequences: false).contains {
        $0.isEmpty || $0 == "." || $0 == ".."
    }
}

private func isValidVerifiedLauncherHelperConfiguration(
    _ configuration: VerifiedLauncherHelperConfiguration
) -> Bool {
    Set(configuration.userApprovedHelpers.map(\.id)).count
        == configuration.userApprovedHelpers.count
        && configuration.userApprovedHelpers.allSatisfy(isValidUserApprovedHelper)
        && configuration.userApprovedHelpers.allSatisfy { helper in
            !verifiedLauncherHelpers.contains { $0.hasSameSigningAssociation(as: helper) }
        }
}

private struct HelperSigningIdentity {
    let identifier: String
    let teamIdentifier: String?
    let information: [CFString: Any]
}

private func staticCode(at url: URL) -> SecStaticCode? {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess else { return nil }
    return code
}

private func signingIdentity(_ code: SecStaticCode) -> HelperSigningIdentity? {
    var rawInformation: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    guard SecCodeCopySigningInformation(code, flags, &rawInformation) == errSecSuccess,
          let information = rawInformation as? [CFString: Any],
          let identifier = information[kSecCodeInfoIdentifier] as? String
    else { return nil }
    return HelperSigningIdentity(
        identifier: identifier,
        teamIdentifier: information[kSecCodeInfoTeamIdentifier] as? String,
        information: information
    )
}

private func developerIDRequirement() -> SecRequirement? {
    var requirement: SecRequirement?
    let source = """
    anchor apple generic and \
    certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
    certificate leaf[field.1.2.840.113635.100.6.1.13] exists
    """
    guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess
    else { return nil }
    return requirement
}

private func appDisplayName(_ bundle: Bundle, url: URL) -> String {
    bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
        ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String
        ?? url.deletingPathExtension().lastPathComponent
}

private func helperDisplayName(_ executableURL: URL, inside appURL: URL) -> String {
    var container = executableURL.deletingLastPathComponent()
    while container.path.count > appURL.path.count {
        if container.pathExtension.caseInsensitiveCompare("app") == .orderedSame,
           let bundle = Bundle(url: container),
           bundle.executableURL?.standardizedFileURL.resolvingSymlinksInPath() == executableURL
        {
            return appDisplayName(bundle, url: container)
        }
        container.deleteLastPathComponent()
    }
    return executableURL.lastPathComponent
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
    guard isValidVerifiedLauncherHelperConfiguration(configuration),
          let data = try? JSONEncoder().encode(configuration)
    else { return errSecParam }
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
