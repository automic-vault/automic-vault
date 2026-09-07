import Foundation
import Testing
@testable import MenubarHelperCore

@Test func verifiedLauncherHelpersDefaultOnAndRoundTripDisabledEntries() throws {
    let defaults = VerifiedLauncherHelperConfiguration()
    #expect(defaults.isEnabled(codexVerifiedLauncherHelper))
    #expect(defaults.isEnabled(claudeCodeVerifiedLauncherHelper))

    let configured = VerifiedLauncherHelperConfiguration(
        disabledHelperIDs: [codexVerifiedLauncherHelper.id, "future-helper"]
    )
    let data = try JSONEncoder().encode(configured)
    #expect(decodeVerifiedLauncherHelperConfiguration(data) == configured)

    var enabled = configured
    enabled.enable([codexVerifiedLauncherHelper])
    #expect(enabled.isEnabled(codexVerifiedLauncherHelper))
}

@Test func malformedVerifiedLauncherHelperConfigurationFailsClosed() {
    let configuration = decodeVerifiedLauncherHelperConfiguration(Data("not json".utf8))
    #expect(!configuration.isEnabled(codexVerifiedLauncherHelper))
    #expect(!configuration.isEnabled(claudeCodeVerifiedLauncherHelper))
}

@Test func enablesAndRoundTripsAnExactUserApprovedHelper() throws {
    let helper = userApprovedHelper()
    var configuration = VerifiedLauncherHelperConfiguration(disabledHelperIDs: [helper.id])
    configuration.enable([helper])

    #expect(configuration.userApprovedHelpers == [helper])
    #expect(configuration.isEnabled(helper))
    #expect(configuration.catalogHelper(matching: helper) == helper)
    let data = try JSONEncoder().encode(configuration)
    #expect(decodeVerifiedLauncherHelperConfiguration(data) == configuration)
}

@Test func discoveredHelperRequiresUserApprovalBeforeItIsEnabled() {
    #expect(!VerifiedLauncherHelperConfiguration().isEnabled(userApprovedHelper()))
}

@Test func enablingInvalidDiscoveredHelperDoesNotCorruptTheCatalog() throws {
    let valid = userApprovedHelper()
    let invalid = VerifiedLauncherHelper(
        id: "forged",
        name: valid.name,
        appName: valid.appName,
        appBundleIdentifier: valid.appBundleIdentifier,
        appTeamIdentifier: valid.appTeamIdentifier,
        helperSigningIdentifier: valid.helperSigningIdentifier,
        helperTeamIdentifier: valid.helperTeamIdentifier,
        relativePath: valid.relativePath
    )
    var configuration = VerifiedLauncherHelperConfiguration(disabledHelperIDs: [invalid.id])
    configuration.enable([invalid])

    #expect(configuration.userApprovedHelpers.isEmpty)
    #expect(configuration.disabledHelperIDs.contains(invalid.id))
    let data = try JSONEncoder().encode(configuration)
    #expect(decodeVerifiedLauncherHelperConfiguration(data) == configuration)
}

@Test func invalidHelperCannotEnableAMatchingBuiltInAssociation() {
    let invalid = VerifiedLauncherHelper(
        id: codexVerifiedLauncherHelper.id,
        name: codexVerifiedLauncherHelper.name,
        appName: codexVerifiedLauncherHelper.appName,
        appBundleIdentifier: codexVerifiedLauncherHelper.appBundleIdentifier,
        appTeamIdentifier: codexVerifiedLauncherHelper.appTeamIdentifier,
        helperSigningIdentifier: codexVerifiedLauncherHelper.helperSigningIdentifier,
        helperTeamIdentifier: codexVerifiedLauncherHelper.helperTeamIdentifier,
        relativePath: "../codex"
    )
    var configuration = VerifiedLauncherHelperConfiguration(
        disabledHelperIDs: [codexVerifiedLauncherHelper.id]
    )
    configuration.enable([invalid])

    #expect(!configuration.isEnabled(codexVerifiedLauncherHelper))
}

@Test func storedUserApprovedHelperCannotShadowABuiltInAssociation() throws {
    let shadow = VerifiedLauncherHelper(
        id: "",
        name: codexVerifiedLauncherHelper.name,
        appName: codexVerifiedLauncherHelper.appName,
        appBundleIdentifier: codexVerifiedLauncherHelper.appBundleIdentifier,
        appTeamIdentifier: codexVerifiedLauncherHelper.appTeamIdentifier,
        helperSigningIdentifier: codexVerifiedLauncherHelper.helperSigningIdentifier,
        helperTeamIdentifier: codexVerifiedLauncherHelper.helperTeamIdentifier,
        relativePath: "Contents/Resources/codex"
    )
    let stored = VerifiedLauncherHelper(
        id: userApprovedVerifiedLauncherHelperID(shadow),
        name: shadow.name,
        appName: shadow.appName,
        appBundleIdentifier: shadow.appBundleIdentifier,
        appTeamIdentifier: shadow.appTeamIdentifier,
        helperSigningIdentifier: shadow.helperSigningIdentifier,
        helperTeamIdentifier: shadow.helperTeamIdentifier,
        relativePath: shadow.relativePath
    )
    let data = try JSONEncoder().encode(VerifiedLauncherHelperConfiguration(
        userApprovedHelpers: [stored]
    ))
    let configuration = decodeVerifiedLauncherHelperConfiguration(data)

    #expect(configuration.userApprovedHelpers.isEmpty)
    #expect(!configuration.isEnabled(codexVerifiedLauncherHelper))
    #expect(!configuration.isEnabled(claudeCodeVerifiedLauncherHelper))
}

@Test func helperRelativePathRejectsResolvedSymlinkEscape() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-helper-path-\(UUID().uuidString)", isDirectory: true)
    let app = root.appendingPathComponent("Example.app", isDirectory: true)
    let contents = app.appendingPathComponent("Contents", isDirectory: true)
    let outside = root.appendingPathComponent("Outside", isDirectory: true)
    let helper = outside.appendingPathComponent("helper")
    try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try Data().write(to: helper)
    try FileManager.default.createSymbolicLink(
        at: contents.appendingPathComponent("Helpers", isDirectory: true),
        withDestinationURL: outside
    )
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(verifiedLauncherHelperRelativePath(
        for: contents.appendingPathComponent("Helpers/helper"),
        inside: app
    ) == nil)
}

@Test func legacyConfigurationDecodesWithoutUserApprovedHelpers() {
    let configuration = decodeVerifiedLauncherHelperConfiguration(
        Data(#"{"disabledHelperIDs":["codex"]}"#.utf8)
    )
    #expect(configuration.disabledHelperIDs == ["codex"])
    #expect(configuration.userApprovedHelpers.isEmpty)
}

@Test func invalidUserApprovedHelperPathFailsClosed() throws {
    let valid = userApprovedHelper()
    let invalid = VerifiedLauncherHelper(
        id: "",
        name: valid.name,
        appName: valid.appName,
        appBundleIdentifier: valid.appBundleIdentifier,
        appTeamIdentifier: valid.appTeamIdentifier,
        helperSigningIdentifier: valid.helperSigningIdentifier,
        helperTeamIdentifier: valid.helperTeamIdentifier,
        relativePath: "../Other.app/Contents/MacOS/Other"
    )
    let encodedInvalid = VerifiedLauncherHelper(
        id: userApprovedVerifiedLauncherHelperID(invalid),
        name: invalid.name,
        appName: invalid.appName,
        appBundleIdentifier: invalid.appBundleIdentifier,
        appTeamIdentifier: invalid.appTeamIdentifier,
        helperSigningIdentifier: invalid.helperSigningIdentifier,
        helperTeamIdentifier: invalid.helperTeamIdentifier,
        relativePath: invalid.relativePath
    )
    let data = try JSONEncoder().encode(VerifiedLauncherHelperConfiguration(
        userApprovedHelpers: [encodedInvalid]
    ))
    let configuration = decodeVerifiedLauncherHelperConfiguration(data)
    #expect(!configuration.isEnabled(codexVerifiedLauncherHelper))
    #expect(configuration.userApprovedHelpers.isEmpty)
}

private func userApprovedHelper() -> VerifiedLauncherHelper {
    let helper = VerifiedLauncherHelper(
        id: "",
        name: "Package Manager Manager Menu",
        appName: "Package Manager Manager",
        appBundleIdentifier: "dev.mxcl.pmm",
        appTeamIdentifier: "ZU76A67LGU",
        helperSigningIdentifier: "dev.mxcl.pmm.menu",
        helperTeamIdentifier: "ZU76A67LGU",
        relativePath: "Contents/Library/LoginItems/Package Manager Manager Menu.app/Contents/MacOS/PMMMenuBar"
    )
    return VerifiedLauncherHelper(
        id: userApprovedVerifiedLauncherHelperID(helper),
        name: helper.name,
        appName: helper.appName,
        appBundleIdentifier: helper.appBundleIdentifier,
        appTeamIdentifier: helper.appTeamIdentifier,
        helperSigningIdentifier: helper.helperSigningIdentifier,
        helperTeamIdentifier: helper.helperTeamIdentifier,
        relativePath: helper.relativePath
    )
}

@Test(.enabled(if: FileManager.default.fileExists(
    atPath: "/Applications/Package Manager Manager.app"
)))
func discoversInstalledPackageManagerManagerHelpers() async {
    let helpers = await discoverVerifiedLauncherHelpers(
        in: URL(fileURLWithPath: "/Applications/Package Manager Manager.app", isDirectory: true)
    )
    #expect(helpers.contains { $0.helperSigningIdentifier == "dev.mxcl.pmm.menu" })
    #expect(helpers.contains { $0.helperSigningIdentifier == "pmmctl" })
}
