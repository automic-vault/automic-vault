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
}

@Test func malformedVerifiedLauncherHelperConfigurationFailsClosed() {
    let configuration = decodeVerifiedLauncherHelperConfiguration(Data("not json".utf8))
    #expect(!configuration.isEnabled(codexVerifiedLauncherHelper))
    #expect(!configuration.isEnabled(claudeCodeVerifiedLauncherHelper))
}
