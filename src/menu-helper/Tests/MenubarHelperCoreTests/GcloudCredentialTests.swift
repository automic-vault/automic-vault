import Testing
@testable import MenubarHelperCore

@Test func gcloudNamesCannotEscapeTheirAccountNamespace() {
    #expect(isGcloudCredentialKey("GCLOUD_AUTH_6140622E63"))
    for name in ["GCLOUD_AUTH_", "GCLOUD_AUTH_*", "GCLOUD_AUTH_A", "GCLOUD_AUTH_aa", "GCLOUD_AUTH_00", "GCLOUD_AUTH_FF", "GH_TOKEN", "GCLOUD_AUTH_" + String(repeating: "41", count: 241)] {
        #expect(!isGcloudCredentialKey(name))
    }
}

@Test func gcloudRefreshRejectsProjectValues() {
    let key = "GCLOUD_AUTH_6140622E63"
    func selection(_ source: StoredSecretValueSource) -> SelectedSecretValues {
        SelectedSecretValues(values: [key: StoredSecretValue(
            source: source, keychainAccount: key, accessibility: .whenUnlocked,
            keychainProperties: []
        )])
    }
    #expect(gcloudCredentialSelectionIsSupported(selection(.global)))
    #expect(!gcloudCredentialSelectionIsSupported(selection(.projectDirectory("/project"))))
}

@Test func gcloudRejectsCredentialTypeAndEndpointSubstitution() {
    let valid = #"{"type":"authorized_user","universe_domain":"googleapis.com","client_id":"test","client_secret":"test","refresh_token":"test","token_uri":"https://oauth2.googleapis.com/token","revoke_uri":"https://oauth2.googleapis.com/revoke"}"#
    #expect(gcloudCredentialIsSupported(valid))
    #expect(!gcloudCredentialIsSupported(valid.replacingOccurrences(of: "authorized_user", with: "external_account")))
    #expect(!gcloudCredentialIsSupported(valid.replacingOccurrences(of: "oauth2.googleapis.com/token", with: "attacker.example/token")))
    #expect(!gcloudCredentialIsSupported(valid.replacingOccurrences(of: "refresh_token", with: "access_token")))
    #expect(!gcloudCredentialIsSupported("{}"))
}

@Test func gcloudStaleRefreshAndLogoutCannotReplaceNewLogin() {
    #expect(gcloudCredentialMatchesExpected(current: nil, expected: nil))
    #expect(gcloudCredentialMatchesExpected(current: "old", expected: "old"))
    #expect(!gcloudCredentialMatchesExpected(current: "new", expected: "old"))
    #expect(!gcloudCredentialMatchesExpected(current: nil, expected: "old"))
    #expect(!gcloudCredentialMatchesExpected(current: "new", expected: nil))
}
