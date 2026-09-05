import Testing
@testable import MenubarHelperCore

@Test func wranglerMutationsStayInsideTheirCredentialNamespace() {
    #expect(isWranglerCredentialKey("WRANGLER_AUTH_64656661756C74"))
    for key in ["GH_TOKEN_GITHUB_COM", "WRANGLER_AUTH_", "WRANGLER_AUTH_*", "WRANGLER_AUTH_0", "WRANGLER_AUTH_aa", "WRANGLER_AUTH_00\0", "WRANGLER_AUTH_" + String(repeating: "A", count: 500)] {
        #expect(!isWranglerCredentialKey(key))
    }
}

@Test func wranglerRefreshCannotBroadenAProjectCredential() {
    let key = "WRANGLER_AUTH_64656661756C74"
    func selection(_ source: StoredSecretValueSource) -> SelectedSecretValues {
        SelectedSecretValues(values: [key: StoredSecretValue(
            source: source, keychainAccount: key, accessibility: .whenUnlocked,
            keychainProperties: []
        )])
    }
    #expect(wranglerCredentialSelectionIsSupported(selection(.global)))
    #expect(!wranglerCredentialSelectionIsSupported(selection(.projectDirectory("/project"))))
    #expect(wranglerCredentialSelectionIsSupported(SelectedSecretValues(values: [:])))
}

@Test func wranglerMutationsRejectProjectValues() {
    let key = "WRANGLER_AUTH_64656661756C74"
    #expect(wranglerCredentialMutationIsSupported(key: key, hasProjectDirectory: false))
    #expect(!wranglerCredentialMutationIsSupported(key: key, hasProjectDirectory: true))
    #expect(!wranglerCredentialMutationIsSupported(key: "GH_TOKEN_GITHUB_COM", hasProjectDirectory: false))
}
