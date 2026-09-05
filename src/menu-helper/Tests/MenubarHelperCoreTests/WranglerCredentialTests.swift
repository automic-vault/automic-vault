import Testing
@testable import MenubarHelperCore

@Test func wranglerMutationsStayInsideTheirCredentialNamespace() {
    #expect(isWranglerCredentialKey("WRANGLER_AUTH_64656661756C74"))
    for key in ["GH_TOKEN_GITHUB_COM", "WRANGLER_AUTH_", "WRANGLER_AUTH_*", "WRANGLER_AUTH_0", "WRANGLER_AUTH_aa", "WRANGLER_AUTH_00\0", "WRANGLER_AUTH_" + String(repeating: "A", count: 500)] {
        #expect(!isWranglerCredentialKey(key))
    }
}
