import Foundation
import MenubarHelperCore
import Testing

@Test func dotenvSchemaDeclarationsAreStaticAndDirect() {
    let schema = Data("""
    # @plugin(@automic-vault/varlock-plugin)
    DATABASE_URL=av()
    STRIPE_API_KEY = av(STRIPE_PROD_API_KEY) # @sensitive
    QUOTED=av("QUOTED_SECRET")
    DYNAMIC=av(ref(SECRET_NAME))
    # COMMENTED=av(COMMENTED_SECRET)
    """.utf8)

    #expect(dotenvSchemaDeclarations(data: schema) == [
        DotenvSecretDeclaration(item: "DATABASE_URL", secret: "DATABASE_URL"),
        DotenvSecretDeclaration(item: "STRIPE_API_KEY", secret: "STRIPE_PROD_API_KEY"),
        DotenvSecretDeclaration(item: "QUOTED", secret: "QUOTED_SECRET"),
    ])
    #expect(dotenvSchemaDeclaration(
        data: schema,
        item: "STRIPE_API_KEY",
        secret: "STRIPE_PROD_API_KEY"
    ) != nil)
    #expect(dotenvSchemaDeclaration(data: schema, item: "DYNAMIC", secret: "SECRET_NAME") == nil)
}

@Test func blessedDotenvMatchesHashProcessChainAndLauncher() {
    let process = BlessedDotenvProcess(
        path: "/opt/homebrew/bin/node",
        arguments: ["node", "src/release.js"],
        cwd: "/repo"
    )
    let dotenv = BlessedDotenv(
        path: "/repo/.env.schema",
        checksum: "abc",
        processes: [process],
        launchers: [BlessedScriptLauncher(bundleIdentifier: "com.openai.codex", requirement: "codex")]
    )

    #expect(dotenv.matches(
        path: "/repo/.env.schema",
        checksum: "abc",
        processes: [process],
        launcherRequirement: "codex"
    ))
    #expect(!dotenv.matches(
        path: "/repo/.env.schema",
        checksum: "changed",
        processes: [process],
        launcherRequirement: "codex"
    ))
    #expect(!dotenv.matches(
        path: "/repo/.env.schema",
        checksum: "abc",
        processes: [BlessedDotenvProcess(
            path: process.path,
            arguments: ["node", "src/other.js"],
            cwd: process.cwd
        )],
        launcherRequirement: "codex"
    ))
}
