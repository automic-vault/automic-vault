import Testing
@testable import MenubarHelperCore

@Test func everyGenericHardenerClassifiesAReadOnlyCommand() {
    let commands: [String: [String]] = [
        "akamai": ["config", "list"],
        "algolia": ["profile", "list"],
        "argocd": ["app", "get", "example"],
        "ast-cli": ["scan", "list"],
        "buf": ["repository", "list"],
        "censys": ["search", "example"],
        "checkov": ["frameworks"],
        "circleci": ["pipeline", "list"],
        "civo": ["instance", "list"],
        "cloudsmith-cli": ["packages", "list"],
        "composer": ["audit"],
        "doctl": ["account", "get"],
        "flyctl": ["apps", "list"],
        "glab": ["repo", "view"],
        "gotify": ["health"],
        "gptcommit": ["--version"],
        "grafanactl": ["resources", "list"],
        "heroku": ["apps"],
        "hcloud": ["server", "list"],
        "huggingface-cli": ["auth", "whoami"],
        "jfrog-cli": ["rt", "ping"],
        "k6": ["inspect", "script.js"],
        "luarocks": ["search", "example"],
        "minio-mc": ["ls", "alias/bucket"],
        "netlify-cli": ["sites", "list"],
        "node": ["view", "example"],
        "pnpm": ["view", "example"],
        "pulumi": ["stack", "ls"],
        "qwen-code": ["--version"],
        "runpodctl": ["get", "pod"],
        "s3cmd": ["ls", "s3://bucket"],
        "sentry-cli": ["projects", "list"],
        "snowflake-cli": ["object", "list"],
        "snyk": ["--version"],
        "transifex-cli": ["status"],
        "travis": ["whoami"],
        "twine": ["check", "dist/*"],
        "vagrant": ["status"],
        "vault": ["token", "lookup"],
        "virustotal-cli": ["domain", "example.com"],
        "vultr": ["instance", "list"],
        "wsk": ["action", "list"],
        "stripe": ["customers", "list"],
        "supabase": ["projects", "list"],
    ]

    #expect(commands.count == 44)
    #expect(Set(commands.keys) == genericSecretGatePolicyIDs)
    for (gateID, arguments) in commands {
        #expect(
            genericSecretGateRequestClassification(gateID: gateID, arguments: arguments) == .readOnly,
            "missing read-only policy for \(gateID)"
        )
    }
}

@Test func genericPoliciesClassifyMutationsSecretsAndUnknowns() {
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["deploy"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["auth", "token"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "stripe",
        arguments: ["sandbox", "create", "--from-git", "--non-interactive", "--config", "/tmp/config.toml"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: ["sandbox", "claim"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["future-command"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "future-hardener", arguments: ["list"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: []) == .unknown)
}

@Test func stripePolicyClassifiesGeneratedBuiltInAndPluginCommands() {
    let readOnly = [
        ["customers", "list"],
        ["billing", "alerts", "retrieve", "al_123"],
        ["climate", "commitment", "show"],
        ["v2", "core", "account_persons", "retrieve", "acct_123"],
        ["--config", "/tmp/config.toml", "payment_intents", "search", "--query", "status:'succeeded'"],
        ["--config", "/tmp/config.toml", "--help"],
        ["--config", "/tmp/config.toml", "--version"],
        ["--config", "/tmp/config.toml", "--map=json", "customers", "create", "--name", "Jenny"],
        ["keys", "permissions", "GET /v1/customers"],
        ["agent", "setup", "--status"],
        ["login", "list"],
        ["reporting", "query-runs", "retrieve", "sqr_123"],
    ]
    for arguments in readOnly {
        #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: arguments) == .readOnly)
    }

    let mutating = [
        ["customers", "create", "--name", "Jenny"],
        ["customers", "create", "--name", "-h"],
        ["billing", "alerts", "archive", "al_123"],
        ["events", "resend", "evt_123"],
        ["terminal", "quickstart"],
        ["v2", "core", "account_persons", "delete", "acct_123"],
        ["post", "/v1/customers"],
        ["samples", "create", "accept-a-payment"],
        ["reporting", "query-runs", "create", "--sql", "select 1"],
    ]
    for arguments in mutating {
        #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: arguments) == .mutating)
    }

    #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: ["listen"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: ["config", "--list"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: ["projects", "add", "database"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: ["customers", "future-operation"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "stripe", arguments: ["future-resource", "list"]) == .unknown)
}

@Test func npmPolicyUsesSpecificSubcommandsBeforeBroadFallbacks() {
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["access", "list", "packages"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["access", "grant", "read-only"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["audit"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["audit", "signatures"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["audit", "fix"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["stage", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["stage", "publish"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "node", arguments: ["ls"]) == .unknown)
}

@Test func pnpmPolicyKeepsCompoundOperationsNarrow() {
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["audit"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["audit", "signatures"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["audit", "--fix"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["audit", "--fix=override"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["audit", "future-command"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["dist-tag", "ls"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["dist-tag", "add"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["stage", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["stage", "download"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["stage", "approve"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["install"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "pnpm", arguments: ["config", "get", "//registry.example/:_authToken"]) == .secretDump)
}

@Test func k6PolicyKeepsCloudCredentialRoutingNarrow() {
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["cloud", "project", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["--quiet", "cloud", "test", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["--quiet=false", "cloud", "test", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["cloud", "run", "script.js"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["cloud", "upload", "script.js"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["run", "--out", "cloud", "script.js"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["run", "-ocloud", "script.js"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["run", "script.js"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["run", "--out", "json", "script.js"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["cloud", "login"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["cloud", "future-command"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "k6", arguments: ["--future-option", "cloud", "run"]) == .unknown)
}
