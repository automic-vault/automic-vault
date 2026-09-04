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
        "gotify": ["version"],
        "gptcommit": ["config", "keys"],
        "grafanactl": ["resources", "list"],
        "heroku": ["apps"],
        "hcloud": ["server", "list"],
        "huggingface-cli": ["auth", "whoami"],
        "jfrog-cli": ["rt", "ping"],
        "k6": ["inspect", "script.js"],
        "luarocks": ["--version"],
        "minio-mc": ["ls", "alias/bucket"],
        "netlify-cli": ["sites:list"],
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
        "vagrant": ["box", "outdated"],
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

@Test func netlifyPolicyClassifiesCurrentCommandsAndLeadingOptions() {
    let readOnly = [
        ["sites:list"],
        ["--verbose", "agents:show", "agent-id"],
        ["database", "status", "--branch", "preview"],
        ["db", "migrations", "pull"],
    ]
    for arguments in readOnly {
        #expect(genericSecretGateRequestClassification(gateID: "netlify-cli", arguments: arguments) == .readOnly)
    }

    let mutating = [
        ["agents:run", "fix the build"],
        ["env:set", "KEY", "value"],
        ["recipes", "blobs-migrate", "store"],
        ["recipes", "--name=blobs-migrate", "store"],
    ]
    for arguments in mutating {
        #expect(genericSecretGateRequestClassification(gateID: "netlify-cli", arguments: arguments) == .mutating)
    }

    #expect(genericSecretGateRequestClassification(
        gateID: "netlify-cli",
        arguments: ["database", "status", "--branch", "preview", "--show-credentials"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "netlify-cli",
        arguments: ["blobs:get", "store", "key"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "netlify-cli",
        arguments: ["api", "getSite"]
    ) == .unknown)
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

@Test func gptcommitPolicyClassifiesReviewedCommands() {
    #expect(genericSecretGateRequestClassification(gateID: "gptcommit", arguments: ["config", "keys"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "gptcommit", arguments: ["install"]) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "gptcommit",
        arguments: ["prepare-commit-msg", "--commit-msg-file", "/tmp/message", "--commit-source", ""]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "gptcommit",
        arguments: ["config", "get", "openai.api_key"]
    ) == .secretDump)
}

@Test func grafanactlPolicyClassifiesReviewedCommands() {
    #expect(genericSecretGateRequestClassification(gateID: "grafanactl", arguments: ["config", "check"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "grafanactl", arguments: ["resources", "pull"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "grafanactl", arguments: ["resources", "push"]) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "grafanactl",
        arguments: ["config", "view", "--raw"]
    ) == .secretDump)
}

@Test func herokuPolicyClassifiesColonCommandsAndSecretOutput() {
    #expect(genericSecretGateRequestClassification(gateID: "heroku", arguments: ["status"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "heroku", arguments: ["apps:info", "example"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "heroku", arguments: ["apps:create", "example"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "heroku", arguments: ["auth:token"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "heroku", arguments: ["config:get", "DATABASE_URL"]) == .secretDump)
}

@Test func hcloudPolicyClassifiesApiAndExplicitSecretCommands() {
    #expect(genericSecretGateRequestClassification(gateID: "hcloud", arguments: ["server", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "hcloud",
        arguments: ["--context", "prod", "server", "list"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "hcloud", arguments: ["server", "create"]) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "hcloud",
        arguments: ["server", "create", "--", "--help"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "hcloud",
        arguments: ["context", "create", "--token-from-env", "dev"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "hcloud",
        arguments: ["--quiet", "config", "get", "--allow-sensitive", "token"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "hcloud",
        arguments: ["config", "list", "--json", "--allow-sensitive"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "hcloud",
        arguments: ["config", "list", "--allow-sensitive=false"]
    ) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "hcloud", arguments: ["server", "future"]) == .unknown)
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
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["--global", "install"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["--registry", "https://registry.npmjs.org", "view", "example"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["install", "--version"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["--cache", "install", "run", "build"]
    ) == .unknown)
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["-gq", "install"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["-C/tmp", "view", "example"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "node",
        arguments: ["install", "--", "--version"]
    ) == .mutating)
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

@Test func twinePolicyRecognizesOnlyBuiltInCommands() {
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["check", "dist/package.whl"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["upload", "dist/package.whl"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["--no-color", "check", "dist/package.whl"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["--no-color", "upload", "dist/package.whl"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["--", "upload", "dist/package.whl"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["--", "--no-color", "upload"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["--", "--", "upload"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["register", "dist/package.whl"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["plugin-command"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "twine", arguments: ["--future-option", "upload"]) == .unknown)
}

@Test func vagrantPolicyRecognizesOnlyCommandsThatCanUseCloudCredentials() {
    let readOnly = [
        ["login"],
        ["box", "outdated"],
        ["cloud", "search", "private-box"],
        ["cloud", "box", "show", "owner/private-box"],
        ["cloud", "auth", "whoami"],
        ["--debug", "cloud", "search", "private-box"],
    ]
    for arguments in readOnly {
        #expect(genericSecretGateRequestClassification(gateID: "vagrant", arguments: arguments) == .readOnly)
    }

    let mutating = [
        ["up"],
        ["reload"],
        ["resume"],
        ["snapshot", "restore", "before-upgrade"],
        ["box", "add", "owner/private-box"],
        ["box", "update"],
        ["cloud", "publish", "owner/box"],
        ["cloud", "provider", "upload", "owner/box"],
        ["--machine-readable", "cloud", "box", "create", "owner/box"],
    ]
    for arguments in mutating {
        #expect(genericSecretGateRequestClassification(gateID: "vagrant", arguments: arguments) == .mutating)
    }

    for arguments in [
        ["destroy"],
        ["halt"],
        ["suspend"],
        ["ssh"],
        ["plugin-command"],
        ["future-command"],
        ["cloud", "future-command"],
        ["box", "list"],
    ] {
        #expect(genericSecretGateRequestClassification(gateID: "vagrant", arguments: arguments) == .unknown)
    }
}

@Test func huggingFacePolicyClassifiesReviewedHubCommands() {
    for arguments in [
        ["auth", "whoami"],
        ["cache", "verify", "private/repo"],
        ["download", "private/repo"],
        ["datasets", "info", "private/repo"],
        ["jobs", "scheduled", "inspect", "job-id"],
        ["repos", "tag", "list", "private/repo"],
        ["spaces", "secrets", "list", "private/space"],
    ] {
        #expect(genericSecretGateRequestClassification(
            gateID: "huggingface-cli",
            arguments: arguments
        ) == .readOnly)
    }

    for arguments in [
        ["upload", "private/repo", "."],
        ["collections", "add-item", "owner/collection"],
        ["endpoints", "catalog", "deploy"],
        ["jobs", "scheduled", "uv", "run", "script.py"],
        ["repo", "branch", "create", "private/repo", "new"],
        ["sandbox", "exec", "sandbox-id", "--", "command"],
        ["webhooks", "delete", "webhook-id"],
    ] {
        #expect(genericSecretGateRequestClassification(
            gateID: "huggingface-cli",
            arguments: arguments
        ) == .mutating)
    }

    #expect(genericSecretGateRequestClassification(
        gateID: "huggingface-cli",
        arguments: ["auth", "token"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "huggingface-cli",
        arguments: ["cp", "hf://private/repo/file", "."]
    ) == .unknown)
}

@Test func composerPolicyClassifiesOnlyCredentialedBuiltIns() {
    for arguments in [
        ["audit"],
        ["dia"],
        ["search", "private"],
        ["why-not", "private/package", "2"],
        ["show", "--latest"],
        ["browse", "private/package"],
    ] {
        #expect(genericSecretGateRequestClassification(
            gateID: "composer",
            arguments: arguments
        ) == .readOnly)
    }

    for arguments in [
        ["install"],
        ["ins"],
        ["req", "private/package:^1"],
        ["archive", "private/package"],
        ["archive", "--", "private/package"],
        ["init", "--repository", "https://private.example.invalid/packages.json"],
        ["global", "require", "private/package:^1"],
        ["--profile", "-d", "/tmp", "update"],
    ] {
        #expect(genericSecretGateRequestClassification(
            gateID: "composer",
            arguments: arguments
        ) == .mutating)
    }

    for arguments in [
        ["config", "http-basic.private.example"],
        ["config", "client-certificate.private.example"],
        ["config", "--list"],
    ] {
        #expect(genericSecretGateRequestClassification(
            gateID: "composer",
            arguments: arguments
        ) == .secretDump)
    }

    for arguments in [
        ["show", "private/package"],
        ["show", "--", "--available"],
        ["config", "http-basic.private.example", "user", "replacement"],
        ["-n", "init"],
        ["init"],
        ["-n", "require", "--no-update", "private/package:^1"],
        ["remove", "--no-update", "private/package"],
        ["exec", "vendor/bin/tool", "install"],
        ["run-script", "deploy"],
        ["plugin-command", "install"],
    ] {
        #expect(genericSecretGateRequestClassification(
            gateID: "composer",
            arguments: arguments
        ) == .unknown)
    }

    #expect(genericSecretGateRequestClassification(
        gateID: "composer",
        arguments: ["install", "--help"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "composer",
        arguments: ["-V"]
    ) == .readOnly)
}

@Test func doctlPolicySeparatesLocalAndCredentialedCommands() {
    #expect(genericSecretGateRequestClassification(gateID: "doctl", arguments: ["account", "get"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "doctl", arguments: ["compute", "droplet", "create"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "doctl", arguments: ["auth", "token"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "doctl", arguments: ["auth", "list"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "doctl", arguments: ["version"]) == .readOnly)
}

@Test func flyctlPolicySeparatesLocalAndCredentialedCommands() {
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["apps", "list"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["deploy"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["auth", "logout"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["auth", "token"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["docs"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "flyctl", arguments: ["version"]) == .readOnly)
}

@Test func glabPolicyClassifiesCredentialDisplays() {
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["auth", "status"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["auth", "status", "--show-token"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["auth", "credential-helper"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["auth", "git-credential", "get"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["auth", "docker-helper", "get"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["auth", "dpop-gen"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["config", "get", "token"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "glab", arguments: ["artifact-registry", "get-token"]) == .secretDump)
}

@Test func gotifyPolicyClassifiesWatchAsMutating() {
    #expect(genericSecretGateRequestClassification(gateID: "gotify", arguments: ["watch", "date"]) == .mutating)
}

@Test func jfrogPolicyClassifiesOnlyRequestsThatReachItsAuthorizationGate() {
    #expect(genericSecretGateRequestClassification(gateID: "jfrog-cli", arguments: ["rt", "search"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "jfrog-cli", arguments: ["worker", "deploy"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "jfrog-cli", arguments: ["rt", "access-token-create"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "jfrog-cli", arguments: ["config", "show"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "jfrog-cli", arguments: ["config", "export"]) == .unknown)
}

@Test func minioPolicyTreatsAliasListingAsASecretDump() {
    #expect(genericSecretGateRequestClassification(gateID: "minio-mc", arguments: ["alias", "list"]) == .secretDump)
    #expect(genericSecretGateRequestClassification(gateID: "minio-mc", arguments: ["ls", "private/bucket"]) == .readOnly)
    #expect(genericSecretGateRequestClassification(gateID: "minio-mc", arguments: ["put", "file", "private/bucket"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "minio-mc", arguments: ["alias", "export", "private"]) == .unknown)
}

@Test func luarocksPolicyOnlyClassifiesUploadBecauseOtherCommandsAreTokenless() {
    #expect(genericSecretGateRequestClassification(gateID: "luarocks", arguments: ["upload", "example.rockspec"]) == .mutating)
    #expect(genericSecretGateRequestClassification(gateID: "luarocks", arguments: ["install", "example"]) == .unknown)
    #expect(genericSecretGateRequestClassification(gateID: "luarocks", arguments: ["search", "example"]) == .unknown)
}

@Test func pulumiPolicyUnderstandsRootOptionsAndLocalCommands() {
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["--cwd", "/tmp", "stack", "list"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["--color=never", "up"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["config", "get", "--show-secrets"]
    ) == .secretDump)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["up", "--help"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["up", "--help=true"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["up", "--help=false"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["about", "env"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["plugin"]
    ) == .readOnly)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["stack", "unselect"]
    ) == .mutating)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["--future-option", "up"]
    ) == .unknown)
    #expect(genericSecretGateRequestClassification(
        gateID: "pulumi",
        arguments: ["--future-option=true", "up"]
    ) == .unknown)
}
