private struct SecretGateCommandPolicy: Sendable {
    let readOnly: Set<String>
    let mutating: Set<String>
    let secretDump: Set<String>

    init(_ readOnly: String, _ mutating: String, secretDump: String = "") {
        self.readOnly = Self.commands(readOnly)
        self.mutating = Self.commands(mutating)
        self.secretDump = Self.commands(secretDump)
    }

    static func commands(_ value: String) -> Set<String> {
        Set(value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) })
    }
}

public func genericSecretGateRequestClassification(
    gateID: String,
    arguments: [String]
) -> SecretGateRequestClassification {
    if gateID == "composer" { return composerRequestClassification(arguments) }
    var words = arguments.map { $0.lowercased() }
    guard !words.isEmpty else { return .unknown }
    if gateID == "stripe" { return stripeRequestClassification(words) }
    if gateID == "netlify-cli" { return netlifyRequestClassification(words) }
    if gateID == "node" { return npmRequestClassification(arguments) }
    if gateID == "sentry-cli" { return sentryCLIRequestClassification(words) }
    if gateID == "snowflake-cli" { return snowflakeCLIRequestClassification(words) }
    if gateID == "runpodctl" {
        guard let normalized = runpodctlCommandWords(words) else { return .unknown }
        words = normalized
    }
    if gateID == "pulumi" { return pulumiRequestClassification(arguments) }
    if gateID == "pnpm", words.first == "audit" {
        if words.dropFirst().contains(where: { $0 == "--fix" || $0.hasPrefix("--fix=") }) {
            return .mutating
        }
        if words.dropFirst().contains(where: { !$0.hasPrefix("-") && $0 != "signatures" }) {
            return .unknown
        }
        return .readOnly
    }
    if gateID == "k6" { return k6RequestClassification(words) }
    if gateID == "twine" { return twineRequestClassification(words) }
    if gateID == "vagrant" { return vagrantRequestClassification(words) }
    if words == ["help"] || words == ["--help"] || words == ["version"] || words == ["--version"] {
        return .readOnly
    }
    if gateID == "hcloud" {
        let commandArguments = Array(words.prefix { $0 != "--" })
        guard let normalized = hcloudArgumentsWithoutPersistentFlags(commandArguments) else { return .unknown }
        words = normalized
        if words.contains("--help") || words.contains("-h") || words.first == "version" { return .readOnly }
        let positionals = words.filter { !$0.hasPrefix("-") }
        if hcloudFlagEnabled(words, "--allow-sensitive")
            && (positionals.starts(with: ["config", "list"])
                || positionals.starts(with: ["config", "get", "token"]))
        {
            return .secretDump
        }
        if hcloudFlagEnabled(words, "--token-from-env")
            && positionals.starts(with: ["context", "create"])
        {
            return .mutating
        }
    }
    guard let policy = secretGateCommandPolicies[gateID] else { return .unknown }
    return commandPolicyClassification(policy, words)
}

private func commandPolicyClassification(
    _ policy: SecretGateCommandPolicy,
    _ words: some Collection<String>
) -> SecretGateRequestClassification {
    let candidates = (1...min(3, words.count)).reversed().map {
        words.prefix($0).joined(separator: " ")
    }
    for candidate in candidates {
        if policy.secretDump.contains(candidate) { return .secretDump }
        if policy.readOnly.contains(candidate) { return .readOnly }
        if policy.mutating.contains(candidate) { return .mutating }
    }
    return .unknown
}

private func npmRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    let booleanShortOptions = "DEOPSadfglpqsy"
    let booleanOptions: Set<String> = [
        "--all", "--dry-run", "--force", "--fund", "--global", "--ignore-scripts",
        "--include-workspace-root", "--json", "--local", "--long", "--offline", "--parseable",
        "--prefer-offline", "--prefer-online", "--quiet", "--readonly", "--silent", "--timing",
        "--verbose", "--workspaces", "--yes", "-D", "-E", "-O", "-P", "-S", "-a", "-d",
        "-dd", "-ddd", "-f", "-g", "-l", "-p", "-q", "-s", "-y",
    ]
    let valueOptions: Set<String> = [
        "--cache", "--call", "--location", "--loglevel", "--otp", "--prefix", "--reg",
        "--registry", "--scope", "--tag", "--userconfig", "--workspace", "-C", "-L", "-c", "-m", "-w",
    ]
    let valueShortOptions = ["-C", "-L", "-c", "-m", "-w"]
    let optionArguments = arguments.prefix { $0 != "--" }
    if optionArguments.contains(where: { ["--help", "-h", "-H", "-?"].contains($0) }) {
        return .readOnly
    }
    if optionArguments.contains(where: { ["--version", "--versions", "-v"].contains($0) }) {
        return .readOnly
    }
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if !argument.hasPrefix("-") { break }
        let shortOptions = argument.dropFirst()
        let isBooleanShortCluster = shortOptions.count > 1
            && shortOptions.allSatisfy { booleanShortOptions.contains($0) }
        let hasAttachedShortValue = valueShortOptions.contains {
            argument.hasPrefix($0) && argument.count > $0.count
        }
        if argument.contains("=") || argument.hasPrefix("--no-")
            || booleanOptions.contains(argument) || isBooleanShortCluster || hasAttachedShortValue
        {
            index += 1
        } else if valueOptions.contains(argument) {
            guard index + 1 < arguments.count else { return .unknown }
            index += 2
        } else {
            return .unknown
        }
    }
    guard index < arguments.count, let policy = secretGateCommandPolicies["node"] else { return .unknown }
    return commandPolicyClassification(policy, arguments[index...].map { $0.lowercased() })
}

private func pulumiRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    let booleanOptions: Set<String> = [
        "--disable-integrity-checking", "--emoji", "--fully-qualify-stack-names", "--help",
        "--logflow", "--logtostderr", "--non-interactive", "--version", "-Q", "-e", "-h",
    ]
    let valueOptions: Set<String> = [
        "--color", "--cwd", "--memprofilerate", "--otel-traces", "--profiling",
        "--tracing", "--tracing-header", "--verbose", "-C", "-v",
    ]
    let optionArguments = arguments.prefix { $0 != "--" }
    if optionArguments.contains(where: {
        ["--help", "-h", "--version", "--help=true", "-h=true", "--version=true"].contains($0)
    }) {
        return .readOnly
    }

    var index = 0
    while index < optionArguments.count {
        let argument = optionArguments[index]
        if !argument.hasPrefix("-") { break }
        let hasAttachedShortValue = ["-C", "-v"].contains {
            argument.hasPrefix($0) && argument.count > $0.count
        }
        let optionName = argument.split(separator: "=", maxSplits: 1).first.map(String.init)
        let hasKnownInlineValue = argument.contains("=") && (optionName.map {
            booleanOptions.contains($0) || valueOptions.contains($0)
        } ?? false)
        if booleanOptions.contains(argument) || hasKnownInlineValue || hasAttachedShortValue
        {
            index += 1
        } else if valueOptions.contains(argument) {
            guard index + 1 < optionArguments.count else { return .unknown }
            index += 2
        } else {
            return .unknown
        }
    }
    guard index < optionArguments.count else { return .unknown }
    let words = optionArguments[index...].map { $0.lowercased() }

    if words.count == 1 && [
        "api", "deployment", "env", "insights", "org", "package", "plugin",
        "policy", "project", "schema", "state", "template",
    ].contains(words[0]) {
        return .readOnly
    }

    if words.starts(with: ["about", "env"])
        || words.starts(with: ["plugin", "list"])
        || words.starts(with: ["plugin", "ls"])
    {
        return .readOnly
    }
    if words.starts(with: ["stack", "unselect"])
        || words.starts(with: ["plugin", "remove"])
        || words.starts(with: ["plugin", "rm"])
        || words.starts(with: ["plugin", "delete"])
        || words.starts(with: ["package", "new"])
        || words.starts(with: ["package", "create"])
        || words.starts(with: ["package", "setup"])
        || words.starts(with: ["policy", "new"])
        || words.starts(with: ["policy", "create"])
        || words.starts(with: ["policy", "setup"])
        || words.first == "logout"
    {
        return .mutating
    }

    guard let policy = secretGateCommandPolicies["pulumi"] else { return .unknown }
    return commandPolicyClassification(policy, words)
}

// Keep global-option handling aligned with runpodctl 2.8.0 so the prompt can
// describe gated API commands without treating their output format as a verb.
private func runpodctlCommandWords(_ arguments: [String]) -> [String]? {
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if argument == "--output" || argument == "-o" {
            guard index + 1 < arguments.count else { return nil }
            index += 2
        } else if argument.hasPrefix("--output=") || argument.hasPrefix("-o=")
            || (argument.hasPrefix("-o") && argument.count > 2)
        {
            index += 1
        } else if ["--help", "-h", "--help=true", "-h=true", "--version", "-v", "--version=true", "-v=true"].contains(argument) {
            return ["help"]
        } else if argument == "--help=false" || argument == "-h=false" {
            index += 1
        } else if argument.hasPrefix("-") {
            return nil
        } else {
            return Array(arguments[index...])
        }
    }
    return []
}

private func sentryCLIRequestClassification(
    _ arguments: [String]
) -> SecretGateRequestClassification {
    let optionsWithValues = ["--auth-token", "--header", "--log-level", "--url"]
    var words: [String] = []
    var index = 0
    while index < arguments.count, words.count < 3 {
        let argument = arguments[index]
        if optionsWithValues.contains(argument) {
            guard index + 1 < arguments.count else { return .unknown }
            if argument == "--auth-token" { return .secretDump }
            index += 2
        } else if optionsWithValues.contains(where: { argument.hasPrefix("\($0)=") }) {
            if argument.hasPrefix("--auth-token=") { return .secretDump }
            index += 1
        } else if ["--help", "-h", "--version", "-v"].contains(argument) {
            return .readOnly
        } else if ["--quiet", "--silent", "--allow-failure"].contains(argument) {
            index += 1
        } else if argument == "--" || argument.hasPrefix("-") {
            return .unknown
        } else {
            words.append(argument)
            index += 1
        }
    }
    guard !words.isEmpty, let policy = secretGateCommandPolicies["sentry-cli"] else {
        return .unknown
    }
    let candidates = (1...words.count).reversed().map {
        words.prefix($0).joined(separator: " ")
    }
    for candidate in candidates {
        if policy.readOnly.contains(candidate) { return .readOnly }
        if policy.mutating.contains(candidate) { return .mutating }
    }
    return .unknown
}

private func snowflakeCLIRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    let optionsWithValues = [
        "--config-file", "--pycharm-debug-library-path", "--pycharm-debug-server-host",
        "--pycharm-debug-server-port",
    ]
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if optionsWithValues.contains(argument) {
            guard index + 1 < arguments.count else { return .unknown }
            index += 2
        } else if optionsWithValues.contains(where: { argument.hasPrefix("\($0)=") })
            || ["--disable-external-command-plugins", "--commands-registration"].contains(argument)
        {
            index += 1
        } else if ["--help", "-h", "--version", "--info", "--docs", "--structure",
                   "--install-completion", "--show-completion"].contains(argument)
        {
            return .readOnly
        } else if argument.hasPrefix("-") {
            return .unknown
        } else {
            break
        }
    }
    guard index < arguments.count else { return .unknown }
    let words = Array(arguments[index...])
    let candidates = (1...min(3, words.count)).reversed().map {
        words.prefix($0).joined(separator: " ")
    }
    for candidate in candidates {
        if snowflakeCLICommandPolicy.secretDump.contains(candidate) { return .secretDump }
        if snowflakeCLICommandPolicy.readOnly.contains(candidate) { return .readOnly }
        if snowflakeCLICommandPolicy.mutating.contains(candidate) { return .mutating }
    }
    return .unknown
}

// Reviewed against Snowflake CLI v3.26.0's built-in command structure. SQL,
// dbt passthrough, external plugins, and future commands remain Unknown.
private let snowflakeCLICommandPolicy = SecretGateCommandPolicy(
    """
    app diff,app open,app validate,app events,app version list,app release-directive list,
    app release-channel list,connection test,cortex search,cortex complete,cortex extract-answer,
    cortex sentiment,cortex summarize,cortex translate,dbt list,dbt describe,dcm list,dcm plan,
    dcm raw-analyze,dcm describe,dcm list-deployments,dcm preview,dcm test,git list,git describe,
    git list-branches,git list-tags,git list-files,logs,notebook get-url,notebook open,object list,
    object describe,snowpark list,snowpark describe,snowpark package lookup,
    spcs compute-pool list,spcs compute-pool describe,spcs compute-pool status,spcs service list,
    spcs service describe,spcs service status,spcs service logs,spcs service events,
    spcs service metrics,spcs service list-endpoints,spcs service list-instances,
    spcs service list-containers,spcs service list-roles,spcs service remote-build-status,
    spcs service remote-build-history,spcs image-registry url,spcs image-repository list,
    spcs image-repository list-images,spcs image-repository list-tags,
    spcs image-repository url,stage list,stage describe,stage list-files,stage diff,streamlit list,
    streamlit describe,streamlit get-url,streamlit logs,ws version list
    """,
    """
    app setup,app run,app teardown,app deploy,app publish,app version create,app version drop,
    app release-directive set,app release-directive unset,app release-directive add-accounts,
    app release-directive remove-accounts,app release-channel add-accounts,
    app release-channel remove-accounts,app release-channel set-accounts,
    app release-channel add-version,app release-channel remove-version,dbt drop,dbt copy,dbt deploy,
    dcm deploy,dcm purge,dcm create,dcm drop,dcm drop-deployment,dcm refresh,git drop,git setup,
    git fetch,git copy,git execute,notebook execute,notebook create,notebook deploy,object drop,
    object create,snowpark deploy,snowpark build,snowpark execute,snowpark drop,
    snowpark package upload,snowpark package create,spcs compute-pool drop,
    spcs compute-pool create,spcs compute-pool deploy,spcs compute-pool stop-all,
    spcs compute-pool suspend,spcs compute-pool resume,spcs compute-pool set,
    spcs compute-pool unset,spcs service drop,spcs service create,spcs service deploy,
    spcs service execute-job,spcs service upgrade,spcs service suspend,spcs service resume,
    spcs service set,spcs service unset,spcs service build-image,spcs service remote-build,
    spcs image-registry login,spcs image-repository drop,spcs image-repository create,
    spcs image-repository deploy,stage drop,stage copy,stage create,stage remove,stage execute,
    streamlit drop,streamlit execute,streamlit share,streamlit deploy,ws bundle,ws deploy,ws drop,
    ws validate,ws version create,ws version drop
    """,
    secretDump: "spcs image-registry token"
)

private func k6RequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    // Mirrors the wrapper's positive catalog so future forms stay Unknown.
    if arguments.contains(where: { $0 == "--help" || $0 == "-h" })
        || arguments == ["--version"]
    {
        return .readOnly
    }
    guard let command = k6CommandIndex(arguments, from: 0) else { return .unknown }
    switch arguments[command] {
    case "inspect", "version":
        return .readOnly
    case "run":
        return k6RunUsesCloudOutput(Array(arguments.dropFirst(command + 1))) ? .mutating : .unknown
    case "cloud":
        guard let subcommand = k6CommandIndex(arguments, from: command + 1) else { return .unknown }
        switch arguments[subcommand] {
        case "run", "upload":
            return .mutating
        case "project", "load-zone", "test":
            guard let operation = k6CommandIndex(arguments, from: subcommand + 1) else { return .unknown }
            return arguments[operation] == "list" ? .readOnly : .unknown
        default:
            return .unknown
        }
    default:
        return .unknown
    }
}

private func k6CommandIndex(_ arguments: [String], from start: Int) -> Int? {
    let flags = ["--no-color", "--log-ns-timestamps", "--verbose", "-v", "--quiet", "-q", "--profiling-enabled"]
    let booleanOptions = ["--no-color=", "--log-ns-timestamps=", "--verbose=", "--quiet=", "--profiling-enabled="]
    let options = ["--secret-source", "--log-output", "--log-format", "--config", "-c", "--address", "-a"]
    var index = start
    while index < arguments.count {
        let argument = arguments[index]
        if flags.contains(argument) {
            index += 1
        } else if options.contains(argument) {
            guard index + 1 < arguments.count else { return nil }
            index += 2
        } else if booleanOptions.contains(where: { argument.hasPrefix($0) })
            || options.contains(where: { argument.hasPrefix("\($0)=") })
            || ((argument.hasPrefix("-c") || argument.hasPrefix("-a")) && argument.count > 2)
        {
            index += 1
        } else if argument.hasPrefix("-") {
            return nil
        } else {
            return index
        }
    }
    return nil
}

private func k6RunUsesCloudOutput(_ arguments: [String]) -> Bool {
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if argument == "--" { return false }
        if argument == "--out" || argument == "-o" {
            if index + 1 < arguments.count, k6CloudOutput(arguments[index + 1]) { return true }
            index += 2
            continue
        }
        if argument.hasPrefix("--out=") {
            if k6CloudOutput(String(argument.dropFirst("--out=".count))) { return true }
        } else if argument.hasPrefix("-o") {
            let value = argument.dropFirst(2)
            if k6CloudOutput(String(value.first == "=" ? value.dropFirst() : value)) { return true }
        }
        index += 1
    }
    return false
}

private func k6CloudOutput(_ value: String) -> Bool {
    value == "cloud" || value.hasPrefix("cloud=")
}

private func twineRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    if arguments.contains(where: { $0 == "--help" || $0 == "-h" })
        || arguments == ["--version"]
    {
        return .readOnly
    }
    var index = 0
    while index < arguments.count, arguments[index] == "--no-color" { index += 1 }
    if index < arguments.count, arguments[index] == "--" { index += 1 }
    let command = index < arguments.count ? arguments[index] : nil
    switch command {
    case "check": return .readOnly
    case "upload": return .mutating
    default: return .unknown
    }
}

private func vagrantRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    let separator = arguments.firstIndex(of: "--") ?? arguments.endIndex
    if arguments[..<separator].contains(where: { ["--help", "-h", "--version", "-v"].contains($0) }) {
        return .readOnly
    }
    let globalFlags = Set(["--color", "--no-color", "--machine-readable", "--debug", "--timestamp", "--debug-timestamp", "--no-tty"])
    let words = arguments.enumerated().compactMap { index, argument in
        index < separator && globalFlags.contains(argument) ? nil : argument
    }
    guard let commandIndex = words.firstIndex(where: { !$0.hasPrefix("-") }) else { return .unknown }
    let command = words[commandIndex]
    let arguments = Array(words.dropFirst(commandIndex + 1))

    switch command {
    case "login": return .readOnly
    case "up", "reload", "resume": return .mutating
    case "snapshot":
        guard let subcommand = arguments.first(where: { !$0.hasPrefix("-") }) else { return .unknown }
        return ["restore", "pop"].contains(subcommand) ? .mutating : .unknown
    case "box":
        guard let subcommand = arguments.first(where: { !$0.hasPrefix("-") }) else { return .unknown }
        if subcommand == "outdated" { return .readOnly }
        return ["add", "update"].contains(subcommand) ? .mutating : .unknown
    case "cloud": return vagrantCloudRequestClassification(arguments)
    default: return .unknown
    }
}

private func vagrantCloudRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    guard let commandIndex = arguments.firstIndex(where: { !$0.hasPrefix("-") }) else { return .unknown }
    let command = arguments[commandIndex]
    let arguments = Array(arguments.dropFirst(commandIndex + 1))
    let subcommand = arguments.first(where: { !$0.hasPrefix("-") })

    switch command {
    case "auth":
        guard let subcommand else { return .unknown }
        return ["login", "whoami"].contains(subcommand) ? .readOnly : .unknown
    case "box":
        guard let subcommand else { return .unknown }
        if subcommand == "show" { return .readOnly }
        return ["create", "delete", "update"].contains(subcommand) ? .mutating : .unknown
    case "provider":
        guard let subcommand else { return .unknown }
        return ["create", "delete", "update", "upload"].contains(subcommand) ? .mutating : .unknown
    case "publish": return .mutating
    case "search": return .readOnly
    case "version":
        guard let subcommand else { return .unknown }
        return ["create", "delete", "release", "revoke", "update"].contains(subcommand) ? .mutating : .unknown
    default: return .unknown
    }
}

private func composerRequestClassification(
    _ arguments: [String],
    inheritedNonInteractive: Bool = false
) -> SecretGateRequestClassification {
    let separator = arguments.firstIndex(of: "--") ?? arguments.endIndex
    let optionArguments = Array(arguments[..<separator])
    if optionArguments.contains(where: { ["--help", "-h", "--version", "-V"].contains($0) }) {
        return .readOnly
    }
    let nonInteractive = inheritedNonInteractive
        || optionArguments.contains(where: { ["--no-interaction", "-n"].contains($0) })
    guard let (command, commandArguments) = composerCommandAndArguments(arguments) else { return .unknown }

    switch command {
    case "install", "create-project", "update", "reinstall":
        return .mutating
    case "require":
        if nonInteractive && commandArguments.contains("--no-update") {
            let packages = composerPositionals(
                commandArguments,
                optionsWithValues: [
                    "--working-dir", "-d", "--prefer-install", "--audit-format",
                    "--ignore-platform-req", "--apcu-autoloader-prefix",
                ]
            )
            return packages.contains(where: {
                !$0.contains(":") && !$0.contains("=") && !$0.contains(" ")
            }) ? .mutating : .unknown
        }
        return .mutating
    case "remove":
        return commandArguments.contains("--no-update") ? .unknown : .mutating
    case "search", "audit", "outdated", "fund", "diagnose", "prohibits":
        return .readOnly
    case "archive":
        return composerHasPositional(commandArguments) ? .mutating : .unknown
    case "browse":
        return composerHasPositional(commandArguments) ? .readOnly : .unknown
    case "config":
        return composerConfigReadsAuth(commandArguments) ? .secretDump : .unknown
    case "global":
        return composerRequestClassification(commandArguments, inheritedNonInteractive: nonInteractive)
    case "init":
        return !nonInteractive && commandArguments.contains(where: {
            $0 == "--repository" || $0.hasPrefix("--repository=")
        }) ? .mutating : .unknown
    case "show":
        let optionEnd = commandArguments.firstIndex(of: "--") ?? commandArguments.endIndex
        return commandArguments[..<optionEnd].contains(where: {
            ["--all", "--available", "-a", "--latest", "-l", "--outdated", "-o"].contains($0)
        }) ? .readOnly : .unknown
    default:
        return .unknown
    }
}

private func composerCommandAndArguments(_ arguments: [String]) -> (String, [String])? {
    let flags = Set([
        "--profile", "--no-plugins", "--no-scripts", "--no-cache", "--quiet", "-q",
        "--verbose", "-v", "-vv", "-vvv", "--ansi", "--no-ansi", "--no-interaction", "-n",
    ])
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if flags.contains(argument) {
            index += 1
        } else if ["--working-dir", "-d"].contains(argument) {
            guard index + 1 < arguments.count else { return nil }
            index += 2
        } else if argument.hasPrefix("--working-dir=") || (argument.hasPrefix("-d") && argument.count > 2) {
            index += 1
        } else if argument.hasPrefix("-") {
            return nil
        } else {
            guard let command = composerCommand(argument) else { return nil }
            return (command, Array(arguments.dropFirst(index + 1)))
        }
    }
    return nil
}

private func composerCommand(_ argument: String) -> String? {
    if composerCommands.contains(argument) { return argument }
    if let command = composerAliases[argument] { return command }
    let candidates = Set(
        composerCommands.filter { $0.hasPrefix(argument) }
            + composerAliases.compactMap { alias, command in alias.hasPrefix(argument) ? command : nil }
    )
    return candidates.count == 1 ? candidates.first : nil
}

private func composerHasPositional(_ arguments: [String]) -> Bool {
    !composerPositionals(
        arguments,
        optionsWithValues: ["--working-dir", "-d", "--format", "-f", "--dir", "--file"]
    ).isEmpty
}

private func composerPositionals(_ arguments: [String], optionsWithValues: Set<String>) -> [String] {
    var positionals: [String] = []
    var skipValue = false
    var optionsEnded = false
    for argument in arguments {
        if skipValue {
            skipValue = false
        } else if argument == "--" {
            optionsEnded = true
        } else if optionsWithValues.contains(argument) {
            skipValue = true
        } else if optionsEnded || !argument.hasPrefix("-") {
            positionals.append(argument)
        }
    }
    return positionals
}

private func composerConfigReadsAuth(_ arguments: [String]) -> Bool {
    if arguments.contains(where: { ["--list", "-l"].contains($0) }) { return true }
    if arguments.contains(where: { ["--editor", "-e", "--unset"].contains($0) }) {
        return false
    }
    let positionals = composerPositionals(
        arguments,
        optionsWithValues: ["--working-dir", "-d", "--file", "-f"]
    )
    guard positionals.count == 1, let root = positionals[0].split(separator: ".").first else { return false }
    return composerAuthConfigRoots.contains(String(root))
}

private let composerCommands = SecretGateCommandPolicy.commands("""
about,archive,audit,browse,bump,check-platform-reqs,clear-cache,completion,config,create-project,depends,diagnose,dump-autoload,exec,fund,global,help,init,install,licenses,list,outdated,policy,prohibits,reinstall,remove,repository,require,run-script,search,self-update,show,status,suggests,update,validate
""")

private let composerAliases = [
    "_complete": "completion", "cc": "clear-cache", "clearcache": "clear-cache",
    "dumpautoload": "dump-autoload", "home": "browse", "i": "install", "info": "show",
    "r": "require", "repo": "repository", "rm": "remove", "run": "run-script",
    "selfupdate": "self-update", "u": "update", "uninstall": "remove", "upgrade": "update",
    "why": "depends", "why-not": "prohibits",
]

private let composerAuthConfigRoots = Set([
    "bitbucket-oauth", "github-oauth", "gitlab-oauth", "gitlab-token", "http-basic",
    "custom-headers", "bearer", "client-certificate", "forgejo-token",
])

private func hcloudArgumentsWithoutPersistentFlags(_ arguments: [String]) -> [String]? {
    let valueFlags = [
        "--config", "--context", "--debug-file", "--endpoint", "--hetzner-endpoint", "--http-timeout",
        "--poll-interval",
    ]
    let booleanFlags = ["--debug", "--no-experimental-warnings", "--quiet"]
    var result: [String] = []
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if valueFlags.contains(argument) {
            guard index + 1 < arguments.count else { return nil }
            index += 2
        } else if valueFlags.contains(where: { argument.hasPrefix("\($0)=") })
            || booleanFlags.contains(argument)
            || booleanFlags.contains(where: { argument.hasPrefix("\($0)=") })
        {
            index += 1
        } else {
            result.append(argument)
            index += 1
        }
    }
    return result
}

private func hcloudFlagEnabled(_ arguments: [String], _ flag: String) -> Bool {
    arguments.contains(flag) || arguments.contains { argument in
        guard argument.hasPrefix("\(flag)=") else { return false }
        return ["1", "t", "true"].contains(argument.dropFirst(flag.count + 1).lowercased())
    }
}

private func netlifyRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    let words = arguments.drop(while: { $0 == "--verbose" })
    guard !words.isEmpty else { return .unknown }
    if ["help", "--help", "version", "--version", "-v"].contains(words.first!) {
        return .readOnly
    }
    if (words.starts(with: ["database", "status"]) || words.starts(with: ["db", "status"]))
        && words.contains("--show-credentials")
    {
        return .secretDump
    }
    if words.first == "recipes"
        && (words.contains("blobs-migrate") || words.contains("--name=blobs-migrate"))
    {
        return .mutating
    }
    guard let policy = secretGateCommandPolicies["netlify-cli"] else { return .unknown }
    let candidates = (1...min(3, words.count)).reversed().map {
        words.prefix($0).joined(separator: " ")
    }
    for candidate in candidates {
        if policy.secretDump.contains(candidate) { return .secretDump }
        if policy.readOnly.contains(candidate) { return .readOnly }
        if policy.mutating.contains(candidate) { return .mutating }
    }
    return .unknown
}

private func stripeRequestClassification(_ arguments: [String]) -> SecretGateRequestClassification {
    let optionsWithValues = ["--api-key", "--color", "--config", "--device-name", "--log-level", "--project-name", "-p"]
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if optionsWithValues.contains(argument) {
            guard index + 1 < arguments.count else { return .unknown }
            index += 2
        } else if optionsWithValues.contains(where: { argument.hasPrefix("\($0)=") }) {
            index += 1
        } else if ["--help", "-h", "--version", "-v"].contains(argument)
            || argument == "--map" || argument.hasPrefix("--map=")
        {
            // Stripe handles --map before command execution and returns after printing the map.
            return .readOnly
        } else if argument.hasPrefix("-") {
            return .unknown
        } else {
            break
        }
    }
    guard index < arguments.count else { return .unknown }
    let words = Array(arguments[index...])

    switch words[0] {
    case "completion", "community", "get", "open", "resources", "serve", "version", "whoami":
        return .readOnly
    case "feedback", "fixtures", "logout", "post", "delete", "reauth", "trigger":
        return .mutating
    case "config", "listen":
        return .secretDump
    case "agent":
        guard words.dropFirst().first == "setup" else { return .unknown }
        return words.contains("--status") ? .readOnly : .mutating
    case "data":
        return words.starts(with: ["data", "metrics", "run"]) ? .readOnly : .unknown
    case "docs":
        if words.starts(with: ["docs", "prefs", "set"]) || words.starts(with: ["docs", "prefs", "unset"]) {
            return .mutating
        }
        return .readOnly
    case "keys":
        return words.starts(with: ["keys", "permissions"]) ? .readOnly : .unknown
    case "login":
        return words.starts(with: ["login", "list"]) ? .readOnly : .mutating
    case "logs":
        return words.starts(with: ["logs", "tail"]) ? .readOnly : .unknown
    case "reporting":
        if words.starts(with: ["reporting", "query-runs", "retrieve"]) { return .readOnly }
        if words.starts(with: ["reporting", "query-runs", "create"]) { return .mutating }
    case "samples":
        if words.starts(with: ["samples", "list"]) { return .readOnly }
        if words.starts(with: ["samples", "create"]) { return .mutating }
        return .unknown
    case "sandbox":
        if words.starts(with: ["sandbox", "create"]) { return .secretDump }
        if words.starts(with: ["sandbox", "claim"]) { return .mutating }
        return .unknown
    case "switch":
        return words.starts(with: ["switch", "context"]) ? .mutating : .unknown
    default:
        break
    }

    guard stripeResourceRoots.contains(words[0]) else { return .unknown }
    for word in words.dropFirst() {
        if stripeReadOnlyOperations.contains(word) { return .readOnly }
        if stripeMutatingOperations.contains(word) { return .mutating }
        if word.hasPrefix("-") { return .unknown }
    }
    return .unknown
}

// Reviewed against Stripe CLI v1.50.6's generated command map. New roots and
// operation names remain Unknown until their authority is reviewed.
private let stripeResourceRoots = SecretGateCommandPolicy.commands("""
account_links,account_sessions,accounts,apple_pay_domains,application_fees,balance,balance_settings,balance_transactions,bank_accounts,billing,billing_portal,capabilities,cards,cash_balances,charges,checkout,climate,confirmation_tokens,country_specs,coupons,credit_note_line_items,credit_notes,customer_balance_transactions,customer_cash_balance_transactions,customer_sessions,customers,disputes,entitlements,ephemeral_keys,events,exchange_rates,external_accounts,fee_refunds,file_links,files,financial_connections,forwarding,identity,invoice_line_items,invoice_payments,invoice_rendering_templates,invoiceitems,invoices,issuing,login_links,mandates,payment_attempt_records,payment_intent_amount_details_line_items,payment_intents,payment_links,payment_method_configurations,payment_method_domains,payment_methods,payment_records,payment_sources,payouts,persons,plans,preview,prices,product_features,products,promotion_codes,quotes,radar,refunds,reporting,reviews,scheduled_query_runs,setup_attempts,setup_intents,shipping_rates,sources,subscription_items,subscription_schedules,subscriptions,tax,tax_codes,tax_ids,tax_rates,terminal,test_helpers,tokens,topups,transfer_reversals,transfers,treasury,v2,webhook_endpoints
""")

private let stripeReadOnlyOperations = SecretGateCommandPolicy.commands("""
balance_transactions,capabilities,find,get,list,list_computed_upfront_line_items,list_line_items,list_owners,list_payment_methods,me,pdf,persons,preview,preview_lines,retrieve,retrieve_features,retrieve_payment_method,search,show,source_transactions
""")

private let stripeMutatingOperations = SecretGateCommandPolicy.commands("""
accept,acknowledge_confirmation_of_payee,activate,add_lines,advance,apply_customer_balance,approve,archive,attach,attach_payment,cancel,cancel_action,capture,close,collect_inputs,collect_payment_method,confirm,confirm_microdeposits,confirm_payment_intent,create,create_force_capture,create_from_calculation,create_funding_instructions,create_preview,create_reversal,create_unlinked_refund,credit,deactivate,delete,delete_discount,delete_where,deliver_card,detach,disable,disconnect,enable,expire,fail,fail_card,finalize_amount,finalize_invoice,finalize_quote,fund_cash_balance,generate_microdeposits,increment,increment_authorization,initiate_confirmation_of_payee,invoke,mark_uncollectible,migrate,pay,ping,post,present_payment_method,process_payment_intent,process_setup_intent,quickstart,reactivate,redact,refresh,refund,refund_payment,reject,release,remove_lines,report_payment,report_payment_attempt,report_payment_attempt_canceled,report_payment_attempt_failed,report_payment_attempt_guaranteed,report_payment_attempt_informational,report_refund,resend,respond,resume,return_card,return_inbound_transfer,return_outbound_payment,return_outbound_transfer,reverse,send_invoice,send_microdeposits,set_reader_display,ship_card,submit,submit_card,subscribe,succeed,succeed_input_collection,terminate,timeout_input_collection,unarchive,unreject,unsubscribe,update,update_features,update_lines,validate,verify,verify_microdeposits,void_credit_note,void_grant,void_invoice
""")

private let secretGateCommandPolicies: [String: SecretGateCommandPolicy] = [
    "akamai": .init("config list", "config set,config remove", secretDump: "config show"),
    "algolia": .init("profile list", "objects import,objects delete,indices delete", secretDump: "profile get"),
    "argocd": .init("app get,app list,app diff,cluster get,cluster list,account get-user-info", "app create,app set,app sync,app delete,app rollback", secretDump: "account generate-token"),
    "ast-cli": .init("scan list,scan show,project list,project show", "scan create,scan cancel,project create,project delete"),
    "buf": .init("repository list,module list,organization list", "push,repository create,repository delete"),
    "censys": .init("search,view,account", "asm seeds add,asm seeds delete"),
    "checkov": .init("frameworks", "submit"),
    "circleci": .init("project list,pipeline list,config validate", "pipeline run,context create,context delete,context store-secret"),
    "civo": .init("instance list,instance show,kubernetes list,kubernetes show", "instance create,instance remove,kubernetes create,kubernetes remove", secretDump: "apikey show"),
    "cloudsmith-cli": .init("whoami,repos list,packages list,packages search", "push,packages delete,repos create,repos delete"),
    "composer": .init("", ""),
    "doctl": .init("account get,compute droplet list,compute droplet get,kubernetes cluster list,kubernetes cluster get", "compute droplet create,compute droplet delete,kubernetes cluster create,kubernetes cluster delete", secretDump: "auth token"),
    "flyctl": .init("status,apps list,machine list,machine status,secrets list,auth whoami", "deploy,scale,apps create,apps destroy,machine run,machine destroy,secrets set,secrets unset,secrets import,auth logout", secretDump: "auth token"),
    "glab": .init(
        "repo view,repo list,issue list,issue view,mr list,mr view,ci list,ci view,pipeline list,pipeline view,auth status",
        "repo create,repo delete,issue create,mr create,ci run,pipeline run",
        secretDump: "auth status --show-token,auth credential-helper,auth git-credential get,auth docker-helper get,auth dpop-gen,config get token,config get gitlab_token,config get oauth_token,artifact-registry get-token"
    ),
    "gotify": .init("version", "push,watch"),
    "gptcommit": .init(
        "config keys,config get",
        "install,uninstall,config set,config delete,prepare-commit-msg",
        secretDump: "config list,config get openai.api_key"
    ),
    "grafanactl": .init(
        "config current-context,config list-contexts,config check,config view,resources get,resources list,resources pull,resources validate",
        "config set,config unset,config use-context,config use,resources delete,resources edit,resources push,resources serve",
        secretDump: "config view --raw"
    ),
    "heroku": .init(
        "apps,apps:info,info,ps,addons,status,auth:whoami,whoami,regions,releases,logs,pg:info,pg,webhooks",
        "apps:create,create,apps:destroy,destroy,auth:logout,logout,config:set,config:unset,ps:scale,scale,run,container:push,container:release",
        secretDump: "auth:token,config,config:get,git:credentials"
    ),
    "hcloud": .init(
        "all list,server list,server describe,network list,network describe,datacenter list,location list",
        "server create,server delete,network create,network delete,context create",
        secretDump: "config get token,config list --allow-sensitive"
    ),
    "huggingface-cli": .init(
        "auth whoami,cache verify,env,download,buckets list,buckets ls,buckets info,collections list,collections ls,collections info,datasets list,datasets ls,datasets leaderboard,datasets info,datasets parquet,datasets sql,datasets card,discussions list,discussions ls,discussions info,discussions diff,endpoints list,endpoints ls,endpoints hardware,endpoints describe,endpoints catalog list,endpoints catalog ls,endpoints list-catalog,jobs logs,jobs stats,jobs list,jobs ls,jobs ps,jobs hardware,jobs inspect,jobs wait,jobs scheduled list,jobs scheduled ls,jobs scheduled ps,jobs scheduled inspect,models list,models ls,models info,models card,papers list,papers ls,papers search,papers info,papers read,repo list,repo ls,repos list,repos ls,repo tag list,repo tag ls,repos tag list,repos tag ls,sandbox pool ls,sandbox pool list,sandbox process ls,sandbox process list,spaces list,spaces ls,spaces info,spaces card,spaces templates,spaces search,spaces wait,spaces hardware,spaces logs,spaces volumes list,spaces volumes ls,spaces secrets list,spaces secrets ls,spaces variables list,spaces variables ls,webhooks list,webhooks ls,webhooks info",
        "upload,upload-large-folder,buckets create,buckets delete,buckets remove,buckets rm,buckets move,buckets settings,buckets sync,collections create,collections update,collections delete,collections add-item,collections update-item,collections delete-item,discussions create,discussions comment,discussions edit,discussions close,discussions reopen,discussions rename,discussions merge,endpoints deploy,endpoints catalog deploy,endpoints update,endpoints delete,endpoints pause,endpoints resume,endpoints scale-to-zero,jobs run,jobs cancel,jobs labels,jobs ssh,jobs uv run,jobs scheduled run,jobs scheduled delete,jobs scheduled suspend,jobs scheduled resume,jobs scheduled trigger,jobs scheduled labels,jobs scheduled uv,repo create,repo duplicate,repo delete,repo move,repo settings,repo delete-files,repo branch create,repo branch delete,repo tag create,repo tag delete,repos create,repos duplicate,repos delete,repos move,repos settings,repos delete-files,repos branch create,repos branch delete,repos tag create,repos tag delete,repo-files delete,sandbox create,sandbox exec,sandbox spawn,sandbox cp,sandbox kill,sandbox pool create,sandbox pool delete,sandbox pool rm,sandbox process kill,spaces dev-mode,spaces ssh,spaces pause,spaces restart,spaces settings,spaces hot-reload,spaces volumes set,spaces volumes delete,spaces secrets add,spaces secrets delete,spaces variables add,spaces variables delete,webhooks create,webhooks update,webhooks enable,webhooks disable,webhooks delete",
        secretDump: "auth token"
    ),
    "jfrog-cli": .init(
        "rt search,rt ping,pl status,worker list,apptrust ping,stats",
        "rt upload,rt delete,rt build-publish,worker deploy,apptrust app-create,release-bundle-create",
        secretDump: "access-token-create,rt access-token-create"
    ),
    "k6": .init("", ""),
    "luarocks": .init("", "upload"),
    "minio-mc": .init("ls,stat,find,du,tree,ping,ready", "cp,mv,rm,mb,rb,mirror,put", secretDump: "alias list,alias ls"),
    "netlify-cli": .init(
        "agents:list,agents:show,blob:list,blobs:list,database status,database migrations pull,db status,db migrations pull,log,logs,open,open:admin,open:site,sites:list,sites:search,status,status:hooks,teams:list,watch",
        "agents:create,agents:run,agents:stop,blob:delete,blob:set,blobs:delete,blobs:set,build,claim,clone,create,deploy,env:clone,env:delete,env:import,env:migrate,env:remove,env:set,env:unset,init,link,sites:create,sites:delete",
        secretDump: "blob:get,blobs:get,env:get,env:list"
    ),
    "node": .init(
        "access list,access get,audit,audit signatures,diff,dist-tag ls,doctor,org ls,outdated,owner ls,ping,profile get,search,find,s,se,stage list,stage view,stars,team ls,token list,trust list,view,info,show,v,whoami",
        "access,audit fix,ci,clean-install,ic,install-clean,isntall-clean,deprecate,dist-tag,dist-tags,install,add,i,in,ins,inst,insta,instal,isnt,isnta,isntal,isntall,install-ci-test,cit,clean-install-test,sit,install-test,it,logout,org,ogr,owner,author,profile,publish,stage,star,team,token,trust,undeprecate,unpublish,unstar,update,u,up,upgrade,udpate",
        secretDump: "config get"
    ),
    "pnpm": .init(
        "view,info,show,v,search,s,se,find,outdated,why,list,ls,dist-tag ls,dist-tags ls,stage list,stage view,whoami,ping,stars",
        "publish,unpublish,deprecate,undeprecate,add,remove,update,up,upgrade,dist-tag add,dist-tag rm,dist-tags add,dist-tags rm,stage publish,stage approve,stage reject,star,unstar",
        secretDump: "config get"
    ),
    "pulumi": .init("whoami,stack list,stack ls,preview,about,config get", "up,destroy,refresh,import,cancel", secretDump: "config get --show-secrets,stack export --show-secrets"),
    // Qwen has no `chat` command and treats arbitrary positionals (including
    // "chat" and "run") as agent prompts whose authority cannot be inferred.
    "qwen-code": .init("", ""),
    "runpodctl": .init(
        "pod list,pod get,pods list,pods get,serverless list,serverless get,sls list,sls get,template list,template search,template get,tpl list,tpl search,tpl get,templates list,templates search,templates get,model list,model ls,network-volume list,network-volume get,nv list,nv get,registry list,registry get,reg list,reg get,hub list,hub search,hub get,gpu list,gpus list,datacenter list,dc list,datacenters list,billing pods,billing serverless,billing sls,billing endpoints,billing network-volume,billing nv,user,account,me,ssh list-keys,ssh info,ssh connect,get cloud,get pod,get models,get model",
        "pod create,pod update,pod start,pod stop,pod restart,pod reset,pod delete,pod rm,pod remove,pods create,pods update,pods start,pods stop,pods restart,pods reset,pods delete,pods rm,pods remove,serverless create,serverless update,serverless delete,serverless rm,serverless remove,sls create,sls update,sls delete,sls rm,sls remove,template create,template update,template delete,template rm,template remove,tpl create,tpl update,tpl delete,tpl rm,tpl remove,templates create,templates update,templates delete,templates rm,templates remove,model add,model remove,model rm,model delete,network-volume create,network-volume update,network-volume delete,network-volume rm,network-volume remove,nv create,nv update,nv delete,nv rm,nv remove,registry create,registry delete,registry rm,registry remove,reg create,reg delete,reg rm,reg remove,ssh add-key,ssh remove-key,doctor,exec python,project dev,project start,project deploy,create pod,create pods,create model,remove pod,remove pods,remove model,start pod,stop pod"
    ),
    "s3cmd": .init(
        "ls,la,du,info,multipart,listmp,gettagging,ws-info,getlifecycle,getnotification,cflist,cfinfo,cfinvalinfo",
        "mb,rb,put,get,del,rm,restore,sync,cp,modify,mv,setacl,setversioning,setownership,setblockpublicaccess,setobjectlegalhold,setobjectretention,setpolicy,delpolicy,setcors,delcors,payer,abortmp,accesslog,signurl,fixbucket,settagging,deltagging,ws-create,ws-delete,expire,setlifecycle,dellifecycle,setnotification,delnotification,cfcreate,cfdelete,cfmodify,cfinval",
        secretDump: "sign,--configure,--dump-config"
    ),
    "sentry-cli": .init(
        "build download,deploys list,events list,info,issues list,logs list,monitors list,organizations list,projects list,releases info,releases list,releases deploys list,repos list,snapshots download",
        "build upload,build snapshots,code-mappings upload,dart-symbol-map upload,debug-files upload,dif upload,difutil upload,deploys new,issues mute,issues resolve,issues unresolve,proguard upload,react-native gradle,react-native xcode,releases archive,releases delete,releases finalize,releases new,releases restore,releases set-commits,releases deploys new,snapshots upload,sourcemaps upload,upload-dif,upload-dsym,upload-proguard"
    ),
    "snowflake-cli": .init("", ""),
    "snyk": .init("", "monitor,auth"),
    "transifex-cli": .init("status", "pull,push"),
    "travis": .init("whoami,repos,history,show,logs", "restart,cancel,enable,disable", secretDump: "token"),
    "twine": .init("", ""),
    "vagrant": .init("", ""),
    "vault": .init("status,list,kv list,token lookup", "write,delete,kv put,kv delete", secretDump: "read,kv get,login,token create,token generate"),
    "virustotal-cli": .init("file,url,domain,ip,collection", "scan,upload"),
    "vultr": .init("instance list,instance get,region list,plan list", "instance create,instance delete,instance start,instance stop"),
    "wsk": .init("action list,action get,namespace list,package list,trigger list", "action create,action update,action delete,action invoke", secretDump: "property get"),
    "stripe": .init("", ""),
    "supabase": .init("projects list,functions list,status,inspect", "link,unlink,db push,db reset,functions deploy,secrets set,secrets unset"),
]

let genericSecretGatePolicyIDs: Set<String> = Set(secretGateCommandPolicies.keys)
