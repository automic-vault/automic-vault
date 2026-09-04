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
        Set(value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
    }
}

public func genericSecretGateRequestClassification(
    gateID: String,
    arguments: [String]
) -> SecretGateRequestClassification {
    if gateID == "composer" { return composerRequestClassification(arguments) }
    let words = arguments.map { $0.lowercased() }
    guard !words.isEmpty else { return .unknown }
    if gateID == "stripe" { return stripeRequestClassification(words) }
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
    guard let policy = secretGateCommandPolicies[gateID] else { return .unknown }
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
    "doctl": .init("account get,compute droplet list,compute droplet get,kubernetes cluster list,kubernetes cluster get", "compute droplet create,compute droplet delete,kubernetes cluster create,kubernetes cluster delete"),
    "flyctl": .init("status,apps list,machine list,machine status,secrets list,auth whoami", "deploy,scale,apps create,apps destroy,machine run,machine destroy,secrets set,secrets unset,secrets import", secretDump: "auth token"),
    "glab": .init("repo view,repo list,issue list,issue view,mr list,mr view,pipeline list,pipeline view", "repo create,repo delete,issue create,mr create,pipeline run", secretDump: "auth token,auth status --show-token"),
    "gotify": .init("health,version", "push"),
    "gptcommit": .init("", "prepare,commit"),
    "grafanactl": .init("resources get,resources list", "resources create,resources delete,resources apply"),
    "heroku": .init("apps,apps info,ps,addons", "apps create,apps destroy,config set,config unset,ps scale", secretDump: "auth token,config"),
    "hcloud": .init("server list,server describe,network list,network describe", "server create,server delete,network create,network delete"),
    "huggingface-cli": .init(
        "auth whoami,cache verify,env,download,buckets list,buckets ls,buckets info,collections list,collections ls,collections info,datasets list,datasets ls,datasets leaderboard,datasets info,datasets parquet,datasets sql,datasets card,discussions list,discussions ls,discussions info,discussions diff,endpoints list,endpoints ls,endpoints hardware,endpoints describe,endpoints catalog list,endpoints catalog ls,endpoints list-catalog,jobs logs,jobs stats,jobs list,jobs ls,jobs ps,jobs hardware,jobs inspect,jobs wait,jobs scheduled list,jobs scheduled ls,jobs scheduled ps,jobs scheduled inspect,models list,models ls,models info,models card,papers list,papers ls,papers search,papers info,papers read,repo list,repo ls,repos list,repos ls,repo tag list,repo tag ls,repos tag list,repos tag ls,sandbox pool ls,sandbox pool list,sandbox process ls,sandbox process list,spaces list,spaces ls,spaces info,spaces card,spaces templates,spaces search,spaces wait,spaces hardware,spaces logs,spaces volumes list,spaces volumes ls,spaces secrets list,spaces secrets ls,spaces variables list,spaces variables ls,webhooks list,webhooks ls,webhooks info",
        "upload,upload-large-folder,buckets create,buckets delete,buckets remove,buckets rm,buckets move,buckets settings,buckets sync,collections create,collections update,collections delete,collections add-item,collections update-item,collections delete-item,discussions create,discussions comment,discussions edit,discussions close,discussions reopen,discussions rename,discussions merge,endpoints deploy,endpoints catalog deploy,endpoints update,endpoints delete,endpoints pause,endpoints resume,endpoints scale-to-zero,jobs run,jobs cancel,jobs labels,jobs ssh,jobs uv run,jobs scheduled run,jobs scheduled delete,jobs scheduled suspend,jobs scheduled resume,jobs scheduled trigger,jobs scheduled labels,jobs scheduled uv,repo create,repo duplicate,repo delete,repo move,repo settings,repo delete-files,repo branch create,repo branch delete,repo tag create,repo tag delete,repos create,repos duplicate,repos delete,repos move,repos settings,repos delete-files,repos branch create,repos branch delete,repos tag create,repos tag delete,repo-files delete,sandbox create,sandbox exec,sandbox spawn,sandbox cp,sandbox kill,sandbox pool create,sandbox pool delete,sandbox pool rm,sandbox process kill,spaces dev-mode,spaces ssh,spaces pause,spaces restart,spaces settings,spaces hot-reload,spaces volumes set,spaces volumes delete,spaces secrets add,spaces secrets delete,spaces variables add,spaces variables delete,webhooks create,webhooks update,webhooks enable,webhooks disable,webhooks delete",
        secretDump: "auth token"
    ),
    "jfrog-cli": .init("rt search,rt ping,rt build-info", "rt upload,rt delete,rt build-publish", secretDump: "config show,config export"),
    "k6": .init("", ""),
    "luarocks": .init("search,show,list,which", "install,remove,upload,publish"),
    "minio-mc": .init("ls,stat,find,du,tree", "cp,mv,rm,mb,rb,mirror", secretDump: "alias export"),
    "netlify-cli": .init("status,sites list,functions list", "deploy,sites create,sites delete,functions create", secretDump: "env list,env get"),
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
    "pulumi": .init("whoami,stack ls,preview,about,config get", "up,destroy,refresh,import,cancel", secretDump: "config get --show-secrets,stack export --show-secrets"),
    "qwen-code": .init("", "chat,run"),
    "runpodctl": .init("get,list", "create,remove,start,stop", secretDump: "config view"),
    "s3cmd": .init("ls,la,info,du", "put,get,del,rm,sync,cp,mv,mb,rb", secretDump: "--dump-config"),
    "sentry-cli": .init("projects list,organizations list,releases list", "send-event,releases new,releases deploys new,upload-dif"),
    "snowflake-cli": .init("object list,object describe,connection test", "object create,object drop,stage copy"),
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
