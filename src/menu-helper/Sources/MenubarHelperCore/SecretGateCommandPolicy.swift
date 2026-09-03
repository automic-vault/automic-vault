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
    "composer": .init("show,search,outdated,audit,diagnose", "install,update,require,remove,publish", secretDump: "config --auth,config --global --auth"),
    "doctl": .init("account get,compute droplet list,compute droplet get,kubernetes cluster list,kubernetes cluster get", "compute droplet create,compute droplet delete,kubernetes cluster create,kubernetes cluster delete"),
    "flyctl": .init("status,apps list,machine list,machine status,secrets list,auth whoami", "deploy,scale,apps create,apps destroy,machine run,machine destroy,secrets set,secrets unset,secrets import", secretDump: "auth token"),
    "glab": .init("repo view,repo list,issue list,issue view,mr list,mr view,pipeline list,pipeline view", "repo create,repo delete,issue create,mr create,pipeline run", secretDump: "auth token,auth status --show-token"),
    "gotify": .init("health,version", "push"),
    "gptcommit": .init("", "prepare,commit"),
    "grafanactl": .init("resources get,resources list", "resources create,resources delete,resources apply"),
    "heroku": .init("apps,apps info,ps,addons", "apps create,apps destroy,config set,config unset,ps scale", secretDump: "auth token,config"),
    "hcloud": .init("server list,server describe,network list,network describe", "server create,server delete,network create,network delete"),
    "huggingface-cli": .init("auth whoami,repo list,cache scan", "upload,upload-large-folder,repo create,repo delete"),
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
    "twine": .init("check", "upload"),
    "vagrant": .init("status,global-status,validate,version", "up,destroy,halt,reload,suspend,resume,cloud publish"),
    "vault": .init("status,list,kv list,token lookup", "write,delete,kv put,kv delete", secretDump: "read,kv get,login,token create,token generate"),
    "virustotal-cli": .init("file,url,domain,ip,collection", "scan,upload"),
    "vultr": .init("instance list,instance get,region list,plan list", "instance create,instance delete,instance start,instance stop"),
    "wsk": .init("action list,action get,namespace list,package list,trigger list", "action create,action update,action delete,action invoke", secretDump: "property get"),
    "stripe": .init("", ""),
    "supabase": .init("projects list,functions list,status,inspect", "link,unlink,db push,db reset,functions deploy,secrets set,secrets unset"),
]

let genericSecretGatePolicyIDs: Set<String> = Set(secretGateCommandPolicies.keys)
