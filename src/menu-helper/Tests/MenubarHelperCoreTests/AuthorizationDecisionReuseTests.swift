import Foundation
import Testing
@testable import MenubarHelperCore

enum RequestMutation: CaseIterable {
    case pid, pidVersion, startUsec, effectiveUserID, auditSessionID
    case callerPath, signingIdentifier, signingTeamIdentifier
    case operation, keys, target, arguments, workingDirectory
    case replaceExistingEnvironment, allowMissingSecrets, environmentConflicts
    case shebangScript, scriptData, snapshotIncompatibleInterpreter, tool, title, detail
    case credentialScope, credentialParentPID, credentialParentStartUsec, credentialParentEUID
    case credentialParentTarget, credentialParentArguments, selectedValueSource
}

@Test("an allowed decision is reused only for the complete request", arguments: RequestMutation.allCases)
func authorizationDecisionReuseBindsEveryRequestField(_ mutation: RequestMutation) {
    let approved = reuseRequest()
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(.approved, for: approved, now: Date(timeIntervalSince1970: 100))

    #expect(
        cache.decision(
            for: reuseRequest(mutation),
            now: Date(timeIntervalSince1970: 101)
        ) == nil,
        "mutation unexpectedly reused approval: \(mutation)"
    )
}

@Test func authorizationDecisionReuseNormalizesSetsButPreservesArgumentOrder() {
    let approved = reuseRequest(keys: ["B", "A", "A"], conflicts: ["Y", "X", "X"])
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(.approved, for: approved, now: Date(timeIntervalSince1970: 100))

    let normalized = reuseRequest(keys: ["A", "B"], conflicts: ["X", "Y"])
    #expect(cache.decision(for: normalized, now: Date(timeIntervalSince1970: 101)) == .approved)
    #expect(
        cache.decision(
            for: reuseRequest(arguments: ["--region", "us-east-1"]),
            now: Date(timeIntervalSince1970: 101)
        ) == nil
    )
}

@Test func authorizationDecisionReuseNeverCachesFreshOnlyApproval() {
    let request = reuseRequest(policy: .freshApprovalRequired)
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(.approved, for: request, now: Date(timeIntervalSince1970: 100))
    cache.remember(.alwaysApproved, for: request, now: Date(timeIntervalSince1970: 100))

    #expect(cache.decision(for: request, now: Date(timeIntervalSince1970: 101)) == nil)
}

@Test func authorizationDecisionReuseDisabledIsolatesRequestsSharingAHelper() {
    let request = reuseRequest(policy: .disabled)
    let otherRequest = reuseRequest(.arguments, policy: .disabled)
    let now = Date(timeIntervalSince1970: 100)
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(.denied, for: request, now: now)
    #expect(cache.decision(for: request, now: now) == nil)
    #expect(cache.decision(for: otherRequest, now: now) == nil)
    #expect(cache.decision(for: reuseRequest(), now: now) == nil)

    cache.remember(.approved, for: request, now: now)
    cache.remember(.alwaysApproved, for: request, now: now)
    #expect(cache.decision(for: request, now: now) == nil)

    // A shared helper's existing denial must not suppress a fresh SSH request.
    cache.remember(.denied, for: reuseRequest(), now: now)
    #expect(cache.decision(for: request, now: now) == nil)
    // Fresh approval alone deliberately retains denial quarantine for other gates.
    #expect(cache.decision(for: reuseRequest(policy: .freshApprovalRequired), now: now) == .denied)
}

@Test func authorizationDecisionReuseDenialQuarantinesTheLiveGateClient() {
    let denied = reuseRequest()
    let differentRequest = reuseRequest(.arguments)
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(.denied, for: denied, now: Date(timeIntervalSince1970: 100))

    #expect(cache.decision(for: differentRequest, now: Date(timeIntervalSince1970: 399)) == .denied)
    #expect(cache.decision(for: differentRequest, now: Date(timeIntervalSince1970: 400)) == nil)
    #expect(
        cache.decision(
            for: reuseRequest(.pidVersion),
            now: Date(timeIntervalSince1970: 101)
        ) == nil
    )
}

@Test(
    "non-terminal authorization outcomes are never cached",
    arguments: [
        AuthorizationDecisionReuseOutcome.canceled,
        .interrupted,
        .temporaryAccessGrant,
    ]
)
func authorizationDecisionReuseIgnoresNonTerminalOutcomes(
    _ outcome: AuthorizationDecisionReuseOutcome
) {
    let request = reuseRequest()
    var cache = AuthorizationDecisionReuseCache()
    cache.remember(outcome, for: request, now: Date(timeIntervalSince1970: 100))

    #expect(cache.decision(for: request, now: Date(timeIntervalSince1970: 101)) == nil)
}

@Test func authorizationDecisionReuseExpiresAllowedDecisionAtTTLBoundary() {
    let request = reuseRequest()
    var cache = AuthorizationDecisionReuseCache(ttl: 300)
    cache.remember(.alwaysApproved, for: request, now: Date(timeIntervalSince1970: 100))

    #expect(cache.decision(for: request, now: Date(timeIntervalSince1970: 399)) == .approved)
    #expect(cache.decision(for: request, now: Date(timeIntervalSince1970: 400)) == nil)
}

private func reuseRequest(
    _ mutation: RequestMutation? = nil,
    keys: [String] = ["API_TOKEN"],
    conflicts: [String] = ["PATH"],
    arguments: [String] = ["repo", "view"],
    policy: AuthorizationDecisionReusePolicy = .reusable
) -> AuthorizationDecisionReuseRequest {
    let client = AuthorizationClientExecution(
        pid: mutation == .pid ? 124 : 123,
        pidVersion: mutation == .pidVersion ? 8 : 7,
        startUsec: mutation == .startUsec ? 457 : 456,
        effectiveUserID: mutation == .effectiveUserID ? 502 : 501,
        auditSessionID: mutation == .auditSessionID ? 43 : 42
    )
    let credentialParent = AuthorizationCredentialHelperParent(
        pid: mutation == .credentialParentPID ? 778 : 777,
        startUsec: mutation == .credentialParentStartUsec ? 889 : 888,
        effectiveUserID: mutation == .credentialParentEUID ? 502 : 501,
        target: mutation == .credentialParentTarget ? "/usr/local/bin/docker-2" : "/usr/local/bin/docker",
        arguments: mutation == .credentialParentArguments ? ["pull"] : ["login"]
    )
    let source: StoredSecretValueSource = mutation == .selectedValueSource
        ? .projectDirectory("/tmp/project-2")
        : .projectDirectory("/tmp/project")
    let selected = SelectedSecretValues(values: [
        "API_TOKEN": StoredSecretValue(
            source: source,
            keychainAccount: "bound-api-token",
            accessibility: .whenUnlocked,
            keychainProperties: []
        ),
    ])
    return AuthorizationDecisionReuseRequest(
        client: client,
        callerPath: mutation == .callerPath ? "/usr/local/bin/other" : "/usr/local/bin/gh",
        signingIdentifier: mutation == .signingIdentifier ? "other" : "gh",
        signingTeamIdentifier: mutation == .signingTeamIdentifier ? "OTHER" : "TEAM",
        operation: mutation == .operation ? "value" : "keys",
        secretNames: mutation == .keys ? ["OTHER_TOKEN"] : keys,
        target: mutation == .target ? "/usr/bin/other" : "/usr/bin/gh",
        arguments: mutation == .arguments ? ["repo", "list"] : arguments,
        workingDirectory: mutation == .workingDirectory ? "/private/tmp" : "/tmp",
        replaceExistingEnvironment: mutation == .replaceExistingEnvironment,
        allowMissingSecrets: mutation == .allowMissingSecrets,
        environmentConflicts: mutation == .environmentConflicts ? ["HOME"] : conflicts,
        shebangScript: mutation == .shebangScript ? "/tmp/two.swift" : "/tmp/one.swift",
        scriptData: mutation == .scriptData ? Data("two".utf8) : Data("one".utf8),
        snapshotIncompatibleInterpreter: mutation == .snapshotIncompatibleInterpreter ? "ruby" : "python",
        tool: mutation == .tool ? "git" : "gh",
        title: mutation == .title ? "Other request" : "Request",
        detail: mutation == .detail ? "Other detail" : "Detail",
        credentialScope: mutation == .credentialScope ? "registry-2.example" : "registry.example",
        credentialParent: credentialParent,
        selectedSecretValues: selected,
        policy: policy
    )
}
