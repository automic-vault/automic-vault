import Foundation
import Testing
@testable import MenubarHelperCore

private let codexID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
private let claudeID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!

private func scope(
    gateID: String = "aws",
    launcherRequirement: String = "identifier com.example.launcher",
    runtimeRequirement: LauncherRuntimeRequirement = .hardened,
    agent: AgentTaskContext = AgentTaskContext(provider: .codex, id: codexID)
) -> TemporaryAccessGrantScope {
    TemporaryAccessGrantScope(
        authorizationGateID: gateID,
        launcherDesignatedRequirement: launcherRequirement,
        launcherRuntimeRequirement: runtimeRequirement,
        agentTaskContext: agent
    )
}

@Test func temporaryGrantPresentationExplainsEligibility() {
    #expect(operationClassificationTitle(.readOnly) == "Read Only")
    #expect(operationClassificationTitle(.localWrite) == "Local Write")
    #expect(operationClassificationTitle(.update) == "Homebrew Update")
    #expect(operationClassificationTitle(.mutating)
        == "Local Write, System Write, Remote Write, or a combination")
    #expect(operationClassificationTitle(.secretDump)
        == "Elevated Secret Application or Secret Disclosure")
    #expect(operationClassificationTitle(.unknown) == "Unknown")

    let agent = AgentTaskContext(provider: .codex, id: codexID)
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: true,
        classification: .unknown,
        launcherRuntimeProtection: .hardened,
        agentTaskContext: agent
    ) == "10-minute Write Access excludes Unknown operations.")
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: false,
        classification: nil,
        launcherRuntimeProtection: .hardened,
        agentTaskContext: agent
    ) == "10-minute Write Access is unavailable at the Direct Secret Gate.")
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: true,
        classification: .readOnly,
        launcherRuntimeProtection: .hardened,
        agentTaskContext: agent
    ) == "10-minute Write Access is available only for recognized write operations.")
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: true,
        classification: .secretDump,
        launcherRuntimeProtection: .hardened,
        agentTaskContext: agent
    ) == "10-minute Write Access excludes Elevated Secret Application and Secret Disclosure.")
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: true,
        classification: .mutating,
        launcherRuntimeProtection: nil,
        agentTaskContext: agent
    ) == "10-minute Write Access requires an eligible Verified Launcher and runtime posture.")
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: true,
        classification: .mutating,
        launcherRuntimeProtection: .hardened,
        agentTaskContext: nil
    ) == "10-minute Write Access requires a recognized Codex task or Claude Code session.")
    #expect(temporaryAccessGrantUnavailableReason(
        hasToolSpecificGate: true,
        classification: .mutating,
        launcherRuntimeProtection: .hardened,
        agentTaskContext: agent
    ) == nil)
}

@Test func recognizedAgentEnvironmentProducesExactContext() throws {
    let codex = try #require(AgentTaskContext(environment: [
        "CODEX_THREAD_ID": codexID.uuidString.lowercased(),
    ]))
    #expect(codex == AgentTaskContext(provider: .codex, id: codexID))
    #expect(codex.abbreviatedID == "11111111")

    let claude = try #require(AgentTaskContext(environment: [
        "CLAUDE_CODE_SESSION_ID": claudeID.uuidString,
    ]))
    #expect(claude == AgentTaskContext(provider: .claudeCode, id: claudeID))
}

@Test(arguments: [
    [:],
    ["CODEX_THREAD_ID": "not-a-uuid"],
    ["CODEX_THREAD_ID": "{11111111-2222-3333-4444-555555555555}"],
    ["CLAUDE_CODE_SESSION_ID": ""],
    [
        "CODEX_THREAD_ID": codexID.uuidString,
        "CLAUDE_CODE_SESSION_ID": claudeID.uuidString,
    ],
    [
        "CODEX_THREAD_ID": codexID.uuidString,
        "CLAUDE_CODE_SESSION_ID": "malformed",
    ],
])
func malformedMissingOrAmbiguousAgentEnvironmentIsRejected(_ environment: [String: String]) {
    #expect(AgentTaskContext(environment: environment) == nil)
}

@Test func fixedDualClockExpiryUsesEitherDeadline() {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )
    #expect(controller.snapshots(wallNow: start.addingTimeInterval(599), monotonicNow: 649).count == 1)
    #expect(controller.snapshots(wallNow: start.addingTimeInterval(600), monotonicNow: 100).isEmpty)

    controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )
    #expect(controller.snapshots(wallNow: start, monotonicNow: 650).isEmpty)
}

@Test func suspendedCountdownFreezesRemainingTimeAndAuthority() throws {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let grant = controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )

    let suspended = try #require(controller.setCountdownSuspended(
        id: grant.id,
        suspended: true,
        wallNow: start.addingTimeInterval(100),
        monotonicNow: 150
    ))
    #expect(suspended.isCountdownSuspended)
    #expect(suspended.remaining(wallNow: start.addingTimeInterval(10_000), monotonicNow: 10_050) == 500)
    #expect(controller.withActiveLease(
        authorizationGateID: "aws",
        launcherDesignatedRequirement: "identifier com.example.launcher",
        launcherRuntimeProtection: .hardened,
        agentTaskContext: AgentTaskContext(provider: .codex, id: codexID),
        classification: .mutating,
        wallNow: start.addingTimeInterval(10_000),
        monotonicNow: 10_050
    ) { _ in true } == nil)

    let resumedAt = start.addingTimeInterval(10_000)
    let resumed = try #require(controller.setCountdownSuspended(
        id: grant.id,
        suspended: false,
        wallNow: resumedAt,
        monotonicNow: 10_050
    ))
    #expect(!resumed.isCountdownSuspended)
    #expect(resumed.expiresAt == resumedAt.addingTimeInterval(500))
    #expect(resumed.monotonicDeadline == 10_550)
    #expect(controller.withActiveLease(
        authorizationGateID: "aws",
        launcherDesignatedRequirement: "identifier com.example.launcher",
        launcherRuntimeProtection: .hardened,
        agentTaskContext: AgentTaskContext(provider: .codex, id: codexID),
        classification: .mutating,
        wallNow: resumedAt,
        monotonicNow: 10_050
    ) { _ in true } == true)
    #expect(controller.snapshots(
        wallNow: resumedAt.addingTimeInterval(500),
        monotonicNow: 10_050
    ).isEmpty)
}

@Test func suspendedCountdownPreservesTheLesserClockRemainder() throws {
    let start = Date(timeIntervalSince1970: 1_000)

    let wallLimited = TemporaryAccessGrantController()
    let wallGrant = wallLimited.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )
    let wallSuspended = try #require(wallLimited.setCountdownSuspended(
        id: wallGrant.id,
        suspended: true,
        wallNow: start.addingTimeInterval(590),
        monotonicNow: 150
    ))
    #expect(wallSuspended.suspendedRemaining == 10)

    let monotonicLimited = TemporaryAccessGrantController()
    let monotonicGrant = monotonicLimited.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )
    let monotonicSuspended = try #require(monotonicLimited.setCountdownSuspended(
        id: monotonicGrant.id,
        suspended: true,
        wallNow: start.addingTimeInterval(100),
        monotonicNow: 640
    ))
    #expect(monotonicSuspended.suspendedRemaining == 10)

    let resumedAt = start.addingTimeInterval(10_000)
    let resumed = try #require(monotonicLimited.setCountdownSuspended(
        id: monotonicGrant.id,
        suspended: false,
        wallNow: resumedAt,
        monotonicNow: 20_000
    ))
    #expect(resumed.expiresAt == resumedAt.addingTimeInterval(10))
    #expect(resumed.monotonicDeadline == 20_010)
}

@Test func expiredCountdownCannotBeSuspended() {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let grant = controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )
    #expect(controller.setCountdownSuspended(
        id: grant.id,
        suspended: true,
        wallNow: start.addingTimeInterval(600),
        monotonicNow: 50
    ) == nil)
}

@Test func tenMinuteExtensionsPreserveCountdownStateAndCannotReviveExpiry() throws {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let grant = controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )

    let extended = try #require(controller.addTenMinutes(
        id: grant.id,
        wallNow: start.addingTimeInterval(100),
        monotonicNow: 150
    ))
    #expect(extended.expiresAt == start.addingTimeInterval(1_200))
    #expect(extended.monotonicDeadline == 1_250)
    #expect(extended.remaining(wallNow: start.addingTimeInterval(100), monotonicNow: 150) == 1_100)

    _ = controller.setCountdownSuspended(
        id: grant.id,
        suspended: true,
        wallNow: start.addingTimeInterval(200),
        monotonicNow: 250
    )
    let suspendedExtension = try #require(controller.addTenMinutes(
        id: grant.id,
        wallNow: start.addingTimeInterval(10_000),
        monotonicNow: 10_050
    ))
    #expect(suspendedExtension.isCountdownSuspended)
    #expect(suspendedExtension.suspendedRemaining == 1_600)

    let expiredController = TemporaryAccessGrantController()
    let expired = expiredController.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 50
    )
    #expect(expiredController.addTenMinutes(
        id: expired.id,
        wallNow: start.addingTimeInterval(600),
        monotonicNow: 650
    ) == nil)
}

@Test func multipleScopesCoexistAndDuplicateScopeRefreshesInPlace() throws {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let first = controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 10
    )
    _ = controller.start(
        scope: scope(gateID: "github"),
        launcherName: "Codex",
        authorizationGateName: "GitHub",
        wallNow: start,
        monotonicNow: 10
    )
    #expect(controller.snapshots(wallNow: start, monotonicNow: 10).count == 2)

    let refreshed = controller.start(
        scope: scope(),
        launcherName: "Codex App",
        authorizationGateName: "AWS",
        wallNow: start.addingTimeInterval(20),
        monotonicNow: 30
    )
    #expect(refreshed.id == first.id)
    #expect(refreshed.generation != first.generation)
    #expect(refreshed.expiresAt == start.addingTimeInterval(620))
    #expect(refreshed.useCount == 1)
    #expect(refreshed.lastUsedAt == start.addingTimeInterval(20))
    #expect(controller.snapshots(wallNow: start, monotonicNow: 30).count == 2)
}

@Test func successfulUsesUpdateGrantUsage() throws {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let grant = controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 10
    )
    #expect(grant.useCount == 1)
    #expect(grant.lastUsedAt == start)

    _ = controller.withActiveLease(
        authorizationGateID: "aws",
        launcherDesignatedRequirement: "identifier com.example.launcher",
        launcherRuntimeProtection: .hardened,
        agentTaskContext: AgentTaskContext(provider: .codex, id: codexID),
        classification: .mutating,
        wallNow: start.addingTimeInterval(5),
        monotonicNow: 15
    ) { _ in false }
    let afterFailure = try #require(controller.snapshots(
        wallNow: start.addingTimeInterval(5),
        monotonicNow: 15
    ).first)
    #expect(afterFailure.useCount == 1)
    #expect(afterFailure.lastUsedAt == start)

    _ = controller.withActiveLease(
        authorizationGateID: "aws",
        launcherDesignatedRequirement: "identifier com.example.launcher",
        launcherRuntimeProtection: .hardened,
        agentTaskContext: AgentTaskContext(provider: .codex, id: codexID),
        classification: .mutating,
        wallNow: start.addingTimeInterval(10),
        monotonicNow: 20
    ) { _ in true }
    let afterSuccess = try #require(controller.snapshots(
        wallNow: start.addingTimeInterval(10),
        monotonicNow: 20
    ).first)
    #expect(afterSuccess.useCount == 2)
    #expect(afterSuccess.lastUsedAt == start.addingTimeInterval(10))
}

@Test func requestQueuedBeforeGrantIsEligibleWhenAuthorizationDecisionRuns() throws {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let attempt = { (wallNow: Date, monotonicNow: TimeInterval) in
        controller.withActiveLease(
            authorizationGateID: "aws",
            launcherDesignatedRequirement: "identifier com.example.launcher",
            launcherRuntimeProtection: .hardened,
            agentTaskContext: AgentTaskContext(provider: .codex, id: codexID),
            classification: .mutating,
            wallNow: wallNow,
            monotonicNow: monotonicNow
        ) { _ in true }
    }

    #expect(attempt(start, 10) == nil)
    controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start.addingTimeInterval(5),
        monotonicNow: 15
    )
    #expect(attempt(start.addingTimeInterval(6), 16) == true)

    let grant = try #require(controller.snapshots(
        wallNow: start.addingTimeInterval(6),
        monotonicNow: 16
    ).first)
    #expect(grant.useCount == 2)
    #expect(grant.lastUsedAt == start.addingTimeInterval(6))
}

@Test func exactScopeAndWriteClassificationAreRequired() {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    #expect(scope().protection == .fullExceptSecretDumps)
    controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 10
    )
    let base = { (
        gate: String,
        launcher: String,
        runtime: LauncherRuntimeProtection,
        agent: AgentTaskContext,
        classification: SecretGateRequestClassification
    ) in
        controller.withActiveLease(
            authorizationGateID: gate,
            launcherDesignatedRequirement: launcher,
            launcherRuntimeProtection: runtime,
            agentTaskContext: agent,
            classification: classification,
            wallNow: start,
            monotonicNow: 10
        ) { _ in true }
    }
    let agent = AgentTaskContext(provider: .codex, id: codexID)
    #expect(base("aws", "identifier com.example.launcher", .hardened, agent, .localWrite) == true)
    #expect(base("github", "identifier com.example.launcher", .hardened, agent, .mutating) == nil)
    #expect(base("aws", "identifier com.other", .hardened, agent, .mutating) == nil)
    #expect(base("aws", "identifier com.example.launcher", .hardened, AgentTaskContext(provider: .codex, id: UUID()), .update) == nil)
    #expect(base("aws", "identifier com.example.launcher", .hardened, AgentTaskContext(provider: .claudeCode, id: codexID), .update) == nil)
    #expect(base("aws", "identifier com.example.launcher", .hardenedWithLibraryValidationDisabled, agent, .mutating) == nil)
    #expect(base("aws", "identifier com.example.launcher", .hardened, agent, .secretDump) == nil)
    #expect(base("aws", "identifier com.example.launcher", .hardened, agent, .unknown) == nil)

    let expandedRuntime = TemporaryAccessGrantController()
    expandedRuntime.start(
        scope: scope(runtimeRequirement: .hardenedAllowingLibraryValidationDisabled),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 10
    )
    #expect(expandedRuntime.withActiveLease(
        authorizationGateID: "aws",
        launcherDesignatedRequirement: "identifier com.example.launcher",
        launcherRuntimeProtection: .hardened,
        agentTaskContext: agent,
        classification: .mutating,
        wallNow: start,
        monotonicNow: 10
    ) { _ in true } == nil)
}

@Test func cancellationWaitsForAnActiveLeaseAndThenRevokesIt() throws {
    let controller = TemporaryAccessGrantController()
    let start = Date(timeIntervalSince1970: 1_000)
    let grant = controller.start(
        scope: scope(),
        launcherName: "Codex",
        authorizationGateName: "AWS",
        wallNow: start,
        monotonicNow: 10
    )
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let leaseFinished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        _ = controller.withActiveLease(
            authorizationGateID: "aws",
            launcherDesignatedRequirement: "identifier com.example.launcher",
            launcherRuntimeProtection: .hardened,
            agentTaskContext: AgentTaskContext(provider: .codex, id: codexID),
            classification: .mutating,
            wallNow: start,
            monotonicNow: 10
        ) { _ in
            entered.signal()
            _ = release.wait(timeout: .now() + 5)
            return true
        }
        leaseFinished.signal()
    }
    defer { release.signal() }
    try #require(entered.wait(timeout: .now() + 5) == .success)
    let cancelFinished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        _ = controller.cancel(id: grant.id)
        cancelFinished.signal()
    }
    #expect(cancelFinished.wait(timeout: .now() + 0.05) == .timedOut)
    release.signal()
    try #require(leaseFinished.wait(timeout: .now() + 5) == .success)
    try #require(cancelFinished.wait(timeout: .now() + 5) == .success)
    #expect(controller.snapshots(wallNow: start, monotonicNow: 10).isEmpty)
}

@Test func cancellationWaitsForTheActivationReplyLease() throws {
    let controller = TemporaryAccessGrantController()
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let activationFinished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        _ = controller.startWithLease(
            scope: scope(),
            launcherName: "Codex",
            authorizationGateName: "AWS"
        ) { _ in
            entered.signal()
            _ = release.wait(timeout: .now() + 5)
        }
        activationFinished.signal()
    }
    defer { release.signal() }
    try #require(entered.wait(timeout: .now() + 5) == .success)
    let cancelFinished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        controller.cancelAll()
        cancelFinished.signal()
    }
    #expect(cancelFinished.wait(timeout: .now() + 0.05) == .timedOut)
    release.signal()
    try #require(activationFinished.wait(timeout: .now() + 5) == .success)
    try #require(cancelFinished.wait(timeout: .now() + 5) == .success)
    #expect(controller.snapshots().isEmpty)
}
