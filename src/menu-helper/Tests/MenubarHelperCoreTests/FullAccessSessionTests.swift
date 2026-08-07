import Foundation
import Testing
@testable import MenubarHelperCore

@Test func fullAccessSessionStartsInactiveAndDoesNotPersistAcrossControllers() {
    let now = Date(timeIntervalSince1970: 1_000)
    let first = FullAccessSessionController()

    #expect(!first.isActive(at: now))
    #expect(first.start(at: now, duration: 300))
    #expect(first.isActive(at: now))
    #expect(!FullAccessSessionController().isActive(at: now))
}

@Test func fullAccessSessionDurationIsPositiveAndCappedAtOneHour() throws {
    let now = Date(timeIntervalSince1970: 2_000)
    let session = FullAccessSessionController()

    #expect(!session.start(at: now, uptime: 100, duration: 0))
    #expect(!session.start(at: now, uptime: 100, duration: -1))
    #expect(!session.start(at: now, uptime: 100, duration: .infinity))
    #expect(!session.start(at: now, uptime: 100, duration: .nan))
    #expect(session.start(
        at: now,
        uptime: 100,
        duration: fullAccessSessionMaximumDuration * 2
    ))

    let snapshot = try #require(session.snapshot(at: now, uptime: 100))
    #expect(snapshot.expiresAt == now.addingTimeInterval(fullAccessSessionMaximumDuration))
    #expect(snapshot.remaining(at: now, uptime: 100) == fullAccessSessionMaximumDuration)
}

@Test func fullAccessSessionExpiresAndCanAlwaysBeEnded() {
    let now = Date(timeIntervalSince1970: 3_000)
    let session = FullAccessSessionController()

    #expect(session.start(at: now, uptime: 200, duration: 30))
    #expect(session.isActive(at: now.addingTimeInterval(29), uptime: 229))
    #expect(!session.isActive(at: now.addingTimeInterval(30), uptime: 230))
    #expect(session.snapshot(at: now.addingTimeInterval(30), uptime: 230) == nil)

    #expect(session.start(at: now, uptime: 300, duration: 30))
    session.end()
    #expect(!session.isActive(at: now, uptime: 300))
}

@Test func fullAccessSessionExpiresWhenTheWallClockMovesBackward() {
    let now = Date(timeIntervalSince1970: 4_000)
    let session = FullAccessSessionController()

    #expect(session.start(at: now, uptime: 500, duration: 60))
    #expect(session.snapshot(
        at: now.addingTimeInterval(-300),
        uptime: 559
    )?.remaining(at: now.addingTimeInterval(-300), uptime: 559) == 1)
    #expect(session.snapshot(
        at: now.addingTimeInterval(-300),
        uptime: 560
    ) == nil)
}

@Test func endingWaitsForAnAuthorizedReleaseToFinish() throws {
    let now = Date(timeIntervalSince1970: 5_000)
    let session = FullAccessSessionController()
    #expect(session.start(at: now, uptime: 600, duration: 60))
    let lease = try #require(session.lease(at: now, uptime: 600))
    let releaseStarted = DispatchSemaphore(value: 0)
    let allowReleaseToFinish = DispatchSemaphore(value: 0)
    let releaseFinished = DispatchSemaphore(value: 0)
    let endFinished = DispatchSemaphore(value: 0)

    DispatchQueue.global().async {
        _ = session.withActiveLease(lease, at: now, uptime: 600) {
            releaseStarted.signal()
            allowReleaseToFinish.wait()
        }
        releaseFinished.signal()
    }
    #expect(releaseStarted.wait(timeout: .now() + 1) == .success)
    DispatchQueue.global().async {
        session.end()
        endFinished.signal()
    }
    #expect(endFinished.wait(timeout: .now() + 0.02) == .timedOut)

    allowReleaseToFinish.signal()
    #expect(releaseFinished.wait(timeout: .now() + 1) == .success)
    #expect(endFinished.wait(timeout: .now() + 1) == .success)
    #expect(!session.isActive(at: now, uptime: 600))
}

@Test(
    arguments: SecretGateRequestClassification.allCases
)
func fullAccessSessionAllowsEveryRecognizedClassification(
    classification: SecretGateRequestClassification
) {
    let gate = fullAccessTestGate(id: "aws", keyPatterns: ["AWS_*"])
    let protection = fullAccessSessionProtection(
        for: gate,
        classification: classification,
        launcherEligible: true,
        sessionActive: true
    )

    if classification == .unknown {
        #expect(protection == nil)
    } else {
        #expect(protection == .fullIncludingSecretDumps)
    }
}

@Test func fullAccessSessionRequiresAnActiveSessionAndEligibleLauncher() {
    let gate = fullAccessTestGate(id: "aws", keyPatterns: ["AWS_*"])

    #expect(fullAccessSessionProtection(
        for: gate,
        classification: .readOnly,
        launcherEligible: false,
        sessionActive: true
    ) == nil)
    #expect(fullAccessSessionProtection(
        for: gate,
        classification: .readOnly,
        launcherEligible: true,
        sessionActive: false
    ) == nil)
}

@Test func fullAccessSessionUsesEachGatesNormalizedFullAccessLevel() {
    let brew = fullAccessTestGate(id: "brew", keyPatterns: [])
    let secretless = fullAccessTestGate(id: "custom", keyPatterns: [])

    #expect(fullAccessSessionProtection(
        for: brew,
        classification: .mutating,
        launcherEligible: true,
        sessionActive: true
    ) == .fullExceptSecretDumps)
    #expect(fullAccessSessionProtection(
        for: secretless,
        classification: .mutating,
        launcherEligible: true,
        sessionActive: true
    ) == .fullExceptSecretDumps)
    #expect(fullAccessSessionProtection(
        for: secretless,
        classification: .secretDump,
        launcherEligible: true,
        sessionActive: true
    ) == nil)
}

private func fullAccessTestGate(id: String, keyPatterns: [String]) -> SecretGate {
    SecretGate(
        id: id,
        keyPatterns: keyPatterns,
        routes: [],
        defaultProtection: .noAccess,
        appPolicies: []
    )
}
