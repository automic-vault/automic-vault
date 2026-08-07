import Foundation
import Testing
@testable import MenubarHelperCore

@Test func fullAccessSessionStartsInactiveAndDoesNotPersistAcrossControllers() {
    let now = Date(timeIntervalSince1970: 1_000)
    let first = FullAccessSessionController()

    #expect(!first.isActive(at: now))
    #expect(first.start(at: now))
    #expect(first.isActive(at: now))
    #expect(first.snapshot(at: now)?.lifetime == .untilEnded)
    #expect(!FullAccessSessionController().isActive(at: now))
}

@Test(
    arguments: [
        (FullAccessSessionLifetime.oneHour, 60.0 * 60),
        (FullAccessSessionLifetime.eightHours, 8.0 * 60 * 60),
    ]
)
func timedFullAccessSessionLifetimeExpiresAtItsPreset(
    lifetime: FullAccessSessionLifetime,
    expectedDuration: TimeInterval
) throws {
    let now = Date(timeIntervalSince1970: 2_000)
    let session = FullAccessSessionController()

    #expect(session.start(at: now, uptime: 100, lifetime: lifetime))

    let snapshot = try #require(session.snapshot(at: now, uptime: 100))
    #expect(snapshot.lifetime == lifetime)
    #expect(snapshot.expiresAt == now.addingTimeInterval(expectedDuration))
    #expect(snapshot.remaining(at: now, uptime: 100) == expectedDuration)
}

@Test func fullAccessSessionExpiresAndCanAlwaysBeEnded() throws {
    let now = Date(timeIntervalSince1970: 3_000)
    let session = FullAccessSessionController()

    #expect(session.start(at: now, uptime: 200, lifetime: .oneHour))
    #expect(session.isActive(at: now.addingTimeInterval(3_599), uptime: 3_799))
    #expect(!session.isActive(at: now.addingTimeInterval(3_600), uptime: 3_800))
    #expect(session.snapshot(at: now.addingTimeInterval(3_600), uptime: 3_800) == nil)

    #expect(session.start(at: now, uptime: 300, lifetime: .untilEnded))
    let snapshot = try #require(session.snapshot(
        at: now.addingTimeInterval(60 * 60 * 24 * 365),
        uptime: 60 * 60 * 24 * 365
    ))
    #expect(snapshot.lifetime == .untilEnded)
    #expect(snapshot.expiresAt == nil)
    #expect(snapshot.remaining(at: now, uptime: 300) == nil)
    session.end()
    #expect(!session.isActive(at: now, uptime: 300))
}

@Test func fullAccessSessionExpiresWhenTheWallClockMovesBackward() {
    let now = Date(timeIntervalSince1970: 4_000)
    let session = FullAccessSessionController()

    #expect(session.start(at: now, uptime: 500, lifetime: .oneHour))
    #expect(session.snapshot(
        at: now.addingTimeInterval(-300),
        uptime: 4_099
    )?.remaining(at: now.addingTimeInterval(-300), uptime: 4_099) == 1)
    #expect(session.snapshot(
        at: now.addingTimeInterval(-300),
        uptime: 4_100
    ) == nil)
}

@Test func endingWaitsForAnAuthorizedReleaseToFinish() throws {
    let now = Date(timeIntervalSince1970: 5_000)
    let session = FullAccessSessionController()
    #expect(session.start(at: now, uptime: 600, lifetime: .untilEnded))
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
