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

    #expect(!session.start(at: now, duration: 0))
    #expect(!session.start(at: now, duration: -1))
    #expect(!session.start(at: now, duration: .infinity))
    #expect(!session.start(at: now, duration: .nan))
    #expect(session.start(at: now, duration: fullAccessSessionMaximumDuration * 2))

    let snapshot = try #require(session.snapshot(at: now))
    #expect(snapshot.expiresAt == now.addingTimeInterval(fullAccessSessionMaximumDuration))
    #expect(snapshot.remaining(at: now) == fullAccessSessionMaximumDuration)
}

@Test func fullAccessSessionExpiresAndCanAlwaysBeEnded() {
    let now = Date(timeIntervalSince1970: 3_000)
    let session = FullAccessSessionController()

    #expect(session.start(at: now, duration: 30))
    #expect(session.isActive(at: now.addingTimeInterval(29)))
    #expect(!session.isActive(at: now.addingTimeInterval(30)))
    #expect(session.snapshot(at: now.addingTimeInterval(30)) == nil)

    #expect(session.start(at: now, duration: 30))
    session.end()
    #expect(!session.isActive(at: now))
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
