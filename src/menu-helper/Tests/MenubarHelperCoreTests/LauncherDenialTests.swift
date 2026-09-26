import Foundation
import Security
import Testing
@testable import MenubarHelperCore

private func denialGate(_ id: String = "gh") -> SecretGate {
    SecretGate(id: id, keyPatterns: ["TOKEN"], routes: [], defaultProtection: .fullIncludingSecretDumps, appPolicies: [])
}

@Test func denialThresholdsRespectEachGatesPresets() {
    let gh = denialGate()
    #expect(!gh.denies(.readOnly, at: .readOnlyAndLocalWrites))
    #expect(gh.denies(.localWrite, at: .readOnlyAndLocalWrites))
    #expect(gh.denies(.mutating, at: .readOnlyAndLocalWrites))
    #expect(gh.denies(.secretDump, at: .readOnlyAndLocalWrites))
    #expect(!gh.denies(.localWrite, at: .fullExceptSecretDumps))
    #expect(gh.denies(.mutating, at: .fullExceptSecretDumps))
    #expect(!gh.denies(.mutating, at: .fullIncludingSecretDumps))
    #expect(gh.denies(.secretDump, at: .fullIncludingSecretDumps))
    for threshold in gh.availableProtections {
        #expect(gh.denies(.unknown, at: threshold))
    }
    for classification in SecretGateRequestClassification.allCases {
        #expect(gh.denies(classification, at: .noAccess))
        #expect(gh.denies(classification, at: .readOnly))
    }
    let brew = denialGate("brew")
    #expect(!brew.denies(.update, at: .fullExceptSecretDumps))
    #expect(!brew.denies(.readOnly, at: .fullExceptSecretDumps))
    #expect(brew.denies(.mutating, at: .fullExceptSecretDumps))
    #expect(brew.denies(.update, at: .readOnlyAndUpdates))
    #expect(denialGate("gpg-signing").denies(.localWrite, at: .readOnlyAndLocalWrites))
    #expect(denialGate("ssh-agent").denies(.mutating, at: .fullExceptSecretDumps))
    // Unsupported values must not create a hole after a catalog change.
    #expect(brew.denies(.readOnly, at: .fullIncludingSecretDumps))
}

@Test func weakeningDenialRequiresAuthorityButStrengtheningDoesNot() {
    let gate = denialGate()
    #expect(!gate.weakeningDenial(from: nil, to: .noAccess))
    #expect(!gate.weakeningDenial(from: .fullIncludingSecretDumps, to: .fullExceptSecretDumps))
    #expect(!gate.weakeningDenial(from: .fullExceptSecretDumps, to: .fullExceptSecretDumps))
    #expect(gate.weakeningDenial(from: .fullExceptSecretDumps, to: .fullIncludingSecretDumps))
    #expect(gate.weakeningDenial(from: .fullIncludingSecretDumps, to: nil))
    #expect(!gate.weakeningDenial(from: .noAccess, to: .readOnly)) // Both deny everything.
}

@Test func promptFloodOnlyOffersDenialAndNeverActivatesIt() {
    let state = TemporaryLauncherDenials()
    #expect(!state.recordPrompt("claude", now: 100))
    #expect(!state.recordPrompt("claude", now: 110))
    #expect(!state.recordPrompt("other", now: 115))
    #expect(state.recordPrompt("claude", now: 120))
    #expect(!state.isDenied("claude", now: 120))
    #expect(!state.recordPrompt("claude", now: 151))
    #expect(!state.recordPrompt("", now: 151))
}

@Test func temporaryDenialSurvivesRetriesAndExpiresWithoutApproving() {
    let state = TemporaryLauncherDenials()
    state.deny("claude", now: 100)
    for retry in 0..<10_000 {
        #expect(state.isDenied("claude", now: 100 + Double(retry) / 100))
        #expect(!state.isDenied("other", now: 101))
    }
    #expect(state.isDenied("claude", now: 219.999))
    #expect(!state.isDenied("claude", now: 220))
    #expect(!TemporaryLauncherDenials().isDenied("claude", now: 101))
    state.deny("", now: 100)
    #expect(!state.isDenied("", now: 101))
}

@Test func denialPolicyDecodesOldRecordsAndRejectsUnknownThresholds() throws {
    let legacy = Data(#"{"gateID":"gh","requirement":"claude","protection":"readOnly"}"#.utf8)
    let decoded = try JSONDecoder().decode(SecretGatePolicyRecord.self, from: legacy)
    #expect(decoded.denialThreshold == nil)
    var denied = decoded
    denied.denialThreshold = .fullIncludingSecretDumps
    #expect(try JSONDecoder().decode(SecretGatePolicyRecord.self, from: JSONEncoder().encode(denied)) == denied)
    let invalid = Data(#"{"gateID":"gh","requirement":"claude","protection":"readOnly","denialThreshold":"future"}"#.utf8)
    #expect(throws: DecodingError.self) { try JSONDecoder().decode(SecretGatePolicyRecord.self, from: invalid) }
}

@Test(.enabled(if: dataProtectionKeychainAvailable(), "requires an entitled Keychain test host"))
func persistentDenialOverridesFullAccessAndSurvivesAllowEdits() throws {
    let service = "com.automicvault.tests.denial.\(UUID().uuidString)"
    let account = "policy"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let gate = denialGate()
    let requirement = "identifier com.example.launcher"
    #expect(setSecretGateDenialThreshold(.fullIncludingSecretDumps, requirement: requirement,
        in: gate, runtimeRequirement: .hardened, service: service, account: account) == errSecSuccess)
    #expect(setSecretGateAppProtection(requirement: requirement, protection: .fullIncludingSecretDumps,
        for: gate, service: service, account: account) == errSecSuccess)
    func reason(_ classification: SecretGateRequestClassification, _ launcher: String = requirement) -> String? {
        secretGateDenialReason(gate: gate, classification: classification, launcherRequirements: [launcher],
                              service: service, account: account)
    }
    #expect(reason(.secretDump)?.hasPrefix("Denied by Launcher rule:") == true)
    #expect(reason(.readOnly) == nil)
    #expect(reason(.secretDump, "identifier com.example.other") == nil)
    let loaded = reloadSecretGatePolicy(for: gate, service: service, account: account)
    let policy = try #require(loaded.appPolicies.first)
    #expect(policy.denialThreshold == .fullIncludingSecretDumps)
    #expect(setSecretGateDenialThreshold(nil, requirement: requirement, in: gate, runtimeRequirement: .hardened,
        service: service, account: account) == errSecAuthFailed)
    #expect(removeSecretGateAppPolicy(policy, from: gate, service: service, account: account) == errSecAuthFailed)
    #expect(removeSecretGatePolicies(forLauncherRequirement: requirement, service: service, account: account) == errSecSuccess)
    #expect(reason(.secretDump) != nil)
    #expect(setSecretGateDenialThreshold(nil, requirement: requirement, in: gate, runtimeRequirement: .hardened,
        allowWeakening: true, service: service, account: account) == errSecSuccess)
    #expect(reason(.secretDump) == nil)
    #expect(saveKeychainData(Data("malformed".utf8), service: service, account: account) == errSecSuccess)
    #expect(reason(.readOnly) == "Denied because Authorization Policy is unavailable")
}
