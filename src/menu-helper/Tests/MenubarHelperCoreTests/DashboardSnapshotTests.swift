import CryptoKit
import Foundation
import Security
import Testing
@testable import MenubarHelperCore

@Test func securityPathsEscapeDisplayControls() {
    #expect(
        escapedSecurityPath("/tmp/line\nname\t\\\u{202E}txt")
            == #"/tmp/line\nname\t\\\u{202E}txt"#
    )
    #expect(escapedSecurityPath("/tmp/ordinary path") == "/tmp/ordinary path")
}

@Test func markdownRenderingDropsInitialHeadingMarker() {
    #expect(markdownDroppingInitialHeadingMarker("# gh-cli Detector\n\n## Trigger Conditions") == "\n## Trigger Conditions")
    #expect(markdownDroppingInitialHeadingMarker("# gh-cli Detector") == "")
    #expect(markdownDroppingInitialHeadingMarker("## Trigger Conditions") == "## Trigger Conditions")
}

@Test func scanJSONCountsUniqueFlaggedDetectors() throws {
    let data = Data("""
    {"findings":[
      {"source":"git","severity":"high","affected":[]},
      {"source":"git","severity":"high","affected":[]},
      {"source":"aws","severity":"high","affected":[],"detectors":["aws-cli-credentials-file"]}
    ]}
    """.utf8)

    let snapshot = DashboardSnapshot(
        detectors: [],
        detectorFindings: try detectorFindings(from: data),
        hardenedTools: [],
        secretGates: [],
        secrets: []
    )

    #expect(snapshot.flaggedDetectorCount == 2)
    #expect(snapshot.detectorDisplayCount == 2)
    #expect(snapshot.detectorFindings[0].detectors == ["git"])
    #expect(snapshot.detectorFindings[2].detectors == ["aws-cli-credentials-file"])
}

@Test func cleanScanDisplaysTotalDetectorCount() {
    let snapshot = DashboardSnapshot(
        detectors: [
            DetectorMetadata(name: "aws", homepage: "", docsURL: ""),
            DetectorMetadata(name: "git", homepage: "", docsURL: ""),
        ],
        detectorFindings: [],
        hardenedTools: [],
        secretGates: [],
        secrets: []
    )

    #expect(snapshot.flaggedDetectorCount == 0)
    #expect(snapshot.detectorDisplayCount == 2)
}

@Test func detectorMetadataDecodesAllDetectors() throws {
    let data = Data("""
    {"detectors":[{"name":"git","homepage":"https://git-scm.com/","docs_url":"https://example.test/git","documentation":"# git Detector","watch_scopes":[{"path":"/Users/tester/.gitconfig","recursive":false}]}]}
    """.utf8)

    #expect(try detectorMetadata(from: data) == [
        DetectorMetadata(
            name: "git",
            homepage: "https://git-scm.com/",
            docsURL: "https://example.test/git",
            documentation: "# git Detector",
            watchScopes: [DetectorWatchScope(path: "/Users/tester/.gitconfig", recursive: false)]
        )
    ])
}

@Test func detectorMetadataAcceptsOlderDetectorOutput() throws {
    let data = Data("""
    {"detectors":[{"name":"git","homepage":"https://git-scm.com/","docs_url":"https://example.test/git"}]}
    """.utf8)

    #expect(try detectorMetadata(from: data) == [
        DetectorMetadata(name: "git", homepage: "https://git-scm.com/", docsURL: "https://example.test/git")
    ])
}

@Test func splitDetectorNamesDisplayPackageAndKind() {
    #expect(detectorDisplayName("git-credential-fill") == DetectorDisplayName(packageName: "git", kind: "credential fill"))
    #expect(detectorDisplayName("aws-cli-login-cache") == DetectorDisplayName(packageName: "aws-cli", kind: "login cache"))
    #expect(detectorDisplayName("homebrew") == DetectorDisplayName(packageName: "homebrew", kind: "mutable"))
    #expect(detectorDisplayName("sip") == DetectorDisplayName(packageName: "SIP", kind: "system integrity"))
    #expect(detectorDisplayName("sudo") == DetectorDisplayName(packageName: "sudo", kind: "system integrity"))
}

@Test func homebrewExecutablePathsNormalizeToStableOptPath() {
    let symlinks = ["/opt/homebrew/bin/gh": "../Cellar/gh-cli/2.96.0/bin/gh"]
    let expected = "/opt/homebrew/opt/gh-cli/bin/gh"

    #expect(normalizedExecutablePath("/opt/homebrew/bin/gh") { symlinks[$0] } == expected)
    #expect(normalizedExecutablePath("/opt/homebrew/Cellar/gh-cli/2.96.0/bin/gh") { _ in nil } == expected)
    #expect(normalizedExecutablePath("/opt/homebrew/opt/gh-cli/bin/gh") { _ in nil } == expected)
}

@Test func singleDetectorNamesDefaultToPlaintextSecretKind() {
    #expect(detectorDisplayName("docker-machine") == DetectorDisplayName(packageName: "docker-machine", kind: "plaintext secret"))
    #expect(detectorDisplayName("docker-credential-helper") == DetectorDisplayName(packageName: "docker-credential-helper", kind: "plaintext secret"))
    #expect(detectorDisplayName("curl") == DetectorDisplayName(packageName: "curl", kind: "plaintext secret"))
}

@Test func hardenerMetadataDecodesDocumentation() throws {
    let data = Data("""
    {"hardeners":[{"name":"aws","documentation":"## What It Does","hardened":true,"stub_path":"/usr/local/bin/aws","target_path":"/opt/homebrew/bin/aws"}]}
    """.utf8)

    #expect(try hardenerMetadata(from: data) == [
        HardenerMetadata(
            name: "aws",
            documentation: "## What It Does",
            hardened: true,
            stubPath: "/usr/local/bin/aws",
            targetPath: "/opt/homebrew/bin/aws"
        )
    ])
}

@Test func hardenerMetadataDecodesSecretGateDescriptor() throws {
    let data = Data(#"""
    {"hardeners":[{"name":"gh","documentation":"","hardened":true,"stub_path":null,"target_path":"/opt/homebrew/opt/gh-cli/bin/gh","secret_gate":{"id":"gh","key_patterns":["GH_TOKEN_*"],"routes":[{"operation":"keys","script_path":null,"target_path":"/opt/homebrew/opt/gh-cli/bin/gh","caller_identifiers":["gh","com.github.cli"],"key_patterns":["GH_TOKEN_*"],"replace_existing_env":true,"allow_missing_keys":false}]}}]}
    """#.utf8)

    let hardener = try #require(try hardenerMetadata(from: data).first)
    #expect(hardener.secretGate?.id == "gh")
    #expect(hardener.secretGate?.keyPatterns == ["GH_TOKEN_*"])
    #expect(hardener.secretGate?.routes.first?.callerIdentifiers == ["gh", "com.github.cli"])
}

@Test func dashboardHardeningJSONDecodesHardenerAndDoctorFromOneReport() throws {
    let data = Data(#"""
    {
      "hardeners":[{"name":"aws","documentation":"AWS docs","hardened":true,"stub_path":"/usr/local/bin/aws","target_path":"/opt/av/aws/current/aws"}],
      "detectors":[{"name":"aws-cli","homepage":"https://example.com","docs_url":"https://example.com/docs","documentation":"AWS detector","watch_scopes":[]}],
      "secret_gates":[{"id":"aws","key_patterns":["AWS_ACCESS_KEY_ID"],"routes":[{"operation":"inject","script_path":null,"target_path":"/usr/local/bin/aws","caller_identifiers":["com.automicvault.av"],"key_patterns":["AWS_ACCESS_KEY_ID"],"replace_existing_env":false,"allow_missing_keys":false}]}],
      "results":[{"name":"aws","commands":["aws"],"issues":[{"kind":"aws_update_available","command":"aws","message":"Update available","remediation":"Run `av harden aws`.","stub_path":"/usr/local/bin/aws","target_path":"/opt/av/aws/current/aws","resolved_path":null}]}]
    }
    """#.utf8)

    let report = try dashboardHardening(from: data, loginShellPATHAvailable: false)

    #expect(report.hardeners.map(\.name) == ["aws"])
    #expect(report.detectors.map(\.name) == ["aws-cli"])
    #expect(report.secretGates.map(\.id) == ["aws"])
    #expect(report.doctorIssues.map(\.kind) == ["aws_update_available"])
}

@Test func dashboardHardeningLoadsThroughOneExecutableInvocation() throws {
    let directory = temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let executable = directory.appendingPathComponent("av")
    let invocations = directory.appendingPathComponent("invocations")
    try #"""
#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/invocations"
test "$1" = '__dashboard-hardening-json' || exit 2
printf '%s\n' '{"hardeners":[{"name":"aws","documentation":"AWS docs","hardened":true}],"detectors":[],"secret_gates":[{"id":"aws","key_patterns":["AWS_ACCESS_KEY_ID"],"routes":[{"operation":"inject","script_path":null,"target_path":"/usr/local/bin/aws","caller_identifiers":["com.automicvault.av"],"key_patterns":["AWS_ACCESS_KEY_ID"],"replace_existing_env":false,"allow_missing_keys":false}]}],"results":[]}'
"""#.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

    let report = loadDashboardHardening(avExecutableURL: executable)

    #expect(report.hardeners.map(\.name) == ["aws"])
    #expect(report.detectors.isEmpty)
    #expect(report.secretGates.map(\.id) == ["aws"])
    #expect(report.doctorIssues.isEmpty)
    #expect(try String(contentsOf: invocations, encoding: .utf8) == "__dashboard-hardening-json\n")
}

@Test func dashboardHardeningFallsBackForOlderExecutable() throws {
    let directory = temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let executable = directory.appendingPathComponent("av")
    let invocations = directory.appendingPathComponent("invocations")
    try #"""
#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/invocations"
case "$*" in
  'hardeners --json') printf '%s\n' '{"hardeners":[{"name":"aws","documentation":"AWS docs","hardened":true}]}' ;;
  'detectors --json') printf '%s\n' '{"detectors":[]}' ;;
  '__secret-gates-json') printf '%s\n' '{"secret_gates":[{"id":"aws","key_patterns":["AWS_ACCESS_KEY_ID"],"routes":[{"operation":"inject","script_path":null,"target_path":"/usr/local/bin/aws","caller_identifiers":["com.automicvault.av"],"key_patterns":["AWS_ACCESS_KEY_ID"],"replace_existing_env":false,"allow_missing_keys":false}]}]}' ;;
  'doctor --json') printf '%s\n' '{"results":[]}' ;;
  *) exit 2 ;;
esac
"""#.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

    let report = loadDashboardHardening(avExecutableURL: executable)

    #expect(report.hardeners.map(\.name) == ["aws"])
    #expect(report.detectors.isEmpty)
    #expect(report.secretGates.map(\.id) == ["aws"])
    #expect(report.doctorIssues.isEmpty)
    #expect(
        try String(contentsOf: invocations, encoding: .utf8)
            == "__dashboard-hardening-json\nhardeners --json\n__secret-gates-json\ndetectors --json\ndoctor --json\n"
    )
}

@Test func secretGateCatalogRequiresUniqueDefinitions() throws {
    let data = Data(#"{"secret_gates":[{"id":"aws","key_patterns":["AWS_ACCESS_KEY_ID"],"routes":[{"operation":"inject","script_path":null,"target_path":"/usr/local/libexec/av/aws","caller_identifiers":["com.automicvault.av"],"key_patterns":["AWS_ACCESS_KEY_ID"],"replace_existing_env":false,"allow_missing_keys":false}]}]}"#.utf8)

    #expect(try secretGateDescriptors(from: data).map(\.id) == ["aws"])
    let duplicate = Data(#"{"secret_gates":[{"id":"aws","key_patterns":[],"routes":[]},{"id":"aws","key_patterns":[],"routes":[]}]}"#.utf8)
    #expect(throws: DecodingError.self) {
        try secretGateDescriptors(from: duplicate)
    }
    #expect(throws: DecodingError.self) {
        try loadSecretGateDescriptors(
            avExecutableURL: URL(fileURLWithPath: "/tmp/nonexistent-av-\(UUID().uuidString)")
        )
    }
}

@Test func secretGateCatalogLoadsThroughTheExecutableBoundary() throws {
    let directory = temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let executable = directory.appendingPathComponent("av")
    try #"""
#!/bin/sh
printf '%s\n' '{"secret_gates":[{"id":"docker","key_patterns":["DOCKER_REGISTRY_CREDENTIAL_*"],"routes":[{"operation":"docker-get","script_path":null,"target_path":"/Applications/Docker.app/Contents/Resources/bin/docker","caller_identifiers":["com.automicvault.av"],"key_patterns":["DOCKER_REGISTRY_CREDENTIAL_*"],"replace_existing_env":false,"allow_missing_keys":false}]}]}'
"""#.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

    let gates = try loadSecretGateDescriptors(avExecutableURL: executable)

    #expect(gates.map(\.id) == ["docker"])
    #expect(gates.first?.routes.first?.operation == "docker-get")
}

@Test func doctorJSONFlattensIssuesWithHardenerNames() throws {
    let data = Data(#"""
    {"results":[
      {"name":"aws","commands":["aws"],"issues":[{"kind":"stub_not_first_on_path","command":"aws","message":"aws is shadowed","remediation":"Fix PATH.","stub_path":"/usr/local/bin/aws","target_path":"/opt/homebrew/bin/aws","resolved_path":"/opt/homebrew/bin/aws"}]},
      {"name":"gh","commands":["gh"],"issues":[]}
    ]}
    """#.utf8)

    #expect(try doctorIssues(from: data) == [
        DoctorIssue(
            hardener: "aws",
            kind: "stub_not_first_on_path",
            command: "aws",
            message: "aws is shadowed",
            remediation: "Fix PATH.",
            stubPath: "/usr/local/bin/aws",
            targetPath: "/opt/homebrew/bin/aws",
            resolvedPath: "/opt/homebrew/bin/aws"
        )
    ])
}

@Test func doctorIssueIDsDistinguishMissingUserAndGroup() throws {
    let data = Data(#"""
    {"results":[{"name":"brew","commands":["brew"],"issues":[
      {"kind":"required_identity_missing","command":"brew","message":"brew hardening requires local user `automic`, but it cannot be resolved","remediation":"Create the user.","stub_path":"/usr/local/bin/brew","target_path":"/opt/homebrew/bin/brew","resolved_path":null},
      {"kind":"required_identity_missing","command":"brew","message":"brew hardening requires local group `vault`, but it cannot be resolved","remediation":"Create the group.","stub_path":"/usr/local/bin/brew","target_path":"/opt/homebrew/bin/brew","resolved_path":null}
    ]}]}
    """#.utf8)

    let issues = try doctorIssues(from: data)

    #expect(issues.count == 2)
    #expect(Set(issues.map(\.id)).count == 2)
}

@Test func unavailableLoginShellPATHSuppressesAllUnverifiablePATHIssues() throws {
    let data = Data(#"""
    {"results":[
      {"name":"aws","commands":["aws"],"issues":[
        {"kind":"stub_not_first_on_path","command":"aws","message":"shadowed","remediation":"Fix PATH.","stub_path":"/usr/local/bin/aws","target_path":"/opt/homebrew/bin/aws","resolved_path":"/opt/homebrew/bin/aws"},
        {"kind":"hardening_not_applied","command":"aws","message":"not hardened","remediation":"Harden it.","stub_path":"/usr/local/bin/aws","target_path":"/opt/homebrew/bin/aws","resolved_path":null}
      ]},
      {"name":"gh","commands":["gh"],"issues":[
        {"kind":"isotope_not_first_on_path","command":"gh","message":"gh is not available through PATH","remediation":"Fix PATH.","stub_path":"/opt/homebrew/opt/gh-cli/bin/gh","target_path":"/opt/homebrew/opt/gh-cli/bin/gh","resolved_path":null}
      ]},
      {"name":"herdr Launcher Bundle","commands":["herdr"],"issues":[
        {"kind":"launcher_bundle_not_first_on_path","command":"herdr","message":"herdr is shadowed","remediation":"Fix PATH.","stub_path":"/usr/local/bin/herdr","target_path":"/Applications/Automic Vault/Herdr.app/Contents/MacOS/launcher","resolved_path":"/opt/homebrew/bin/herdr"}
      ]},
      {"name":"codex","commands":["codex"],"issues":[
        {"kind":"agent_cli_unavailable","command":"codex","message":"codex is not available through PATH","remediation":"Fix PATH.","stub_path":"/usr/local/bin/codex","target_path":null,"resolved_path":null},
        {"kind":"agent_cli_signature_invalid","command":"codex","message":"codex has an invalid signature","remediation":"Fix PATH.","stub_path":"/usr/local/bin/codex","target_path":null,"resolved_path":"/usr/bin/codex"}
      ]},
      {"name":"terraform","commands":["terraform"],"issues":[
        {"kind":"terraform_command_shadowed","command":null,"message":"terraform is not available through PATH","remediation":"Fix PATH.","stub_path":null,"target_path":"/usr/local/bin/terraform","resolved_path":null}
      ]}
    ]}
    """#.utf8)

    let issues = try doctorIssues(from: data, loginShellPATHAvailable: false)

    #expect(issues.map(\.kind) == ["hardening_not_applied"])
}

@Test func JSONLoaderCanAcceptDoctorIssueExitStatus() throws {
    let data = try #require(loadJSON(
        avExecutableURL: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "printf '{\"results\":[]}'; exit 1"],
        acceptedTerminationStatuses: [0, 1]
    ))

    #expect(try doctorIssues(from: data).isEmpty)
}

@Test func doctorLoadFailureIsReportedDirectly() {
    let issues = loadDoctorIssues(
        avExecutableURL: URL(fileURLWithPath: "/no/such/automic-vault-av")
    )

    #expect(issues.map(\.kind) == ["doctor_unavailable"])
    #expect(issues.first?.message == "Doctor results are unavailable")
}

@Test func detectorDocumentationReferencesHardenerCommand() {
    #expect(hardenerNameReferencedByDocumentation("```sh\nav harden gh\n```") == "gh")
    #expect(hardenerNameReferencedByDocumentation("Run `sudo av harden aws` after import.") == "aws")
    #expect(hardenerNameReferencedByDocumentation("No mitigation command here.") == nil)
}

@Test func hardenedToolsUseHardenerDetection() throws {
    let directory = temporaryDirectory()
    let tools = loadHardenedTools(
        in: directory,
        ghCLIURL: nil,
        metadata: [
            HardenerMetadata(
                name: "aws",
                documentation: "AWS docs",
                hardened: true,
                stubPath: "/usr/local/bin/aws",
                targetPath: "/opt/homebrew/bin/aws"
            ),
            HardenerMetadata(
                name: "sudo",
                documentation: "Sudo docs",
                hardened: true,
                targetPath: "/etc/pam.d/sudo_local"
            ),
            HardenerMetadata(name: "gh-cli", documentation: "GitHub docs", hardened: false),
        ]
    )

    #expect(tools.map(\.name) == ["aws", "sudo"])
    #expect(tools.map(\.documentation) == ["AWS docs", "Sudo docs"])
    #expect(tools.first?.stubPath == "/usr/local/bin/aws")
    #expect(tools.last?.stubPath == nil)
}

@Test func runtimeGateCatalogDoesNotDependOnHardenerDetection() throws {
    let metadata = testGateMetadata(hardened: false)
    let descriptor = try #require(metadata.secretGate)
    let service = "com.automicvault.tests.\(UUID().uuidString)"

    #expect(loadSecretGates(hardeners: [metadata], service: service).isEmpty)
    #expect(loadSecretGates(descriptors: [descriptor], service: service).map(\.id) == ["gh"])
}

@Test func dashboardRequiresConfiguredCredentialForStandaloneGPGAuthorizationGate() throws {
    let inactiveHardener = testGateMetadata(hardened: false)
    let gpg = SecretGateDescriptor(
        id: "gpg-signing",
        keyPatterns: ["AV_GPG_PRIVATE_KEY"],
        routes: [SecretGateRoute(
            operation: "gpg-sign",
            scriptPath: nil,
            targetPath: "/Applications/Automic Vault.app/Contents/MacOS/av",
            callerIdentifiers: ["com.automicvault.av"],
            keyPatterns: ["AV_GPG_PRIVATE_KEY"],
            replaceExistingEnv: false,
            allowMissingKeys: false
        )]
    )
    #expect(dashboardSecretGateDescriptors(
        hardeners: [inactiveHardener],
        catalog: [try #require(inactiveHardener.secretGate), gpg]
    ).isEmpty)
    #expect(dashboardSecretGateDescriptors(
        hardeners: [inactiveHardener],
        catalog: [try #require(inactiveHardener.secretGate), gpg],
        storedSecretNames: [gpgAlternatePrivateKeySecretName]
    ).map(\.id) == ["gpg-signing"])
    let descriptors = dashboardSecretGateDescriptors(
        hardeners: [inactiveHardener],
        catalog: [try #require(inactiveHardener.secretGate), gpg],
        storedSecretNames: [gpgDefaultPrivateKeySecretName]
    )
    let gate = try #require(loadSecretGates(
        descriptors: descriptors,
        service: "com.automicvault.tests.\(UUID().uuidString)"
    ).first)

    #expect(descriptors.map(\.id) == ["gpg-signing"])
    #expect(gate.availableProtections == [.noAccess, .readOnlyAndLocalWrites])
    #expect(gate.initialProtection == .noAccess)
    #expect(gate.normalizedProtection(.noAccess) == .noAccess)
    #expect(gate.normalizedProtection(.readOnly) == .noAccess)
    #expect(gate.normalizedProtection(.readOnlyAndUpdates) == .noAccess)
    #expect(gate.normalizedProtection(.readOnlyAndLocalWrites) == .readOnlyAndLocalWrites)
    #expect(gate.normalizedProtection(.fullExceptSecretDumps) == .readOnlyAndLocalWrites)
    #expect(gate.normalizedProtection(.fullIncludingSecretDumps) == .readOnlyAndLocalWrites)
    #expect(gate.protectionTitle(.noAccess) == "Approval Required")
    #expect(gate.protectionTitle(.readOnlyAndLocalWrites) == "Allow Signing")
    #expect(gate.protectionSubtitle(.noAccess) == "Every GPG signing request requires approval")
    #expect(
        gate.protectionSubtitle(.readOnlyAndLocalWrites)
            == "Recognized GPG signing requests are automically authorized"
    )
}


private func testGateMetadata(hardened: Bool = true) -> HardenerMetadata {
    HardenerMetadata(
        name: "gh",
        hardened: hardened,
        stubPath: "/opt/homebrew/opt/gh-cli/bin/gh",
        targetPath: "/opt/homebrew/opt/gh-cli/bin/gh",
        secretGate: SecretGateDescriptor(
            id: "gh",
            keyPatterns: ["GH_TOKEN_*"],
            routes: [SecretGateRoute(
                operation: "keys",
                scriptPath: nil,
                targetPath: "/opt/homebrew/opt/gh-cli/bin/gh",
                callerIdentifiers: ["gh", "com.github.cli"],
                keyPatterns: ["GH_TOKEN_*"],
                replaceExistingEnv: true,
                allowMissingKeys: false
            )]
        )
    )
}

private func secretlessGateMetadata() -> HardenerMetadata {
    HardenerMetadata(
        name: "brew",
        hardened: true,
        stubPath: "/usr/local/bin/brew",
        targetPath: "/opt/homebrew/bin/brew",
        secretGate: SecretGateDescriptor(
            id: "brew",
            keyPatterns: [],
            routes: [SecretGateRoute(
                operation: "authorize",
                scriptPath: nil,
                targetPath: "/opt/homebrew/bin/brew",
                callerIdentifiers: ["com.automicvault.av-brew-stub"],
                keyPatterns: [],
                replaceExistingEnv: false,
                allowMissingKeys: false
            )]
        )
    )
}

@Test func hardenedToolGetsOneGateWithoutStoredSecrets() {
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let gates = loadSecretGates(hardeners: [testGateMetadata(), testGateMetadata(hardened: false)], service: service)

    #expect(gates.count == 1)
    #expect(gates.first?.id == "gh")
    #expect(gates.first?.keyPatterns == ["GH_TOKEN_*"])
    #expect(gates.first?.defaultProtection == .readOnly)
    #expect(gates.first?.appPolicies.isEmpty == true)
}

@Test func missingPoliciesUseInitialDefaults() throws {
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let gate = try #require(loadSecretGates(hardeners: [secretlessGateMetadata()], service: service).first)

    #expect(gate.keyPatterns.isEmpty)
    #expect(gate.defaultProtection == .readOnlyAndUpdates)
    #expect(gate.availableProtections == [.noAccess, .readOnlyAndUpdates, .fullExceptSecretDumps])
    #expect(gate.normalizedProtection(.readOnly) == .readOnlyAndUpdates)
    #expect(gate.normalizedProtection(.readOnly).allows(.update))
    #expect(!gate.normalizedProtection(.readOnly).allows(.mutating))
    #expect(gate.protectionTitle(.readOnly) == "Read & Update")
    #expect(gate.protectionTitle(.readOnlyAndUpdates) == "Read & Update")
    #expect(gate.protectionSubtitle(.readOnlyAndUpdates) == "Recognized read-only operations and `brew update` are automically authorized; installs and upgrades require approval")
    #expect(gate.protectionTitle(.fullExceptSecretDumps) == "Full Access")
    #expect(gate.protectionSubtitle(.fullExceptSecretDumps) == "Every recognized operation is automically authorized; unknown operations require approval")

    let secretGate = try #require(loadSecretGates(hardeners: [testGateMetadata()], service: service).first)
    #expect(secretGate.defaultProtection == .readOnly)
    #expect(secretGate.availableProtections == [
        .noAccess,
        .readOnly,
        .readOnlyAndLocalWrites,
        .fullExceptSecretDumps,
        .fullIncludingSecretDumps,
    ])
    #expect(secretGate.protectionTitle(.readOnlyAndLocalWrites) == "Local Write")
    #expect(secretGate.protectionTitle(.fullExceptSecretDumps) == "Write Access")
}

@Test func brewGateBroadensPersistedReadOnlyPoliciesToReadAndUpdate() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let legacy = #"[{"gateID":"brew","requirement":null,"protection":"readOnly"},{"gateID":"brew","requirement":"identifier \"com.example.app\"","protection":"readOnly"}]"#
    #expect(saveStoredSecret(account: account, value: legacy, service: service) == errSecSuccess)

    let gate = try #require(loadSecretGates(
        hardeners: [secretlessGateMetadata()],
        service: service,
        account: account
    ).first)
    #expect(gate.defaultProtection == .readOnlyAndUpdates)
    #expect(gate.appPolicies.first?.protection == .readOnlyAndUpdates)
}

@Test func newGateGetsExplicitInitialPolicy() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let metadata = testGateMetadata()

    #expect(initializeSecretGatePolicies(hardeners: [metadata], service: service, account: account) == errSecSuccess)
    #expect(loadSecretGates(hardeners: [metadata], service: service, account: account).first?.defaultProtection == .readOnly)
    #expect(keychainAccessibility(account: account, service: service) == kSecAttrAccessibleAfterFirstUnlock as String)
}

@Test func newBrewGateGetsReadOnlyAndUpdatesPolicy() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let metadata = secretlessGateMetadata()

    #expect(initializeSecretGatePolicies(hardeners: [metadata], service: service, account: account) == errSecSuccess)
    #expect(loadSecretGates(hardeners: [metadata], service: service, account: account).first?.defaultProtection == .readOnlyAndUpdates)
}

@Test func malformedPoliciesFailClosedAndAreNotReplaced() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let metadata = testGateMetadata()
    #expect(saveStoredSecret(account: account, value: "not json", service: service) == errSecSuccess)

    #expect(loadSecretGates(hardeners: [metadata], service: service, account: account).first?.defaultProtection == .noAccess)
    #expect(initializeSecretGatePolicies(hardeners: [metadata], service: service, account: account) != errSecSuccess)
    #expect(loadStoredSecret(account: account, service: service) == "not json")
}

@Test func secretNameAccessAppsArePersistedSortedAndRevocable() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "name-access.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let zeta = BlessedScriptLauncher(bundleIdentifier: "com.example.zeta", requirement: "zeta")
    let alpha = BlessedScriptLauncher(bundleIdentifier: "com.example.alpha", requirement: "alpha")

    #expect(allowSecretNameAccess(zeta, service: service, account: account) == errSecSuccess)
    #expect(allowSecretNameAccess(alpha, service: service, account: account) == errSecSuccess)
    #expect(loadSecretNameAccessApps(service: service, account: account) == [alpha, zeta])
    #expect(keychainAccessibility(account: account, service: service) == kSecAttrAccessibleAfterFirstUnlock as String)
    #expect(removeSecretNameAccess(alpha, service: service, account: account) == errSecSuccess)
    #expect(loadSecretNameAccessApps(service: service, account: account) == [zeta])
}

@Test func malformedSecretNameAccessPolicyFailsClosedAndIsNotReplaced() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "name-access.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    #expect(saveStoredSecret(account: account, value: "not json", service: service) == errSecSuccess)

    let app = BlessedScriptLauncher(bundleIdentifier: "com.example.app", requirement: "requirement")
    #expect(loadSecretNameAccessApps(service: service, account: account).isEmpty)
    #expect(allowSecretNameAccess(app, service: service, account: account) == errSecDecode)
    #expect(loadStoredSecret(account: account, service: service) == "not json")
}

@Test func directAccessRequiresEveryExactSecretAndHardenedRuntime() {
    let launcher = BlessedScriptLauncher(
        bundleIdentifier: "com.example.launcher",
        requirement: "designated requirement"
    )
    let rules = [
        DirectAccessRule(secretName: "ALPHA_TOKEN", launcher: launcher),
        DirectAccessRule(secretName: "BETA_TOKEN", launcher: launcher),
    ]

    #expect(directAccessAllows(
        secretNames: ["ALPHA_TOKEN", "BETA_TOKEN"],
        launcherRequirement: launcher.requirement,
        runtimeProtection: .hardened,
        rules: rules
    ))
    #expect(!directAccessAllows(
        secretNames: ["ALPHA_TOKEN", "OTHER_TOKEN"],
        launcherRequirement: launcher.requirement,
        runtimeProtection: .hardened,
        rules: rules
    ))
    #expect(!directAccessAllows(
        secretNames: ["ALPHA_TOKEN"],
        launcherRequirement: "another requirement",
        runtimeProtection: .hardened,
        rules: rules
    ))
    #expect(!directAccessAllows(
        secretNames: ["ALPHA_TOKEN"],
        launcherRequirement: launcher.requirement,
        runtimeProtection: .hardenedWithLibraryValidationDisabled,
        rules: rules
    ))
    let libraryLoadingRules = rules.map {
        DirectAccessRule(
            secretName: $0.secretName,
            launcher: $0.launcher,
            runtimeRequirement: .hardenedAllowingLibraryValidationDisabled
        )
    }
    #expect(directAccessAllows(
        secretNames: ["ALPHA_TOKEN", "BETA_TOKEN"],
        launcherRequirement: launcher.requirement,
        runtimeProtection: .hardenedWithLibraryValidationDisabled,
        rules: libraryLoadingRules
    ))
    #expect(!directAccessAllows(
        secretNames: ["ALPHA_TOKEN"],
        launcherRequirement: launcher.requirement,
        runtimeProtection: .hardenedRuntimeMissing,
        rules: libraryLoadingRules
    ))
    #expect(!directAccessAllows(
        secretNames: [],
        launcherRequirement: launcher.requirement,
        runtimeProtection: .hardened,
        rules: rules
    ))
}

@Test func directAccessRulesArePersistedWithSecretsAndRevocable() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let secretService = "com.automicvault.tests.secret.\(UUID().uuidString)"
    let policyService = "com.automicvault.tests.direct.\(UUID().uuidString)"
    let policyAccount = "rules"
    let zeta = BlessedScriptLauncher(bundleIdentifier: "com.example.zeta", requirement: "zeta")
    let alpha = BlessedScriptLauncher(bundleIdentifier: "com.example.alpha", requirement: "alpha")
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: secretService) }
    defer { _ = deleteStoredSecret(account: policyAccount, service: policyService) }

    #expect(saveStoredSecret(account: "API_TOKEN", value: "secret", service: secretService) == errSecSuccess)
    #expect(allowDirectAccess(
        to: "API_TOKEN",
        for: zeta,
        runtimeRequirement: .hardenedAllowingLibraryValidationDisabled,
        service: policyService,
        account: policyAccount
    ) == errSecSuccess)
    #expect(allowDirectAccess(
        to: "API_TOKEN", for: alpha, service: policyService, account: policyAccount
    ) == errSecSuccess)
    let rules = loadDirectAccessRules(service: policyService, account: policyAccount)
    #expect(rules.map(\.launcher) == [alpha, zeta])
    #expect(rules.last?.runtimeRequirement == .hardenedAllowingLibraryValidationDisabled)
    #expect(loadStoredSecrets(
        service: secretService,
        directAccessRules: loadDirectAccessRules(service: policyService, account: policyAccount)
    ).first?.directAccessLaunchers == [alpha, zeta])
    #expect(keychainAccessibility(account: policyAccount, service: policyService) == kSecAttrAccessibleAfterFirstUnlock as String)

    #expect(removeDirectAccess(
        to: "API_TOKEN", for: alpha, service: policyService, account: policyAccount
    ) == errSecSuccess)
    #expect(loadDirectAccessRules(service: policyService, account: policyAccount).map(\.launcher) == [zeta])
    #expect(revokeDirectAccess(
        to: "API_TOKEN", service: policyService, account: policyAccount
    ) == errSecSuccess)
    #expect(loadDirectAccessRules(service: policyService, account: policyAccount).isEmpty)
}

@Test func legacyDirectAccessRulesRemainStrictlyHardened() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.direct.\(UUID().uuidString)"
    let account = "rules"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let legacy = #"[{"secretName":"API_TOKEN","launcher":{"bundleIdentifier":"com.example.app","requirement":"requirement"}}]"#
    #expect(saveStoredSecret(account: account, value: legacy, service: service) == errSecSuccess)

    let rule = try #require(loadDirectAccessRules(service: service, account: account).first)
    #expect(rule.runtimeRequirement == .hardened)
    #expect(!directAccessAllows(
        secretNames: ["API_TOKEN"],
        launcherRequirement: "requirement",
        runtimeProtection: .hardenedWithLibraryValidationDisabled,
        rules: [rule]
    ))
}

@Test func malformedDirectAccessPolicyFailsClosedAndIsNotReplaced() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.direct.\(UUID().uuidString)"
    let secretService = "com.automicvault.tests.secret.\(UUID().uuidString)"
    let account = "rules"
    let launcher = BlessedScriptLauncher(bundleIdentifier: "com.example.app", requirement: "requirement")
    defer { _ = deleteStoredSecret(account: account, service: service) }
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: secretService) }
    #expect(saveStoredSecret(account: account, value: "not json", service: service) == errSecSuccess)
    #expect(saveStoredSecret(account: "API_TOKEN", value: "secret", service: secretService) == errSecSuccess)

    #expect(loadDirectAccessRules(service: service, account: account).isEmpty)
    #expect(allowDirectAccess(
        to: "API_TOKEN", for: launcher, service: service, account: account
    ) == errSecDecode)
    #expect(deleteStoredSecretRevokingDirectAccess(
        account: "API_TOKEN",
        service: secretService,
        directAccessService: service,
        directAccessAccount: account
    ) == errSecDecode)
    #expect(storedSecretExists(account: "API_TOKEN", service: secretService))
    #expect(loadStoredSecret(account: account, service: service) == "not json")
}

@Test func deletingOrRenamingASecretRevokesDirectAccessFirst() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let secretService = "com.automicvault.tests.secret.\(UUID().uuidString)"
    let policyService = "com.automicvault.tests.direct.\(UUID().uuidString)"
    let policyAccount = "rules"
    let launcher = BlessedScriptLauncher(bundleIdentifier: "com.example.app", requirement: "requirement")
    defer { _ = deleteStoredSecret(account: "OLD_TOKEN", service: secretService) }
    defer { _ = deleteStoredSecret(account: "NEW_TOKEN", service: secretService) }
    defer { _ = deleteStoredSecret(account: policyAccount, service: policyService) }

    #expect(saveStoredSecret(account: "OLD_TOKEN", value: "secret", service: secretService) == errSecSuccess)
    #expect(allowDirectAccess(
        to: "OLD_TOKEN", for: launcher, service: policyService, account: policyAccount
    ) == errSecSuccess)
    #expect(renameStoredSecretRevokingDirectAccess(
        account: "OLD_TOKEN",
        to: "NEW_TOKEN",
        service: secretService,
        directAccessService: policyService,
        directAccessAccount: policyAccount
    ) == errSecSuccess)
    #expect(loadDirectAccessRules(service: policyService, account: policyAccount).isEmpty)

    #expect(allowDirectAccess(
        to: "NEW_TOKEN", for: launcher, service: policyService, account: policyAccount
    ) == errSecSuccess)
    #expect(deleteStoredSecretRevokingDirectAccess(
        account: "NEW_TOKEN",
        service: secretService,
        directAccessService: policyService,
        directAccessAccount: policyAccount
    ) == errSecSuccess)
    #expect(loadDirectAccessRules(service: policyService, account: policyAccount).isEmpty)
}

@Test func secretlessGateNormalizesLegacyFullPolicy() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let legacy = #"[{"gateID":"brew","requirement":null,"protection":"fullIncludingSecretDumps"},{"gateID":"brew","requirement":"identifier \"com.example.app\"","protection":"fullIncludingSecretDumps"}]"#
    #expect(saveStoredSecret(account: account, value: legacy, service: service) == errSecSuccess)

    var gate = try #require(loadSecretGates(
        hardeners: [secretlessGateMetadata()],
        service: service,
        account: account
    ).first)
    #expect(gate.defaultProtection == .fullExceptSecretDumps)
    #expect(gate.appPolicies.first?.protection == .fullExceptSecretDumps)
    #expect(gate.appPolicies.first?.requiresHardenedRuntime == false)
    #expect(gate.appPolicies.first?.runtimeRequirement == .legacyUnchecked)

    #expect(setSecretGateDefaultProtection(
        .readOnly,
        for: gate,
        service: service,
        account: account
    ) == errSecSuccess)
    gate = try #require(loadSecretGates(
        hardeners: [secretlessGateMetadata()],
        service: service,
        account: account
    ).first)
    #expect(gate.defaultProtection == .readOnlyAndUpdates)
}

@Test func existingHardenedRuntimePoliciesRemainStrict() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let legacy = #"[{"gateID":"test","requirement":"identifier \"com.example.app\"","protection":"readOnly","requiresHardenedRuntime":true}]"#
    #expect(saveStoredSecret(account: account, value: legacy, service: service) == errSecSuccess)

    let gate = try #require(loadSecretGates(
        hardeners: [testGateMetadata()],
        service: service,
        account: account
    ).first)
    #expect(gate.appPolicies.first?.runtimeRequirement == .hardened)
}

@Test func unhealthyInstalledWrapperKeepsItsSecretGate() throws {
    let directory = temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let stub = directory.appendingPathComponent("aws")
    try "#!/usr/local/bin/av inject +AWS_ACCESS_KEY_ID /bin/zsh".write(
        to: stub,
        atomically: true,
        encoding: .utf8
    )
    let route = SecretGateRoute(
        operation: "inject",
        scriptPath: stub.path,
        targetPath: "/bin/zsh",
        callerIdentifiers: ["com.automicvault.av"],
        keyPatterns: ["AWS_ACCESS_KEY_ID"],
        replaceExistingEnv: false,
        allowMissingKeys: false
    )
    let metadata = HardenerMetadata(
        name: "aws",
        hardened: false,
        secretGate: SecretGateDescriptor(id: "aws", keyPatterns: ["AWS_ACCESS_KEY_ID"], routes: [route])
    )

    #expect(loadSecretGates(hardeners: [metadata]).map(\.id) == ["aws"])
}

@Test(
    arguments: SecretGateProtection.allCases,
    SecretGateRequestClassification.allCases
)
func protectionPolicyMatrix(
    protection: SecretGateProtection,
    classification: SecretGateRequestClassification
) {
    let expected = switch protection {
    case .noAccess: false
    case .readOnly: classification == .readOnly
    case .readOnlyAndLocalWrites: classification == .readOnly || classification == .localWrite
    case .readOnlyAndUpdates: classification == .readOnly || classification == .update
    case .fullExceptSecretDumps: classification != .secretDump && classification != .unknown
    case .fullIncludingSecretDumps: classification != .unknown
    }
    #expect(protection.allows(classification) == expected)
}

@Test func nodeGateUsesNpmDisplayNameWithoutChangingItsID() {
    let gate = SecretGate(
        id: "node",
        keyPatterns: ["NODE_AUTH_TOKEN"],
        routes: [],
        defaultProtection: .readOnly,
        appPolicies: []
    )

    #expect(gate.id == "node")
    #expect(gate.displayName == "npm")
    #expect(gate.authorizationGateName == "npm Authorization Gate")
}

@Test func secretGatePoliciesPersistAndResolveOverrides() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let metadata = testGateMetadata()
    var gate = try #require(loadSecretGates(hardeners: [metadata], service: service, account: account).first)
    let requirement = #"identifier "com.example.app""#
    #expect(gate.defaultPolicyLabel == "All Apps")
    #expect(secretGateProtection(for: nil, in: gate).source == "All Apps")

    #expect(setSecretGateDefaultProtection(.fullExceptSecretDumps, for: gate, service: service, account: account) == errSecSuccess)
    gate = try #require(loadSecretGates(hardeners: [metadata], service: service, account: account).first)
    #expect(secretGateProtection(for: nil, in: gate).protection == .fullExceptSecretDumps)

    #expect(setSecretGateAppProtection(
        requirement: requirement,
        protection: .noAccess,
        for: gate,
        runtimeRequirement: .hardenedAllowingLibraryValidationDisabled,
        service: service,
        account: account
    ) == errSecSuccess)
    gate = try #require(loadSecretGates(hardeners: [metadata], service: service, account: account).first)
    let appPolicy = try #require(gate.appPolicies.first)
    #expect(appPolicy.protection == .noAccess)
    #expect(appPolicy.requiresHardenedRuntime)
    #expect(appPolicy.runtimeRequirement == .hardenedAllowingLibraryValidationDisabled)
    #expect(gate.defaultPolicyLabel == "All Other Apps")
    #expect(secretGateProtection(for: requirement, in: gate).protection == .noAccess)
    #expect(secretGateProtection(for: #"identifier "com.other.app""#, in: gate).protection == .fullExceptSecretDumps)

    #expect(setSecretGateAppProtection(
        requirement: appPolicy.requirement,
        protection: .readOnly,
        for: gate,
        runtimeRequirement: appPolicy.runtimeRequirement,
        service: service,
        account: account
    ) == errSecSuccess)
    gate = try #require(loadSecretGates(hardeners: [metadata], service: service, account: account).first)
    #expect(gate.appPolicies.first?.runtimeRequirement == .hardenedAllowingLibraryValidationDisabled)

    #expect(removeSecretGateAppPolicy(appPolicy, from: gate, service: service, account: account) == errSecSuccess)
    gate = try #require(loadSecretGates(hardeners: [metadata], service: service, account: account).first)
    #expect(gate.appPolicies.isEmpty)
    #expect(gate.defaultPolicyLabel == "All Apps")
    #expect(secretGateProtection(for: requirement, in: gate).protection == .fullExceptSecretDumps)
}

@Test func appIdentifierAcceptsCodesignBareIdentifiers() {
    #expect(appIdentifier(from: #"identifier "com.example.app" and anchor apple generic"#) == "com.example.app")
    let codex = #"identifier codex and anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2""#
    #expect(appIdentifier(from: codex) == "codex")
    #expect(codeSigningTeamIdentifier(from: codex) == "2DC432GLL2")
}

@Test func noAccessDefaultIsPersisted() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    let account = "policies.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let metadata = testGateMetadata()
    let gate = try #require(loadSecretGates(hardeners: [metadata], service: service, account: account).first)

    #expect(setSecretGateDefaultProtection(.noAccess, for: gate, service: service, account: account) == errSecSuccess)
    #expect(initializeSecretGatePolicies(hardeners: [metadata], service: service, account: account) == errSecSuccess)
    #expect(loadSecretGates(hardeners: [metadata], service: service, account: account).first?.defaultProtection == .noAccess)
}

@Test func storedSecretsListNamesOnlyAndDelete() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    #expect(saveStoredSecret(account: "API_TOKEN", value: "secret", service: service) == errSecSuccess)
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: service) }

    let secrets = loadStoredSecrets(service: service)
    #expect(secrets.map(\.account) == ["API_TOKEN"])
    #expect(secrets.first?.accessibility == .whenUnlocked)
    #expect(secrets.first?.accessibility.isAvailableWhileLocked == false)
    #expect(secrets.first?.keychainProperties.contains("Data Protection Enabled") == true)
    #expect(secrets.first?.keychainProperties.contains("iCloud Off") == true)
    #expect(deleteStoredSecret(account: "API_TOKEN", service: service) == errSecSuccess)
    #expect(loadStoredSecrets(service: service).isEmpty)
}

@Test func storedSecretExistenceDoesNotRequireLoadingItsValue() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    #expect(!storedSecretExists(account: "API_TOKEN", service: service))
    #expect(saveStoredSecret(account: "API_TOKEN", value: "secret", service: service) == errSecSuccess)
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: service) }

    #expect(storedSecretExists(account: "API_TOKEN", service: service))
}

@Test func storedSecretsUseDataProtectionKeychain() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    #expect(saveStoredSecret(account: "API_TOKEN", value: "secret", service: service) == errSecSuccess)
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: service) }

    #expect(keychainAccessibility(account: "API_TOKEN", service: service) == kSecAttrAccessibleWhenUnlocked as String)
}

@Test func touchIDApprovalOptInPersistsAndInvalidDataFailsClosed() {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.touch-id.\(UUID().uuidString)"
    let account = "TouchIDApproval"
    defer { _ = setTouchIDApprovalEnabled(false, service: service, account: account) }

    #expect(!touchIDApprovalIsEnabled(service: service, account: account))
    #expect(setTouchIDApprovalEnabled(true, service: service, account: account) == errSecSuccess)
    #expect(touchIDApprovalIsEnabled(service: service, account: account))
    #expect(saveKeychainData(Data([0]), service: service, account: account) == errSecSuccess)
    #expect(!touchIDApprovalIsEnabled(service: service, account: account))
    #expect(setTouchIDApprovalEnabled(false, service: service, account: account) == errSecSuccess)
    #expect(!touchIDApprovalIsEnabled(service: service, account: account))
}

@Test func conditionalSecretSaveNeverReplacesDifferingValue() {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.conditional-save.\(UUID().uuidString)"
    let account = "TOKEN"
    defer { _ = deleteStoredSecret(account: account, service: service) }

    #expect(saveStoredSecretIfAbsentOrEqual(account: account, value: "first", service: service) == errSecSuccess)
    #expect(keychainAccessibility(account: account, service: service) == kSecAttrAccessibleWhenUnlocked as String)
    #expect(saveStoredSecretIfAbsentOrEqual(account: account, value: "first", service: service) == errSecSuccess)
    #expect(saveStoredSecretIfAbsentOrEqual(account: account, value: "second", service: service) == errSecDuplicateItem)
    #expect(loadStoredSecret(account: account, service: service) == "first")
}

@Test func conditionalSecretSaveVerifiesNewValueBeforeSuccess() {
    let expected = Data("secret".utf8)
    var performedReadback = false

    let status = verifyKeychainDataAfterConditionalAdd(status: errSecSuccess, expected: expected) {
        performedReadback = true
        return .success(expected)
    }

    #expect(performedReadback)
    #expect(status == errSecSuccess)
}

@Test func conditionalSecretSavePropagatesNewValueReadbackFailure() {
    let expected = Data("secret".utf8)

    let status = verifyKeychainDataAfterConditionalAdd(status: errSecSuccess, expected: expected) {
        .failure(errSecInteractionNotAllowed)
    }

    #expect(status == errSecInteractionNotAllowed)
}

@Test func conditionalSecretSavePreservesExistingAccessibility() {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.conditional-save.\(UUID().uuidString)"
    let account = "TOKEN"
    defer { _ = deleteStoredSecret(account: account, service: service) }

    #expect(saveStoredSecret(
        account: account,
        value: "first",
        accessibility: .afterFirstUnlock,
        service: service
    ) == errSecSuccess)
    #expect(saveStoredSecretIfAbsentOrEqual(account: account, value: "first", service: service) == errSecSuccess)
    #expect(keychainAccessibility(account: account, service: service) == kSecAttrAccessibleAfterFirstUnlock as String)
}

@Test func storedSecretAccessibilityCanChangeWithoutChangingValue() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: service) }

    #expect(saveStoredSecret(
        account: "API_TOKEN",
        value: "secret",
        accessibility: .afterFirstUnlock,
        service: service
    ) == errSecSuccess)
    #expect(loadStoredSecrets(service: service).first?.accessibility == .afterFirstUnlock)
    #expect(keychainAccessibility(account: "API_TOKEN", service: service) == kSecAttrAccessibleAfterFirstUnlock as String)

    #expect(setStoredSecretAccessibility(
        account: "API_TOKEN",
        accessibility: .whenUnlocked,
        service: service
    ) == errSecSuccess)
    #expect(loadStoredSecret(account: "API_TOKEN", service: service) == "secret")
    #expect(loadStoredSecrets(service: service).first?.accessibility == .whenUnlocked)
    #expect(keychainAccessibility(account: "API_TOKEN", service: service) == kSecAttrAccessibleWhenUnlocked as String)
}

@Test func storedSecretsCanBeRenamed() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.\(UUID().uuidString)"
    #expect(saveStoredSecret(
        account: "OLD_TOKEN",
        value: "secret",
        accessibility: .afterFirstUnlock,
        service: service
    ) == errSecSuccess)
    defer { _ = deleteStoredSecret(account: "OLD_TOKEN", service: service) }
    defer { _ = deleteStoredSecret(account: "NEW_TOKEN", service: service) }

    #expect(renameStoredSecret(account: "OLD_TOKEN", to: "NEW_TOKEN", service: service) == errSecSuccess)
    #expect(loadStoredSecrets(service: service).map(\.account) == ["NEW_TOKEN"])
    #expect(loadStoredSecrets(service: service).first?.accessibility == .afterFirstUnlock)
}

@Test func projectValuesGroupUnderOneSecretNameAndSelectNearestAncestor() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.project-values.\(UUID().uuidString)"
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-project-values-\(UUID().uuidString)", isDirectory: true)
    let nested = root.appendingPathComponent("nested/work", isDirectory: true)
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    let rootPath = try canonicalProjectDirectory(root.path)
    let nestedPath = try canonicalProjectDirectory(nested.deletingLastPathComponent().path)
    defer {
        _ = deleteStoredSecret(account: "TOKEN", service: service)
        try? FileManager.default.removeItem(at: root)
    }

    #expect(saveStoredSecret(account: "TOKEN", value: "global", service: service) == errSecSuccess)
    #expect(saveStoredSecret(
        account: "TOKEN",
        value: "root",
        source: .projectDirectory(rootPath),
        service: service
    ) == errSecSuccess)
    #expect(saveStoredSecret(
        account: "TOKEN",
        value: "nested",
        source: .projectDirectory(nestedPath),
        service: service
    ) == errSecSuccess)

    let secret = try #require(loadStoredSecrets(service: service).first)
    #expect(secret.account == "TOKEN")
    #expect(secret.values.count == 3)
    let selected = try #require(resolveStoredSecretValues(
        names: ["TOKEN"], cwd: try canonicalProjectDirectory(nested.path), secrets: [secret]
    )["TOKEN"])
    #expect(selected.source == .projectDirectory(nestedPath))
    #expect(loadStoredSecretValue(selected, service: service) == .success("nested"))
}

@Test func projectSelectionFallsBackToGlobalPerSecretName() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let global = StoredSecretValue(
        source: .global,
        keychainAccount: "GLOBAL",
        accessibility: .whenUnlocked,
        keychainProperties: []
    )
    let selected = try resolveStoredSecretValues(
        names: ["GLOBAL", "MISSING"],
        cwd: cwd,
        secrets: [StoredSecret(account: "GLOBAL", values: [global])]
    )
    #expect(selected["GLOBAL"] == global)
    #expect(selected["MISSING"] == nil)
}

@Test func projectDirectoryValidationUsesPhysicalCanonicalPathsAndRejectsRoots() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-project-path-\(UUID().uuidString)", isDirectory: true)
    let directory = root.appendingPathComponent("directory", isDirectory: true)
    let symlink = root.appendingPathComponent("link", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: directory)
    defer { try? FileManager.default.removeItem(at: root) }

    let canonical = try canonicalProjectDirectory(symlink.path)
    let canonicalDirectory = try canonicalProjectDirectory(directory.path)
    #expect(canonical == canonicalDirectory)
    #expect(throws: ProjectDirectoryValidationError.self) {
        try validateCanonicalProjectDirectory(symlink.path)
    }
    #expect(throws: ProjectDirectoryValidationError.self) {
        try validateCanonicalProjectDirectory("/")
    }
}

@Test func physicalDirectoryAncestorsRejectsCanonicalizationCycles() {
    #expect(throws: ProjectDirectoryValidationError.filesystemCycle) {
        try physicalDirectoryAncestors("/cycle/child") { path in
            switch path {
            case "/cycle/child": (path, 1)
            case "/cycle": ("/cycle/child", 1)
            default: (path, 1)
            }
        }
    }
}

@Test func multiValueAvailabilityAndRenameCompleteAsForwardOperations() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.project-mutation.\(UUID().uuidString)"
    let directory = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    defer {
        _ = deleteStoredSecret(account: "OLD_TOKEN", service: service)
        _ = deleteStoredSecret(account: "NEW_TOKEN", service: service)
    }
    #expect(saveStoredSecret(account: "OLD_TOKEN", value: "global", service: service) == errSecSuccess)
    #expect(saveStoredSecret(
        account: "OLD_TOKEN",
        value: "project",
        source: .projectDirectory(directory),
        service: service
    ) == errSecSuccess)

    #expect(setStoredSecretAccessibility(
        account: "OLD_TOKEN",
        accessibility: .afterFirstUnlock,
        service: service
    ) == errSecSuccess)
    let updated = try #require(loadStoredSecrets(service: service).first)
    #expect(updated.values.allSatisfy { $0.accessibility == .afterFirstUnlock })
    #expect(pendingSecretMutationNames() == [])

    #expect(renameStoredSecret(account: "OLD_TOKEN", to: "NEW_TOKEN", service: service) == errSecSuccess)
    #expect(loadStoredSecrets(service: service).map(\.account) == ["NEW_TOKEN"])
    #expect(loadStoredSecrets(service: service).first?.values.count == 2)
    #expect(loadStoredSecret(account: "NEW_TOKEN", service: service) == "global")
    #expect(loadStoredSecret(
        account: "NEW_TOKEN",
        source: .projectDirectory(directory),
        service: service
    ) == "project")
}

@Test func inconsistentMultiValueAvailabilityDeniesSelection() throws {
    let cwd = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let secret = StoredSecret(
        account: "TOKEN",
        values: [
            StoredSecretValue(
                source: .global,
                keychainAccount: "TOKEN",
                accessibility: .whenUnlocked,
                keychainProperties: []
            ),
            StoredSecretValue(
                source: .projectDirectory(cwd),
                keychainAccount: "PROJECT_TOKEN",
                accessibility: .afterFirstUnlock,
                keychainProperties: []
            ),
        ]
    )
    #expect(throws: StoredSecretSelectionError.self) {
        try resolveStoredSecretValues(names: ["TOKEN"], cwd: cwd, secrets: [secret])
    }
}

@Test func deletingOneValueRetainsDirectAccessUntilTheLastValueIsDeleted() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let secretService = "com.automicvault.tests.project-delete.\(UUID().uuidString)"
    let policyService = "com.automicvault.tests.project-delete-policy.\(UUID().uuidString)"
    let policyAccount = "rules"
    let directory = try canonicalProjectDirectory(FileManager.default.temporaryDirectory.path)
    let launcher = BlessedScriptLauncher(bundleIdentifier: "terminal", requirement: "identifier terminal")
    defer {
        _ = deleteStoredSecret(account: "TOKEN", service: secretService)
        _ = deleteStoredSecret(account: policyAccount, service: policyService)
    }
    #expect(saveStoredSecret(account: "TOKEN", value: "global", service: secretService) == errSecSuccess)
    #expect(saveStoredSecret(
        account: "TOKEN",
        value: "project",
        source: .projectDirectory(directory),
        service: secretService
    ) == errSecSuccess)
    #expect(allowDirectAccess(
        to: "TOKEN", for: launcher, service: policyService, account: policyAccount
    ) == errSecSuccess)

    #expect(deleteStoredSecretValueRevokingDirectAccessIfLast(
        secretName: "TOKEN",
        source: .projectDirectory(directory),
        service: secretService,
        directAccessService: policyService,
        directAccessAccount: policyAccount
    ) == errSecSuccess)
    #expect(loadDirectAccessRules(service: policyService, account: policyAccount).count == 1)

    #expect(deleteStoredSecretValueRevokingDirectAccessIfLast(
        secretName: "TOKEN",
        source: .global,
        service: secretService,
        directAccessService: policyService,
        directAccessAccount: policyAccount
    ) == errSecSuccess)
    #expect(loadDirectAccessRules(service: policyService, account: policyAccount).isEmpty)
}

@Test func malformedProjectValueAccountsFailClosed() {
    guard dataProtectionKeychainAvailable() else { return }
    let service = "com.automicvault.tests.project-corruption.\(UUID().uuidString)"
    let account = "AVProjectValueV1:not-valid"
    defer { _ = deleteStoredSecretValue(secretName: account, source: .global, service: service) }
    #expect(saveStoredSecret(account: account, value: "secret", service: service) == errSecSuccess)
    guard case .failure(let status) = loadStoredSecretsResult(service: service) else {
        Issue.record("malformed encoded account was accepted")
        return
    }
    #expect(status == errSecDecode)
}

@Test func backgroundMetadataMigratesWithoutChangingSecretAccessibility() throws {
    guard dataProtectionKeychainAvailable() else { return }
    let policyService = "com.automicvault.tests.policy.\(UUID().uuidString)"
    let accessLogService = "com.automicvault.tests.log.\(UUID().uuidString)"
    let secretService = "com.automicvault.tests.secret.\(UUID().uuidString)"
    let policyAccount = "policies"
    let accessLogAccount = "access-log"
    defer { _ = deleteStoredSecret(account: policyAccount, service: policyService) }
    defer { _ = deleteStoredSecret(account: accessLogAccount, service: accessLogService) }
    defer { _ = deleteStoredSecret(account: "API_TOKEN", service: secretService) }

    #expect(saveStoredSecret(account: policyAccount, value: "[]", service: policyService) == errSecSuccess)
    #expect(saveStoredSecret(account: accessLogAccount, value: "[]", service: accessLogService) == errSecSuccess)
    #expect(saveStoredSecret(account: "API_TOKEN", value: "secret", service: secretService) == errSecSuccess)

    #expect(migrateBackgroundKeychainItems(
        policyService: policyService,
        policyAccount: policyAccount,
        accessLogService: accessLogService,
        accessLogAccount: accessLogAccount
    ) == errSecSuccess)
    #expect(keychainAccessibility(account: policyAccount, service: policyService) == kSecAttrAccessibleAfterFirstUnlock as String)
    #expect(keychainAccessibility(account: accessLogAccount, service: accessLogService) == kSecAttrAccessibleAfterFirstUnlock as String)
    #expect(keychainAccessibility(account: "API_TOKEN", service: secretService) == kSecAttrAccessibleWhenUnlocked as String)
}

@Test func accessRequestLogKeepsNewestFifty() throws {
    let defaultsName = "com.automicvault.tests.defaults.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: defaultsName))
    defer { defaults.removePersistentDomain(forName: defaultsName) }

    for index in 0..<55 {
        #expect(appendAccessRequestRecord(AccessRequestRecord(
            date: Date(timeIntervalSince1970: TimeInterval(index)),
            tool: "aws",
            command: "aws s3 ls \(index)",
            decision: "Approved",
            approvalSource: "Human",
            reason: "Approved in prompt",
            launcher: "Codex",
            callerPath: "/usr/local/bin/av",
            target: "/opt/homebrew/bin/aws",
            cwd: "/tmp",
            keys: ["AWS_ACCESS_KEY_ID"],
            detail: nil
        ), defaults: defaults))
    }

    let records = loadAccessRequestRecords(defaults: defaults)
    #expect(records.count == 50)
    #expect(records.first?.command == "aws s3 ls 54")
    #expect(records.first?.approvalSourceLabel == "Human")
    #expect(records.last?.command == "aws s3 ls 5")
}

@Test func humanApprovedDirectInjectPersistsForAuthorizationHistory() throws {
    let defaultsName = "com.automicvault.tests.defaults.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: defaultsName))
    defer { defaults.removePersistentDomain(forName: defaultsName) }
    let record = AccessRequestRecord(
        date: .now,
        tool: "sh",
        command: "sh",
        decision: "Approved",
        approvalSource: "Human",
        reason: "Approved in prompt",
        launcher: "ChatGPT",
        callerPath: "/usr/local/bin/av",
        target: "/bin/sh",
        cwd: "/Users/example/project",
        keys: ["FOO"],
        detail: nil
    )

    #expect(appendAccessRequestRecord(record, defaults: defaults))
    let restored = try #require(loadAccessRequestRecords(defaults: defaults).first)
    #expect(restored == record)
    #expect(restored.approvalSourceLabel == "Human")
    #expect(restored.keys == ["FOO"])
    #expect(restored.target == "/bin/sh")
    #expect(restored.callerPath == "/usr/local/bin/av")
}

@Test func productionAccessRequestLogIgnoresUserDefaultsTampering() {
    guard dataProtectionKeychainAvailable() else { return }
    let key = "AccessRequestLogTests-\(UUID().uuidString)"
    defer { _ = deleteStoredSecret(account: key, service: accessRequestLogKeychainService) }
    defer { UserDefaults.standard.removeObject(forKey: key) }
    let record = AccessRequestRecord(
        date: Date(),
        tool: "aws",
        command: "aws s3 ls",
        decision: "Approved",
        approvalSource: "Auto",
        reason: "Read Only",
        launcher: "Codex",
        callerPath: "/usr/local/bin/av",
        target: "/opt/homebrew/bin/aws",
        cwd: "/tmp",
        keys: ["AWS_ACCESS_KEY_ID"],
        detail: nil
    )

    #expect(appendAccessRequestRecord(record, key: key))
    #expect(keychainAccessibility(
        account: key,
        service: accessRequestLogKeychainService
    ) == kSecAttrAccessibleAfterFirstUnlock as String)
    UserDefaults.standard.set(Data("[]".utf8), forKey: key)
    _ = UserDefaults.standard.synchronize()

    #expect(loadAccessRequestRecords(key: key).map(\.id) == [record.id])
}

@Test func accessRequestLogInfersSourceForOlderRecords() throws {
    let data = Data("""
    [{
      "id": "00000000-0000-0000-0000-000000000001",
      "date": 0,
      "tool": "gh",
      "command": "gh pr list",
      "decision": "Approved",
      "reason": "Auto-approved read-only gh request",
      "launcher": "Codex",
      "callerPath": "/opt/homebrew/bin/gh",
      "target": "/opt/homebrew/bin/gh",
      "cwd": "/tmp",
      "keys": [],
      "detail": null
    }]
    """.utf8)

    let records = try JSONDecoder().decode([AccessRequestRecord].self, from: data)
    #expect(records.first?.approvalSource == nil)
    #expect(records.first?.approvalSourceLabel == "Policy")
}

private func temporaryDirectory() -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-menubar-tests-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func dataProtectionKeychainAvailable() -> Bool {
    let service = "com.automicvault.tests.probe.\(UUID().uuidString)"
    let status = saveStoredSecret(account: "PROBE", value: "secret", service: service)
    defer { _ = deleteStoredSecret(account: "PROBE", service: service) }
    return status != errSecMissingEntitlement
}

private func keychainAccessibility(account: String, service: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let attributes = result as? [String: Any]
    else { return nil }
    return attributes[kSecAttrAccessible as String] as? String
}
