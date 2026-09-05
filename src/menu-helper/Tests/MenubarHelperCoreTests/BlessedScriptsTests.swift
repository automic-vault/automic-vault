import Foundation
import Testing
@testable import MenubarHelperCore

@Test func blessedScriptManifestParsesStrictCommentYAML() throws {
    let data = Data("""
    #!/usr/local/bin/av inject --replace-existing-env +B +A /bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    #   aws: write
    #   stripe: trusted
    # ---
    echo ok
    """.utf8)

    let declaration = try blessedScriptDeclaration(data: data)

    #expect(declaration.keys == ["A", "B"])
    #expect(declaration.target == "/bin/sh")
    #expect(declaration.replaceExistingEnv)
    #expect(!declaration.allowMissingKeys)
    #expect(declaration.manifest.capabilities == [
        "gh": .readOnly,
        "aws": .fullExceptSecretDumps,
        "stripe": .fullExceptSecretDumps,
    ])
    #expect(declaration.checksum.count == 64)
}

@Test func blessedScriptManifestIsOptional() throws {
    let data = Data("""
    #!/usr/local/bin/av inject +TOKEN /bin/sh
    echo ok
    """.utf8)

    let declaration = try blessedScriptDeclaration(data: data)

    #expect(declaration.keys == ["TOKEN"])
    #expect(declaration.manifest.capabilities.isEmpty)
    #expect(declaration.snapshotIncompatibleInterpreter == nil)
}

@Test func blessedScriptDetectsSnapshotIncompatibleInterpreterChains() throws {
    let data = Data("""
    #!/usr/local/bin/av inject +TOKEN -- /usr/local/bin/dotenvx run -- /opt/homebrew/bin/uv run --script
    print("ok")
    """.utf8)

    let declaration = try blessedScriptDeclaration(data: data)

    #expect(declaration.snapshotIncompatibleInterpreter == "uv")
}

@Test func blessedScriptCanDeclareCapabilitiesWithoutSecrets() throws {
    let data = Data("""
    #!/usr/local/bin/av inject -- /bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    # ---
    echo ok
    """.utf8)

    let declaration = try blessedScriptDeclaration(data: data)

    #expect(declaration.keys.isEmpty)
    #expect(declaration.manifest.capabilities == ["gh": .readOnly])
}

@Test func launcherEndorsementOnlyControlsAutomaticExecution() {
    let requirement = #"identifier "com.apple.Terminal""#
    let script = BlessedScript(
        path: "/tmp/script",
        checksum: "checksum",
        keys: ["TOKEN"],
        target: "/bin/sh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: ["gh": .fullExceptSecretDumps],
        launchers: []
    )
    let endorsedScript = BlessedScript(
        path: script.path,
        checksum: script.checksum,
        keys: script.keys,
        target: script.target,
        replaceExistingEnv: script.replaceExistingEnv,
        allowMissingKeys: script.allowMissingKeys,
        capabilities: script.capabilities,
        launchers: [BlessedScriptLauncher(
            bundleIdentifier: "com.apple.Terminal",
            requirement: requirement
        )]
    )
    func automaticallyMatches(
        _ script: BlessedScript,
        launcherRequirement: String,
        checksum: String = "checksum"
    ) -> Bool {
        script.matchesExecution(
            path: "/tmp/script",
            checksum: checksum,
            keys: ["TOKEN"],
            target: "/bin/sh",
            replaceExistingEnv: false,
            allowMissingKeys: false,
            launcherRequirement: launcherRequirement
        )
    }
    func approvedExecutionMatches(_ script: BlessedScript, checksum: String = "checksum") -> Bool {
        script.matchesExecution(
            path: "/tmp/script",
            checksum: checksum,
            keys: ["TOKEN"],
            target: "/bin/sh",
            replaceExistingEnv: false,
            allowMissingKeys: false
        )
    }

    #expect(approvedExecutionMatches(script))
    #expect(approvedExecutionMatches(endorsedScript))
    #expect(!approvedExecutionMatches(endorsedScript, checksum: "changed"))
    #expect(!automaticallyMatches(script, launcherRequirement: requirement))
    #expect(automaticallyMatches(endorsedScript, launcherRequirement: requirement))
    #expect(!automaticallyMatches(
        endorsedScript,
        launcherRequirement: #"identifier "com.openai.codex""#
    ))
}

@Test func blessingIdentityRequiresPathAndChecksum() {
    let script = BlessedScript(
        path: "/tmp/script",
        checksum: "checksum",
        keys: [],
        target: "/bin/sh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: [:],
        launchers: []
    )

    #expect(script.matchesBlessing(path: "/tmp/script", checksum: "checksum"))
    #expect(!script.matchesBlessing(path: "/tmp/other", checksum: "checksum"))
    #expect(!script.matchesBlessing(path: "/tmp/script", checksum: "changed"))
}

@Test func canonicalPathExecutionRequiresAnExplicitBlessingOverride() {
    let strict = BlessedScript(
        path: "/tmp/script",
        checksum: "checksum",
        keys: [],
        target: "/opt/homebrew/bin/uv",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: [:],
        launchers: []
    )
    let overridden = BlessedScript(
        path: strict.path,
        checksum: strict.checksum,
        keys: strict.keys,
        target: strict.target,
        replaceExistingEnv: strict.replaceExistingEnv,
        allowMissingKeys: strict.allowMissingKeys,
        allowsCanonicalPathExecution: true,
        capabilities: strict.capabilities,
        launchers: strict.launchers
    )

    #expect(strict.allowsExecution(snapshotIncompatibleInterpreter: nil))
    #expect(!strict.allowsExecution(snapshotIncompatibleInterpreter: "uv"))
    #expect(overridden.allowsExecution(snapshotIncompatibleInterpreter: "uv"))
}

@Test func existingBlessingsDoNotImplicitlyAllowCanonicalPathExecution() throws {
    let data = Data(#"{"path":"/tmp/script","checksum":"checksum","keys":[],"target":"/opt/homebrew/bin/uv","replaceExistingEnv":false,"allowMissingKeys":false,"capabilities":{},"launchers":[],"blessedAt":0}"#.utf8)

    let script = try JSONDecoder().decode(BlessedScript.self, from: data)

    #expect(!script.allowsExecution(snapshotIncompatibleInterpreter: "uv"))
    #expect(script.reviewedContents == nil)
}

@Test func reviewedBlessingContentsMustMatchTheBlessedChecksum() throws {
    let reviewed = Data("#!/usr/local/bin/av inject +TOKEN /bin/sh\necho old\n".utf8)
    let declaration = try blessedScriptDeclaration(data: reviewed)
    let script = BlessedScript(
        path: "/tmp/script",
        checksum: declaration.checksum,
        keys: declaration.keys,
        target: declaration.target,
        replaceExistingEnv: declaration.replaceExistingEnv,
        allowMissingKeys: declaration.allowMissingKeys,
        capabilities: declaration.manifest.capabilities,
        launchers: [],
        reviewedContents: reviewed
    )

    #expect(script.verifiedReviewedContents == reviewed)
    #expect(BlessedScript(
        path: script.path,
        checksum: script.checksum,
        keys: script.keys,
        target: script.target,
        replaceExistingEnv: script.replaceExistingEnv,
        allowMissingKeys: script.allowMissingKeys,
        capabilities: script.capabilities,
        launchers: [],
        reviewedContents: Data("changed".utf8)
    ).verifiedReviewedContents == nil)
}

@Test func blessedScriptDiffShowsReviewedAndCurrentLines() {
    let rows = blessedScriptDiff(
        previous: Data("one\ntwo\nthree\n".utf8),
        current: Data("one\nchanged\nthree\nfour\n".utf8)
    )

    #expect(rows == [
        "--- Blessed",
        "+++ Current",
        "@@ -1,4 +1,5 @@",
        "  one",
        "- two",
        "+ changed",
        "  three",
        "+ four",
        "  ",
    ])
}

@Test func blessedScriptDiffLimitsUnchangedContext() {
    let previous = (1...20).map { "line \($0)" }.joined(separator: "\n")
    let current = previous.replacingOccurrences(of: "line 10", with: "changed 10")

    let rows = blessedScriptDiff(previous: Data(previous.utf8), current: Data(current.utf8))

    #expect(rows == [
        "--- Blessed",
        "+++ Current",
        "@@ -7,7 +7,7 @@",
        "  line 7",
        "  line 8",
        "  line 9",
        "- line 10",
        "+ changed 10",
        "  line 11",
        "  line 12",
        "  line 13",
    ])
}

@Test func legacyBlessingBackfillOnlyRecordsMatchingContents() throws {
    let contents = Data("#!/usr/local/bin/av inject +TOKEN /bin/sh\necho reviewed\n".utf8)
    let declaration = try blessedScriptDeclaration(data: contents)
    let blessing = BlessedScript(
        path: "/tmp/script",
        checksum: declaration.checksum,
        keys: declaration.keys,
        target: declaration.target,
        replaceExistingEnv: declaration.replaceExistingEnv,
        allowMissingKeys: declaration.allowMissingKeys,
        capabilities: declaration.manifest.capabilities,
        launchers: []
    )

    #expect(blessingByRecordingReviewedContents(blessing, contents: contents)?.verifiedReviewedContents == contents)
    #expect(blessingByRecordingReviewedContents(blessing, contents: Data("changed".utf8)) == nil)
}

@Test func removingLauncherPreservesLegacyCanonicalPathExecutionValue() throws {
    let data = Data(#"[{"path":"/tmp/script","checksum":"checksum","keys":["Z","A"],"target":"/bin/sh","replaceExistingEnv":false,"allowMissingKeys":false,"capabilities":{},"launchers":[{"bundleIdentifier":"com.example.launcher","requirement":"identifier \"com.example.launcher\""}],"blessedAt":0}]"#.utf8)
    let script = try #require(JSONDecoder().decode([BlessedScript].self, from: data).first)
    let updated = script.removingLauncher(requirement: #"identifier "com.example.launcher""#)

    #expect(updated.allowsCanonicalPathExecution == nil)
    #expect(updated.keys == script.keys)
    #expect(updated.launchers.isEmpty)
}

@Test func reblessingPreservesLauncherEndorsementsAndAddsTheRequestedLauncher() {
    let terminal = BlessedScriptLauncher(
        bundleIdentifier: "com.apple.Terminal",
        requirement: #"identifier "com.apple.Terminal""#
    )
    let codex = BlessedScriptLauncher(
        bundleIdentifier: "com.openai.codex",
        requirement: #"identifier "com.openai.codex""#
    )
    let visualStudioCode = BlessedScriptLauncher(
        bundleIdentifier: "com.microsoft.VSCode",
        requirement: #"identifier "com.microsoft.VSCode""#
    )
    let previouslyEndorsed = [terminal, visualStudioCode]

    #expect(launcherEndorsementsForReblessing(
        previouslyEndorsed: previouslyEndorsed,
        requestedLauncher: nil
    ) == previouslyEndorsed)
    #expect(launcherEndorsementsForReblessing(
        previouslyEndorsed: previouslyEndorsed,
        requestedLauncher: codex
    ) == [terminal, visualStudioCode, codex])
    #expect(launcherEndorsementsForReblessing(
        previouslyEndorsed: previouslyEndorsed,
        requestedLauncher: terminal
    ) == previouslyEndorsed)
}

@Test(arguments: [
    """
    #!/bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    # ---
    """,
    """
    #!/bin/sh inject +A /bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    # ---
    """,
    """
    #!/usr/local/bin/av inject +A /bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    #   gh: trusted
    # ---
    """,
    """
    #!/usr/local/bin/av inject +A /bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: anything
    # ---
    """,
    """
    #!/usr/local/bin/av inject +A sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    # ---
    """,
])
func malformedBlessedScriptManifestsFailClosed(_ source: String) {
    #expect(throws: (any Error).self) {
        try blessedScriptDeclaration(data: Data(source.utf8))
    }
}

@Test func blessedScriptReadsAreBoundedAndRejectSymlinks() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-blessed-script-\(UUID().uuidString)", isDirectory: true)
    let script = directory.appendingPathComponent("script")
    let link = directory.appendingPathComponent("link")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let canonicalPath = script.resolvingSymlinksInPath().path

    try Data(repeating: 0, count: 1024 * 1024 + 1).write(to: script)
    do {
        _ = try readBlessedScript(path: canonicalPath)
        Issue.record("expected an oversized script to be rejected")
    } catch {
        #expect(error.localizedDescription == "script exceeds the 1 MiB size limit")
    }

    try Data("ok".utf8).write(to: script)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: script)
    #expect(throws: (any Error).self) { try readBlessedScript(path: link.path) }
    #expect(try readBlessedScript(path: canonicalPath) == Data("ok".utf8))
}

@Test func blessedScriptParseErrorsExplainWhyTheScriptWasRejected() {
    do {
        _ = try blessedScriptDeclaration(data: Data("#!/bin/sh\n".utf8))
        Issue.record("expected a non-av shebang to be rejected")
    } catch {
        #expect(error.localizedDescription == "invalid av inject shebang")
    }
}

@Test func blessedScriptNarrowedPolicyExplanationIdentifiesMissingCapability() {
    let script = BlessedScript(
        path: "/tmp/deploy.sh",
        checksum: "checksum",
        keys: [],
        target: "/bin/sh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: ["aws": .fullExceptSecretDumps],
        launchers: []
    )

    let explanation = activeBlessedScriptPromptExplanation(
        script: script,
        gateID: "gpg-signing",
        launcherAllowsOperation: true
    )
    #expect(explanation == "The Blessed Script’s declared Capabilities narrow gate policy for this execution and lack a gpg-signing Capability. Approval applies only to this request.")
}

@Test func blessedScriptNarrowedPolicyExplanationIdentifiesExceededCapability() {
    let script = BlessedScript(
        path: "/tmp/deploy.sh",
        checksum: "checksum",
        keys: [],
        target: "/bin/sh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: ["gh": .readOnly],
        launchers: []
    )

    let explanation = activeBlessedScriptPromptExplanation(
        script: script,
        gateID: "gh",
        launcherAllowsOperation: true
    )
    #expect(explanation == "The Blessed Script’s declared Capabilities narrow gate policy for this execution and exceed the declared gh Capability. Approval applies only to this request.")
}

@Test func blessedScriptNarrowedPolicyExplanationFallsBackWhenLauncherDoesNotAllow() {
    let script = BlessedScript(
        path: "/tmp/deploy.sh",
        checksum: "checksum",
        keys: [],
        target: "/bin/sh",
        replaceExistingEnv: false,
        allowMissingKeys: false,
        capabilities: ["aws": .fullExceptSecretDumps],
        launchers: []
    )

    #expect(activeBlessedScriptPromptExplanation(
        script: script,
        gateID: "gpg-signing",
        launcherAllowsOperation: false
    ) == "This request exceeds the stored authority. Approval applies only to this request.")

    #expect(activeBlessedScriptPromptExplanation(
        script: script,
        gateID: nil,
        launcherAllowsOperation: true
    ) == "This request exceeds the stored authority. Approval applies only to this request.")
}
