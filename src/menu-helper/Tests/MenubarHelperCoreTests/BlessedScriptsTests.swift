import Foundation
import Testing
@testable import MenubarHelperCore

@Test func blessedScriptManifestParsesStrictCommentYAML() throws {
    let data = Data("""
    #!/usr/local/bin/av inject --replace-existing-env +B +A /bin/sh
    # --- automic-vault
    # capabilities:
    #   gh: read-only
    #   aws: trusted
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
    ])
    #expect(declaration.checksum.count == 64)
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
    #!/usr/local/bin/av inject +A /bin/sh
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
