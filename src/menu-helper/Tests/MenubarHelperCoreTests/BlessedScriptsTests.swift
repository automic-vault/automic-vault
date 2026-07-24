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
    #!/bin/sh inject +A /bin/sh
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

@Test func blessedScriptReadsAreBoundedAndRejectSymlinks() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-blessed-script-\(UUID().uuidString)", isDirectory: true)
    let script = directory.appendingPathComponent("script")
    let link = directory.appendingPathComponent("link")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let canonicalPath = script.resolvingSymlinksInPath().path

    try Data(repeating: 0, count: 1024 * 1024 + 1).write(to: script)
    #expect(throws: (any Error).self) { try readBlessedScript(path: canonicalPath) }

    try Data("ok".utf8).write(to: script)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: script)
    #expect(throws: (any Error).self) { try readBlessedScript(path: link.path) }
    #expect(try readBlessedScript(path: canonicalPath) == Data("ok".utf8))
}
