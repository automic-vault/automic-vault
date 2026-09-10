import Foundation
import Testing
@testable import MenubarHelperCore

@Test func gitTransportPositiveSurface() {
    let url = "https://github.com/automic-vault/automic-vault.git"
    for command in ["clone", "fetch", "pull", "push"] {
        let args = [command, url] + (command == "clone" ? ["destination"] : [])
        let operation = GitTransportOperation(args)!
        #expect(operation.classification == (command == "push" ? .mutating : .localWrite))
        #expect(!SecretGateProtection.readOnly.allows(operation.classification))
        #expect(SecretGateProtection.readOnlyAndLocalWrites.allows(operation.classification) == (command != "push"))
        #expect(SecretGateProtection.fullExceptSecretDumps.allows(operation.classification))
        #expect(GitTransportOperation(args + ["--force"]) == nil)
        let phase = command == "push" ? "push" : "fetch"
        #expect(operation.arguments(phase: phase, oid: String(repeating: "a", count: 40)) != nil)
        #expect(operation.arguments(phase: phase, oid: "HEAD") == nil)
        #expect(operation.arguments(phase: "credential", oid: "") == nil)
        #expect(SecretGateProtection.fullExceptSecretDumps.allows(.secretDump) == false)
    }
    for url in ["https://github.com.evil/a/b.git", "https://evil/a/b.git", "http://github.com/a/b.git",
                "https://u@github.com/a/b.git", "https://github.com/a/b.git?x", "https://github.com/a/%2e.git",
                "https://github.com/../b.git", "https://github.com/a/b.git/", "https://github.com:443/a/b.git"] {
        #expect(GitTransportOperation(["fetch", url]) == nil)
    }
    let environment = gitTransportEnvironment(objects: "/tmp/objects", nonce: "nonce")
    #expect(environment["GIT_DIR"] == gitTransportRepository)
    #expect(environment["GIT_TRACE_CURL"] == nil)
    #expect(environment["GH_TOKEN"] == nil)
}

@Test func gitTransportRejectsExtendedACL() throws {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
    #expect(FileManager.default.createFile(atPath: path, contents: Data(), attributes: [.posixPermissions: 0o600]))
    defer { try? FileManager.default.removeItem(atPath: path) }
    func chmod(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = arguments + [path]
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
    }
    try chmod(["-N"])
    #expect(gitTransportPathHasNoACL(path))
    try chmod(["+a", "everyone allow write"])
    #expect((try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    #expect(!gitTransportPathHasNoACL(path))
}
