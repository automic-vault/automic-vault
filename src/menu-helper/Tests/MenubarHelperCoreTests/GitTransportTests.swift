import Testing
@testable import MenubarHelperCore

@Test func gitTransportPositiveSurface() {
    let url = "https://github.com/automic-vault/automic-vault.git"
    for command in ["clone", "fetch", "pull", "push"] {
        let args = [command, url] + (command == "clone" ? ["destination"] : [])
        let operation = GitTransportOperation(args)!
        #expect(operation.classification == (command == "push" ? .mutating : .localWrite))
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
