import Foundation
import Security
import Testing
@testable import MenubarHelperCore

struct BruExecutionTests {
    @Test func closedCommandCatalog() {
        for args in [["install", "jq"], ["upgrade"], ["uninstall", "openssl@3"], ["services", "upgrade", "postgresql@18"]] {
            #expect(bruOperation(args) == .systemWrite)
        }
        for args in [["services", "start", "nginx"], ["services", "stop", "--all"], ["services", "cleanup"]] {
            #expect(bruOperation(args) == .localWrite)
        }
        for args in [[], ["install"], ["install", "../x"], ["install", "tap/formula"], ["install", "--cask", "x"], ["services", "upgrade", "--all"], ["services", "start", "x", "--sudo"], ["eval", "x"], ["inject", "+SECRET"], ["INSTALL", "jq"]] {
            #expect(bruOperation(args) == nil)
        }
    }
    @Test func enrollmentRequiresCurrentProtocolAndServiceAccount() throws {
        for (version, uid, gid, valid) in [(2,400,400,true), (1,400,400,false), (2,0,400,false), (2,400,0,false)] {
            let data = try JSONSerialization.data(withJSONObject: ["protocolVersion":version, "uid":uid, "gid":gid])
            #expect(try JSONDecoder().decode(BruEnrollment.self, from: data).isValid == valid)
        }
    }
    @Test func copiedIdentifierDoesNotAuthenticateAdHocCode() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let binary = directory.appendingPathComponent("fake-bru")
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: binary.path)
        let signer = Process()
        signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", "--identifier", BruEnrollment.identifier, "--options", "runtime", binary.path]
        try signer.run()
        signer.waitUntilExit()
        #expect(signer.terminationStatus == 0)
        var requirement: SecRequirement?
        #expect(SecRequirementCreateWithString(BruEnrollment.requirement as CFString, [], &requirement) == errSecSuccess)
        let checkedRequirement = try #require(requirement)
        var code: SecStaticCode?
        #expect(SecStaticCodeCreateWithPath(binary as CFURL, [], &code) == errSecSuccess)
        let checkedCode = try #require(code)
        #expect(SecStaticCodeCheckValidity(checkedCode, [], nil) == errSecSuccess)
        #expect(SecStaticCodeCheckValidity(checkedCode, [], checkedRequirement) != errSecSuccess)
    }

}
