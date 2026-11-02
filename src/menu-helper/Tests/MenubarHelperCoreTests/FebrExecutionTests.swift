import Foundation
import Testing
@testable import MenubarHelperCore

struct FebrExecutionTests {
    @Test func closedCommandCatalog() {
        for args in [["install", "jq"], ["upgrade"], ["uninstall", "openssl@3"], ["services", "upgrade", "postgresql@18"]] {
            #expect(febrOperation(args) == .systemWrite)
        }
        for args in [["services", "start", "nginx"], ["services", "stop", "--all"], ["services", "cleanup"]] {
            #expect(febrOperation(args) == .localWrite)
        }
        for args in [[], ["install"], ["install", "../x"], ["install", "tap/formula"], ["install", "--cask", "x"], ["services", "upgrade", "--all"], ["services", "start", "x", "--sudo"], ["eval", "x"], ["inject", "+SECRET"], ["INSTALL", "jq"]] {
            #expect(febrOperation(args) == nil)
        }
    }
    @Test func enrollmentCannotInjectSigningRequirement() throws {
        for hash in [String(repeating: "a", count: 39), String(repeating: "g", count: 40), "\" or true"] {
            let data = try JSONSerialization.data(withJSONObject: ["protocolVersion":1, "cdhash":hash, "uid":400, "gid":400])
            #expect(try !JSONDecoder().decode(FebrEnrollment.self, from: data).isValid)
        }
        let data = try JSONSerialization.data(withJSONObject: ["protocolVersion":1, "cdhash":String(repeating:"a",count:40), "uid":0, "gid":400])
        #expect(try !JSONDecoder().decode(FebrEnrollment.self, from: data).isValid)
    }
}
