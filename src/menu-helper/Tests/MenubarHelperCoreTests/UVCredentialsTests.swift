import Foundation
import Testing
@testable import MenubarHelperCore

@Test func uvRoutesReviewedCommandsAndClassifiesTheirEffects() {
    let commands: [(String, SecretGateRequestClassification)] = [
        ("add", .localWrite), ("remove", .localWrite), ("sync", .localWrite),
        ("lock", .localWrite), ("upgrade", .localWrite), ("tree", .localWrite),
        ("export", .localWrite), ("audit", .localWrite), ("version", .localWrite),
        ("venv", .localWrite), ("pip compile", .localWrite), ("pip install", .localWrite),
        ("pip sync", .localWrite), ("pip uninstall", .localWrite),
        ("tool install", .localWrite), ("tool upgrade", .localWrite),
        ("pip list", .readOnly), ("pip tree", .readOnly), ("tool list", .readOnly),
        ("run", .unknown), ("tool run", .unknown), ("tool uvx", .unknown),
        ("check", .unknown), ("build", .unknown), ("publish", .mutating),
    ]
    for (command, classification) in commands {
        let args = command.split(separator: " ").map(String.init)
        #expect(uvCredentialCommand(args) != nil, "\(command)")
        #expect(uvRequestClassification(args) == classification, "\(command)")
        #expect(uvRequestClassification(["--directory", "auth"] + args) == classification)
    }
    for command in ["", "--help", "--version", "pip install --help", "run -V", "help", "auth token", "auth helper get",
                    "auth login", "init", "format", "python install", "self update",
                    "pip show", "pip freeze", "pip check", "tool uninstall", "tool audit",
                    "workspace list", "future", "--future run", "--directory", "--directory= run",
                    "-- run", "--project publish auth token"] {
        let args = command.split(separator: " ").map(String.init)
        #expect(uvCredentialCommand(args) == nil, "\(command)")
        #expect(uvRequestClassification(args) == .unknown)
    }
}

@Test func uvNonceBindsTheCompleteProcessExecution() {
    let nonce = String(repeating: "a", count: 64)
    var registration = UVRegisteredInvocation(nonce: nonce, arguments: ["pip", "install", "private"],
        cwd: "/project", processStart: 100, effectiveUID: 501, auditSession: 7)
    func matches(_ value: UVRegisteredInvocation, nonce supplied: String? = nil,
                 args: [String] = ["pip", "install", "private"], start: UInt64 = 100,
                 uid: UInt32 = 501, session: UInt32 = 7, version: Int32 = 2) -> Bool {
        value.matches(nonce: supplied ?? nonce, arguments: args, processStart: start,
            effectiveUID: uid, auditSession: session, pidVersion: version)
    }
    #expect(matches(registration))
    #expect(!matches(registration, nonce: String(repeating: "b", count: 64)))
    #expect(!matches(registration, args: ["auth", "token", "https://example.com"]))
    #expect(!matches(registration, args: ["pip", "install", "other"]))
    #expect(!matches(registration, start: 101))
    #expect(!matches(registration, uid: 502))
    #expect(!matches(registration, session: 8))
    registration.targetPIDVersion = 2
    #expect(matches(registration))
    #expect(!matches(registration, version: 3))
}

@Test func uvReleasesOnlyTheUniqueCredentialAtTheMostSpecificHTTPSPath() throws {
    let entries = [
        ["service": "https://example.com/", "username": "alice", "password": "root-dummy"],
        ["service": "https://example.com/private/", "username": "alice", "password": "private-dummy"],
        ["service": "https://example.com/private/", "username": "bob", "password": "bob-dummy"],
    ]
    let stored = String(decoding: try JSONSerialization.data(withJSONObject: ["credential": entries]), as: UTF8.self)
    #expect(uvKeyringCredential(stored, service: "https://EXAMPLE.com:443/private/pkg", username: "alice")?.password == "private-dummy")
    #expect(uvKeyringCredential(stored, service: "https://example.com/private/pkg", username: nil) == nil)
    #expect(uvKeyringCredential(stored, service: "https://example.com/privateevil", username: "alice")?.password == "root-dummy")
    #expect(uvKeyringCredential(stored, service: "https://example.com/public", username: nil)?.username == "alice")
    for url in ["http://example.com/private/", "example.com", "https://other.example.com/",
                "https://example.com:444/private/", "https://example.com/?query", "https://alice@example.com/",
                "https://example.com/#fragment", "https://example.com/\n"] {
        #expect(uvKeyringCredential(stored, service: url, username: "alice") == nil, "\(url)")
    }
    #expect(uvKeyringCredential(stored, service: "https://example.com/", username: "missing") == nil)
    for malformed in ["{}", "{\"credential\":[]}", stored.replacingOccurrences(of: "password", with: "token"),
                      stored.replacingOccurrences(of: "bob-dummy", with: "")] {
        #expect(uvKeyringCredential(malformed, service: "https://example.com/", username: "alice") == nil)
    }
}

@Test func uvWireProtocolHasSeparateRegistrationAndCredentialOperations() {
    #expect(ApprovalServiceOperation.uvHelperVersion.rawValue == "uv-helper-version")
    #expect(ApprovalServiceOperation.uvRegister.rawValue == "uv-register")
    #expect(ApprovalServiceOperation.uvGet.rawValue == "uv-get")
    #expect(uvOfficialTarget == "/opt/av/uv/0.12.12/uv")
    #expect(uvLauncherStub == "#!/usr/local/bin/av uv\n")
    #expect(uvxLauncherStub == "#!/usr/local/bin/av uvx\n")
    #expect(uvKeyringStub == "#!/usr/local/bin/av uv-keyring\n")
}
