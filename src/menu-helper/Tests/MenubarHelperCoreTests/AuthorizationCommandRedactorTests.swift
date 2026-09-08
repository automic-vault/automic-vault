import Foundation
import Testing
@testable import MenubarHelperCore

@Test func redactsSensitiveFlagValues() {
    #expect(redactedAuthorizationArguments(
        tool: "tool",
        arguments: ["--api-key", "api-secret", "--password=hunter2", "--profile", "production"]
    ) == ["--api-key", "<redacted>", "--password=<redacted>", "--profile", "production"])
}

@Test func redactsSensitiveEnvironmentAssignments() {
    #expect(redactedAuthorizationArguments(
        tool: "env",
        arguments: ["API_TOKEN=token-value", "DATABASE_PASSWORD=hunter2", "REGION=us-east-1"]
    ) == ["API_TOKEN=<redacted>", "DATABASE_PASSWORD=<redacted>", "REGION=us-east-1"])
}

@Test func redactsSensitiveHeaders() {
    #expect(redactedAuthorizationArguments(
        tool: "client",
        arguments: [
            "Authorization: Bearer token-value",
            "X-API-Key: api-secret",
            "Cookie: session=secret",
            "Accept: application/json",
        ]
    ) == [
        "Authorization: <redacted>",
        "X-API-Key: <redacted>",
        "Cookie: <redacted>",
        "Accept: application/json",
    ])
}

@Test func redactsURLPasswordsAndSensitiveQueryValues() {
    #expect(redactedAuthorizationArguments(
        tool: "curl",
        arguments: ["https://alice:hunter2@example.com/repos?id=42&access_token=token-value#readme"]
    ) == ["https://alice:<redacted>@example.com/repos?id=42&access_token=<redacted>#readme"])
}

@Test func redactsToolSpecificCredentialArguments() {
    #expect(redactedAuthorizationArguments(
        tool: "/usr/bin/curl",
        arguments: ["-u", "alice:hunter2", "-HAuthorization: Bearer token-value", "--header", "Cookie: a=b"]
    ) == ["-u", "alice:<redacted>", "-HAuthorization: <redacted>", "--header", "Cookie: <redacted>"])
    #expect(redactedAuthorizationArguments(
        tool: "sshpass",
        arguments: ["-p", "hunter2", "ssh", "host"]
    ) == ["-p", "<redacted>", "ssh", "host"])
}

@Test func redactsUAACredentialFlags() {
    #expect(redactedAuthorizationArguments(
        tool: "/usr/local/bin/uaa",
        arguments: ["get-password-token", "user", "-p", "password", "--client_secret=secret"]
    ) == ["get-password-token", "user", "-p", "<redacted>", "--client_secret=<redacted>"])
}

@Test func redactsOpenHueApplicationKeyFlags() {
    #expect(redactedAuthorizationArguments(
        tool: "openhue-cli",
        arguments: ["config", "--bridge", "192.0.2.10", "--key=application-key"]
    ) == ["config", "--bridge", "192.0.2.10", "--key=<redacted>"])
}

@Test func redactsRecognizableCredentialFormats() {
    let stripeToken = ["sk", "live", "1234567890abcdefghijklmnop"].joined(separator: "_")
    let slackToken = ["xoxb", "1234567890", "abcdefghijklmnop"].joined(separator: "-")
    let githubToken = ["ghp", String(repeating: "a", count: 24)].joined(separator: "_")
    let values = [
        githubToken,
        stripeToken,
        slackToken,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----",
    ]
    #expect(redactedAuthorizationArguments(tool: "tool", arguments: values) == Array(repeating: "<redacted>", count: values.count))
}

@Test func preservesIdentifiersNamesAndOrdinaryArguments() {
    let values = [
        "0123456789abcdef0123456789abcdef01234567",
        "550e8400-e29b-41d4-a716-446655440000",
        "arn:aws:iam::123456789012:role/example-production-role",
        "--profile", "production",
        "--secret-name", "payments-production",
        "--secret-id", "secret-123",
        "https://example.com/repos?id=42&profile=production",
        "-h", "help-topic",
        "ordinary-positional-value",
    ]
    #expect(redactedAuthorizationArguments(tool: "aws", arguments: values) == values)
}

@Test func accessRequestRecordPersistsExactAndDisplayCommands() throws {
    let record = AccessRequestRecord(
        date: Date(timeIntervalSince1970: 1),
        tool: "curl",
        command: "curl --api-key api-secret",
        displayCommand: "curl --api-key <redacted>",
        decision: "Approved",
        reason: "Approved in prompt",
        launcher: "Terminal",
        launcherIconPath: "/System/Applications/Utilities/Terminal.app",
        callerPath: "/usr/local/bin/av",
        target: "/usr/bin/curl",
        targetRuntimeProtection: "Hardened Runtime",
        cwd: "/tmp",
        keys: [],
        detail: nil
    )

    let decoded = try JSONDecoder().decode(AccessRequestRecord.self, from: JSONEncoder().encode(record))
    #expect(decoded.command == "curl --api-key api-secret")
    #expect(decoded.commandForDisplay == "curl --api-key <redacted>")
    #expect(decoded.targetRuntimeProtection == "Hardened Runtime")
    #expect(decoded.launcherIconPath == "/System/Applications/Utilities/Terminal.app")
    #expect(!decoded.commandForDisplay.contains("api-secret"))
}

@Test func legacyAccessRequestHidesAllArguments() throws {
    let data = Data("""
    {
      "id": "00000000-0000-0000-0000-000000000001",
      "date": 0,
      "tool": "gh",
      "command": "gh api --header Authorization:secret-value",
      "decision": "Approved",
      "reason": "Approved in prompt",
      "launcher": "Terminal",
      "callerPath": "/usr/local/bin/av",
      "target": "/usr/bin/gh",
      "cwd": "/tmp",
      "keys": [],
      "detail": null
    }
    """.utf8)

    let record = try JSONDecoder().decode(AccessRequestRecord.self, from: data)
    #expect(record.command == "gh api --header Authorization:secret-value")
    #expect(record.commandForDisplay == "gh <arguments hidden>")
    #expect(record.targetRuntimeProtection == nil)
    #expect(record.launcherIconPath == nil)
    #expect(!record.commandForDisplay.contains("secret-value"))
}
