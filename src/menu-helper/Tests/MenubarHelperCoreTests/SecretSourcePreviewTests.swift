import Foundation
import Testing
@testable import MenubarHelperCore

@Test func secretSourcePreviewUsesNearestPhysicalDirectoryAndOnlyEncodesMetadata() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let nested = root.appendingPathComponent("project/nested")
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let project = try canonicalProjectDirectory(root.appendingPathComponent("project").path)
    let cwd = try canonicalProjectDirectory(nested.path)
    func value(_ source: StoredSecretValueSource) -> StoredSecretValue {
        StoredSecretValue(source: source, keychainAccount: "MUST_NOT_BE_DISCLOSED", accessibility: .whenUnlocked, keychainProperties: [])
    }
    let secrets = [
        StoredSecret(account: "PROJECT", values: [value(.global), value(.projectDirectory(project)), value(.projectDirectory(cwd))]),
        StoredSecret(account: "GLOBAL", values: [value(.global), value(.projectDirectory("/unrelated"))]),
        StoredSecret(account: "MISSING", values: [value(.projectDirectory("/unrelated"))]),
    ]
    let result = try secretSourcePreview(secrets: secrets, cwd: cwd)
    #expect(result.map(\.name) == ["GLOBAL", "MISSING", "PROJECT"])
    #expect(result.map(\.source) == ["global", "missing", "project"])
    #expect(result.last?.projectDirectory == cwd)
    let encoded = try JSONEncoder().encode(result)
    let rows = try #require(JSONSerialization.jsonObject(with: encoded) as? [[String: Any]])
    #expect(rows.allSatisfy { Set($0.keys).isSubset(of: ["name", "source", "projectDirectory"]) })
    #expect(!String(decoding: encoded, as: UTF8.self).contains("MUST_NOT_BE_DISCLOSED"))

    let link = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: nested)
    #expect(try secretSourcePreview(secrets: secrets, cwd: canonicalProjectDirectory(link.path)) == result)
    #expect(throws: (any Error).self) { try secretSourcePreview(secrets: secrets, cwd: link.path) }
    #expect(throws: (any Error).self) { try secretSourcePreview(secrets: secrets, cwd: cwd + "/missing") }
}
