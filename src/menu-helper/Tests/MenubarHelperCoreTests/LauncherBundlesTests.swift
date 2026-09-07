import Foundation
import Security
import Testing
@testable import MenubarHelperCore

@Test func launcherBundleNamesRejectPathsAndControls() {
    #expect(launcherBundleDisplayName(from: "  Acme CLI  ") == "Acme CLI")
    #expect(launcherBundleDisplayName(from: "../Acme") == nil)
    #expect(launcherBundleDisplayName(from: "Acme/CLI") == nil)
    #expect(launcherBundleDisplayName(from: "Acme\nCLI") == nil)
}

@Test func launcherBundleCommandNamesAreSafePathComponents() {
    #expect(launcherBundleCommandName(from: "  herdr  ") == "herdr")
    #expect(launcherBundleCommandName(from: "aws-v2") == "aws-v2")
    #expect(launcherBundleCommandName(from: "../herdr") == nil)
    #expect(launcherBundleCommandName(from: "-herdr") == nil)
    #expect(launcherBundleCommandName(from: "herdr cli") == nil)
}

@Test func launcherBundleSigningKindDecodesLegacyDeveloperID() throws {
    let kind = try JSONDecoder().decode(
        LauncherBundleSigningKind.self,
        from: Data(#""developerID""#.utf8)
    )
    #expect(kind == .developerID)
}

@Test func launcherBundleTreeDigestIsDeterministicAndRejectsLinks() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: root.appendingPathComponent("nested", isDirectory: true),
        withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("one".utf8).write(to: root.appendingPathComponent("alpha"))
    try Data("two".utf8).write(to: root.appendingPathComponent("nested/z"))

    #expect(try launcherBundleTreeSHA256(at: root)
        == "ebed77e2222c82013c40a9e5ba1fc849625b3d5ad1fea2a95d5bec8a55019040")
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: root.appendingPathComponent("alpha").path
    )
    #expect(try launcherBundleTreeSHA256(at: root)
        == "ebed77e2222c82013c40a9e5ba1fc849625b3d5ad1fea2a95d5bec8a55019040")
    try FileManager.default.createSymbolicLink(
        at: root.appendingPathComponent("link"),
        withDestinationURL: root.appendingPathComponent("alpha")
    )
    #expect(throws: LauncherBundleVerificationError.invalidBundle) {
        try launcherBundleTreeSHA256(at: root)
    }
}

@Test func launcherBundlePayloadSnapshotAcceptsOneMachOAndResolvesItsSymlink() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let source = directory.appendingPathComponent("source")
    let link = directory.appendingPathComponent("link")
    let destination = directory.appendingPathComponent("payload")
    try Data([0xcf, 0xfa, 0xed, 0xfe, 1, 2, 3, 4]).write(to: source)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: source.path)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)

    let snapshot = try copyLauncherBundlePayload(from: link, to: destination)
    let copiedSHA256 = try sha256OfRegularFile(at: destination)

    #expect(snapshot.sourcePath == source.path)
    #expect(snapshot.byteCount == 8)
    #expect(snapshot.sourceSHA256 == copiedSHA256)
    #expect(FileManager.default.isExecutableFile(atPath: destination.path))
}

@Test func launcherBundlePayloadSnapshotRejectsScripts() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let source = directory.appendingPathComponent("script")
    let destination = directory.appendingPathComponent("payload")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: source)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: source.path)

    #expect(throws: LauncherBundlePayloadError.notRegularMachO) {
        try copyLauncherBundlePayload(from: source, to: destination)
    }
    #expect(!FileManager.default.fileExists(atPath: destination.path))
}

@Test func reservedLauncherBundleIdentityIsRecognizedFromMinimalMetadata() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("\(UUID().uuidString).app", isDirectory: true)
    let contents = directory.appendingPathComponent("Contents", isDirectory: true)
    try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let info = ["CFBundleIdentifier": "\(launcherBundleIdentifierPrefix)test"]
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        .write(to: contents.appendingPathComponent("Info.plist"))

    #expect(launcherBundleClaimsReservedIdentity(at: directory))
}

@Test func invalidLauncherBundleRequirementEvidenceFailsClosed() {
    #expect(launcherBundleDesignatedRequirement(from: [:]) == nil)
    #expect(launcherBundleDesignatedRequirement(from: [
        kSecCodeInfoDesignatedRequirement: "not a requirement",
    ]) == nil)
}

@Test func launcherBundleVerificationPinsTheSignedPayload() throws {
    let generation = UUID()
    let identifier = launcherBundleIdentifierPrefix + generation.uuidString.lowercased()
    let app = FileManager.default.temporaryDirectory
        .appendingPathComponent("\(UUID().uuidString).app", isDirectory: true)
    let contents = app.appendingPathComponent("Contents", isDirectory: true)
    let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
    let resources = contents.appendingPathComponent("Resources", isDirectory: true)
    try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: app) }
    let launcher = macOS.appendingPathComponent("launcher")
    let payload = resources.appendingPathComponent(launcherBundlePayloadName)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/echo"), to: launcher)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/echo"), to: payload)
    try launcherBundleTestCodesign(payload, identifier: identifier + ".payload")
    let payloadSHA256 = try sha256OfRegularFile(at: payload)
    let info: [String: Any] = [
        "CFBundleIdentifier": identifier,
        "CFBundleExecutable": "launcher",
        "CFBundlePackageType": "APPL",
        launcherBundleGenerationInfoKey: generation.uuidString,
        launcherBundlePayloadSHA256InfoKey: payloadSHA256,
    ]
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        .write(to: contents.appendingPathComponent("Info.plist"))
    try launcherBundleTestCodesign(app, identifier: identifier)

    let bundleEvidence = try launcherBundleCodeEvidence(at: app, bundle: true)
    let launcherEvidence = try launcherBundleCodeEvidence(at: launcher)
    let payloadEvidence = try launcherBundleCodeEvidence(at: payload)
    #expect(payloadEvidence.codeIdentifiers.count >= 2)
    let enrollment = LauncherBundleEnrollment(
        generation: generation,
        displayName: "Echo",
        bundleIdentifier: identifier,
        bundlePath: app.path,
        launcherIdentifier: identifier,
        launcherRequirement: bundleEvidence.designatedRequirement,
        bundleCodeIdentifiers: bundleEvidence.codeIdentifiers,
        launcherCodeIdentifiers: launcherEvidence.codeIdentifiers,
        payloadCodeIdentifiers: payloadEvidence.codeIdentifiers,
        sourceSHA256: payloadSHA256,
        payloadSHA256: payloadSHA256,
        payloadEntitlements: [],
        runtimeRequirement: .hardened,
        signingKind: .adHoc,
        signingIdentity: nil
    )

    #expect(try verifyLauncherBundle(
        at: app,
        liveLauncherIdentifier: identifier,
        liveLauncherCodeIdentifier: launcherEvidence.codeIdentifiers[0],
        liveRuntimeProtection: .hardened,
        enrollments: .success([enrollment])
    ) == enrollment)
    #expect(try verifyLauncherBundlePayload(
        at: app,
        livePayloadIdentifier: payloadEvidence.identifier,
        livePayloadCodeIdentifier: payloadEvidence.codeIdentifiers[0],
        liveRuntimeProtection: .hardened,
        enrollments: .success([enrollment])
    ) == enrollment)
    #expect(try verifyLauncherBundleProcess(
        at: app,
        executableURL: launcher,
        liveIdentifier: identifier,
        liveCodeIdentifier: launcherEvidence.codeIdentifiers[0],
        liveRuntimeProtection: .hardened,
        enrollments: .success([enrollment])
    ) == enrollment)
    #expect(try verifyLauncherBundleProcess(
        at: app,
        executableURL: app.appendingPathComponent("Contents/MacOS/../Resources/payload"),
        liveIdentifier: payloadEvidence.identifier,
        liveCodeIdentifier: payloadEvidence.codeIdentifiers[0],
        liveRuntimeProtection: .hardened,
        enrollments: .success([enrollment])
    ) == enrollment)
    #expect(throws: LauncherBundleVerificationError.identityMismatch) {
        try verifyLauncherBundle(
            at: app,
            liveLauncherIdentifier: payloadEvidence.identifier,
            liveLauncherCodeIdentifier: payloadEvidence.codeIdentifiers[0],
            liveRuntimeProtection: .hardened,
            enrollments: .success([enrollment])
        )
    }
    #expect(throws: LauncherBundleVerificationError.identityMismatch) {
        try verifyLauncherBundleProcess(
            at: app,
            executableURL: resources.appendingPathComponent("other"),
            liveIdentifier: payloadEvidence.identifier,
            liveCodeIdentifier: payloadEvidence.codeIdentifiers[0],
            liveRuntimeProtection: .hardened,
            enrollments: .success([enrollment])
        )
    }
    #expect(throws: LauncherBundleVerificationError.identityMismatch) {
        try verifyLauncherBundleProcess(
            at: app,
            executableURL: payload,
            liveIdentifier: payloadEvidence.identifier,
            liveCodeIdentifier: Data([0]),
            liveRuntimeProtection: .hardened,
            enrollments: .success([enrollment])
        )
    }
    #expect(throws: LauncherBundleVerificationError.runtimeMismatch) {
        try verifyLauncherBundleProcess(
            at: app,
            executableURL: payload,
            liveIdentifier: payloadEvidence.identifier,
            liveCodeIdentifier: payloadEvidence.codeIdentifiers[0],
            liveRuntimeProtection: .hardenedWithLibraryValidationDisabled,
            enrollments: .success([enrollment])
        )
    }

    let movedApp = FileManager.default.temporaryDirectory
        .appendingPathComponent("\(UUID().uuidString).app", isDirectory: true)
    try FileManager.default.copyItem(at: app, to: movedApp)
    defer { try? FileManager.default.removeItem(at: movedApp) }
    #expect(throws: LauncherBundleVerificationError.identityMismatch) {
        try verifyLauncherBundleProcess(
            at: movedApp,
            executableURL: movedApp.appendingPathComponent("Contents/Resources/payload"),
            liveIdentifier: payloadEvidence.identifier,
            liveCodeIdentifier: payloadEvidence.codeIdentifiers[0],
            liveRuntimeProtection: .hardened,
            enrollments: .success([enrollment])
        )
    }

    let handle = try FileHandle(forWritingTo: payload)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data([0]))
    try handle.close()
    #expect(throws: (any Error).self) {
        try verifyLauncherBundle(
            at: app,
            liveLauncherIdentifier: identifier,
            liveLauncherCodeIdentifier: launcherEvidence.codeIdentifiers[0],
            liveRuntimeProtection: .hardened,
            enrollments: .success([enrollment])
        )
    }
    #expect(throws: (any Error).self) {
        try verifyLauncherBundleProcess(
            at: app,
            executableURL: payload,
            liveIdentifier: payloadEvidence.identifier,
            liveCodeIdentifier: payloadEvidence.codeIdentifiers[0],
            liveRuntimeProtection: .hardened,
            enrollments: .success([enrollment])
        )
    }
}

@Test(.enabled(if: launcherBundleKeychainTestsAvailable(), "requires an entitled Keychain test host"))
func launcherBundleEnrollmentReplacementIsOneKeychainRecordChange() throws {
    let service = "com.automicvault.tests.launcher-bundles.\(UUID().uuidString)"
    let account = "LauncherBundles"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let old = launcherBundleEnrollment(name: "Acme", generation: UUID())
    let replacement = launcherBundleEnrollment(name: "Acme", generation: UUID())
    #expect(saveLauncherBundleEnrollment(old, service: service, account: account) == errSecSuccess)

    #expect(saveLauncherBundleEnrollment(
        replacement,
        replacing: old.generation,
        service: service,
        account: account
    ) == errSecSuccess)
    #expect(loadLauncherBundleEnrollments(service: service, account: account) == [replacement])
}

@Test(.enabled(if: launcherBundleKeychainTestsAvailable(), "requires an entitled Keychain test host"))
func launcherBundleEnrollmentCanStageAReplacementAlongsideTheOldGeneration() throws {
    let service = "com.automicvault.tests.launcher-bundles.\(UUID().uuidString)"
    let account = "LauncherBundles"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    let old = launcherBundleEnrollment(name: "Acme", generation: UUID())
    let replacement = launcherBundleEnrollment(name: "Acme", generation: UUID())
    #expect(saveLauncherBundleEnrollment(old, service: service, account: account) == errSecSuccess)
    #expect(saveLauncherBundleEnrollment(replacement, service: service, account: account) == errSecSuccess)
    let stored = loadLauncherBundleEnrollments(service: service, account: account)
    #expect(stored.count == 2)
    #expect(Set(stored.map(\.generation)) == [old.generation, replacement.generation])
}

@Test(.enabled(if: launcherBundleKeychainTestsAvailable(), "requires an entitled Keychain test host"))
func corruptLauncherBundleEnrollmentFailsClosed() {
    let service = "com.automicvault.tests.launcher-bundles.\(UUID().uuidString)"
    let account = "LauncherBundles"
    defer { _ = deleteStoredSecret(account: account, service: service) }
    #expect(saveKeychainData(
        Data("not json".utf8),
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    ) == errSecSuccess)

    #expect(loadLauncherBundleEnrollmentsResult(service: service, account: account) == .failure(errSecDecode))
    #expect(saveLauncherBundleEnrollment(
        launcherBundleEnrollment(name: "Acme", generation: UUID()),
        service: service,
        account: account
    ) == errSecDecode)
}

private func launcherBundleKeychainTestsAvailable() -> Bool {
    let service = "com.automicvault.tests.launcher-bundle-probe.\(UUID().uuidString)"
    let status = saveStoredSecret(account: "PROBE", value: "secret", service: service)
    defer { _ = deleteStoredSecret(account: "PROBE", service: service) }
    return status != errSecMissingEntitlement
}

private func launcherBundleTestCodesign(_ url: URL, identifier: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    process.arguments = [
        "--force", "--sign", "-", "--options", "runtime",
        "--identifier", identifier, url.path,
    ]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw CocoaError(.executableRuntimeMismatch)
    }
}

private func launcherBundleEnrollment(
    name: String,
    generation: UUID
) -> LauncherBundleEnrollment {
    let identifier = "\(launcherBundleIdentifierPrefix)\(generation.uuidString.lowercased())"
    return LauncherBundleEnrollment(
        generation: generation,
        displayName: name,
        bundleIdentifier: identifier,
        bundlePath: "/tmp/\(name).app",
        launcherIdentifier: "\(identifier).runner.aabb",
        launcherRequirement: "identifier \"\(identifier)\"",
        bundleCodeIdentifiers: [Data([1])],
        launcherCodeIdentifiers: [Data([2])],
        payloadCodeIdentifiers: [Data([3])],
        sourceSHA256: String(repeating: "f", count: 64),
        payloadSHA256: String(repeating: "0", count: 64),
        payloadEntitlements: [],
        runtimeRequirement: .hardened,
        signingKind: .adHoc,
        signingIdentity: nil,
        createdAt: Date(timeIntervalSince1970: 1)
    )
}
