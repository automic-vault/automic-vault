#!/usr/bin/env swift

import Darwin
import Foundation
import Security

private typealias ValidateResource = @convention(c) (
    SecStaticCode,
    CFURL,
    UInt32,
    UnsafeMutablePointer<Unmanaged<CFError>?>?
) -> OSStatus

private struct CommandError: Error, CustomStringConvertible {
    let command: String
    let output: String

    var description: String { "\(command) failed: \(output)" }
}

private struct Fixture {
    let root: URL
    let app: URL
    let executable: URL
    let helper: URL
    let target: URL
    let unrelated: URL
    let link: URL
}

private let validateResource: ValidateResource = {
    guard let handle = dlopen(nil, RTLD_LAZY),
          let symbol = dlsym(handle, "SecStaticCodeValidateResourceWithErrors")
    else {
        fputs("SecStaticCodeValidateResourceWithErrors is unavailable\n", stderr)
        exit(2)
    }
    return unsafeBitCast(symbol, to: ValidateResource.self)
}()

private func run(_ executable: String, _ arguments: [String]) throws -> String {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    process.waitUntilExit()
    let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    guard process.terminationStatus == 0 else {
        throw CommandError(command: ([executable] + arguments).joined(separator: " "), output: output)
    }
    return output
}

private func sign(_ url: URL, identity: String, identifier: String) throws {
    var arguments = [
        "--force", "--sign", identity, "--options", "runtime",
        "--identifier", identifier,
    ]
    if identity != "-" { arguments.append("--timestamp=none") }
    arguments.append(url.path)
    _ = try run("/usr/bin/codesign", arguments)
}

private func makeFixture(
    identity: String,
    appIdentifier: String = "com.automicvault.targeted-validation",
    executableSource: String = "/usr/bin/true"
) throws -> Fixture {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-targeted-validation-\(UUID().uuidString)", isDirectory: true)
    let app = root.appendingPathComponent("Example.app", isDirectory: true)
    let contents = app.appendingPathComponent("Contents", isDirectory: true)
    let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
    let helpers = contents.appendingPathComponent("Helpers", isDirectory: true)
    let resources = contents.appendingPathComponent("Resources", isDirectory: true)
    let executable = macOS.appendingPathComponent("Example")
    let helper = helpers.appendingPathComponent("helper")
    let target = resources.appendingPathComponent("target")
    let unrelated = resources.appendingPathComponent("unrelated")
    let link = resources.appendingPathComponent("link")

    try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: executableSource), to: executable)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: helper)
    try Data("target".utf8).write(to: target)
    try Data("unrelated".utf8).write(to: unrelated)
    try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "target")
    try Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>Example</string>
    <key>CFBundleIdentifier</key><string>\(appIdentifier)</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    </dict></plist>
    """.utf8).write(to: contents.appendingPathComponent("Info.plist"))
    try sign(helper, identity: identity, identifier: "\(appIdentifier).helper")
    try sign(app, identity: identity, identifier: appIdentifier)
    return Fixture(
        root: root,
        app: app,
        executable: executable,
        helper: helper,
        target: target,
        unrelated: unrelated,
        link: link
    )
}

private func staticCode(_ url: URL) throws -> SecStaticCode {
    var code: SecStaticCode?
    let status = SecStaticCodeCreateWithPath(url as CFURL, [], &code)
    guard status == errSecSuccess, let code else {
        throw CommandError(command: "SecStaticCodeCreateWithPath \(url.path)", output: "OSStatus \(status)")
    }
    return code
}

private func directStatus(
    app: URL,
    resource: URL,
    error: UnsafeMutablePointer<Unmanaged<CFError>?>? = nil
) throws -> OSStatus {
    validateResource(try staticCode(app), resource as CFURL, kSecCSStrictValidate, error)
}

private func targetedStatus(
    app: URL,
    resource: URL,
    requirement: SecRequirement? = nil
) throws -> OSStatus {
    let code = try staticCode(app)
    let flags = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures
            | kSecCSDoNotValidateResources
            | kSecCSStrictValidate
    )
    let status = SecStaticCodeCheckValidity(code, flags, requirement)
    guard status == errSecSuccess else { return status }
    return validateResource(code, resource as CFURL, kSecCSStrictValidate, nil)
}

private func fullStatus(_ app: URL) throws -> OSStatus {
    SecStaticCodeCheckValidity(
        try staticCode(app),
        SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
        nil
    )
}

private func designatedRequirement(_ app: URL) throws -> SecRequirement {
    var requirement: SecRequirement?
    let status = SecCodeCopyDesignatedRequirement(try staticCode(app), [], &requirement)
    guard status == errSecSuccess, let requirement else {
        throw CommandError(command: "SecCodeCopyDesignatedRequirement", output: "OSStatus \(status)")
    }
    return requirement
}

private func signingIdentifier(_ code: SecStaticCode) throws -> String {
    var information: CFDictionary?
    let status = SecCodeCopySigningInformation(code, [], &information)
    guard status == errSecSuccess,
          let dictionary = information as? [CFString: Any],
          let identifier = dictionary[kSecCodeInfoIdentifier] as? String
    else {
        throw CommandError(command: "SecCodeCopySigningInformation", output: "OSStatus \(status)")
    }
    return identifier
}

private func liveSigningIdentifier(_ pid: pid_t) throws -> String {
    var code: SecCode?
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
    guard status == errSecSuccess, let code else {
        throw CommandError(command: "SecCodeCopyGuestWithAttributes", output: "OSStatus \(status)")
    }
    var staticCode: SecStaticCode?
    let staticStatus = SecCodeCopyStaticCode(code, [], &staticCode)
    guard staticStatus == errSecSuccess, let staticCode else {
        throw CommandError(command: "SecCodeCopyStaticCode", output: "OSStatus \(staticStatus)")
    }
    return try signingIdentifier(staticCode)
}

private func requirement(_ source: String) throws -> SecRequirement {
    var requirement: SecRequirement?
    let status = SecRequirementCreateWithString(source as CFString, [], &requirement)
    guard status == errSecSuccess, let requirement else {
        throw CommandError(command: "SecRequirementCreateWithString", output: "OSStatus \(status)")
    }
    return requirement
}

private func mutate(_ url: URL) throws {
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    try handle.seekToEnd()
    try handle.write(contentsOf: Data([0]))
}

private func overwriteFirstByte(_ url: URL) throws {
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    try handle.seek(toOffset: 0)
    try handle.write(contentsOf: Data([0]))
}

private func flipByte(_ url: URL, offset: UInt64) throws {
    let handle = try FileHandle(forUpdating: url)
    defer { try? handle.close() }
    try handle.seek(toOffset: offset)
    guard let byte = try handle.read(upToCount: 1)?.first else {
        throw CommandError(command: "flip byte", output: "\(url.path) is too short")
    }
    try handle.seek(toOffset: offset)
    try handle.write(contentsOf: Data([byte ^ 0xff]))
}

private func replaceExecutable(_ url: URL) throws {
    try FileManager.default.removeItem(at: url)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/false"), to: url)
}

private func tamperX86Slice(_ fixture: Fixture) throws {
    let x86 = fixture.root.appendingPathComponent("x86_64")
    let arm = fixture.root.appendingPathComponent("arm64e")
    let replacement = fixture.root.appendingPathComponent("tampered-universal")
    _ = try run("/usr/bin/lipo", [fixture.executable.path, "-thin", "x86_64", "-output", x86.path])
    _ = try run("/usr/bin/lipo", [fixture.executable.path, "-thin", "arm64e", "-output", arm.path])
    try flipByte(x86, offset: 4_096)
    _ = try run("/usr/bin/lipo", ["-create", x86.path, arm.path, "-output", replacement.path])
    try FileManager.default.removeItem(at: fixture.executable)
    try FileManager.default.moveItem(at: replacement, to: fixture.executable)
}

private func codesignAccepts(_ app: URL, reportFailure: Bool = false) -> Bool {
    do {
        _ = try run("/usr/bin/codesign", ["--verify", "--strict", "--all-architectures", app.path])
        return true
    } catch {
        if reportFailure { print("      \(error)") }
        return false
    }
}

private func withFixture(
    identity: String,
    _ body: (Fixture) throws -> Bool
) throws -> Bool {
    let fixture = try makeFixture(identity: identity)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    return try body(fixture)
}

private struct Harness {
    var passed = 0
    var failed = 0

    mutating func check(_ name: String, _ body: () throws -> Bool) {
        do {
            if try body() {
                passed += 1
                print("PASS  \(name)")
            } else {
                failed += 1
                print("FAIL  \(name)")
            }
        } catch {
            failed += 1
            print("FAIL  \(name): \(error)")
        }
    }
}

private let arguments = Array(CommandLine.arguments.dropFirst())
private let identity: String = {
    guard let index = arguments.firstIndex(of: "--identity"), arguments.indices.contains(index + 1)
    else { return "-" }
    return arguments[index + 1]
}()

print("macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
#if arch(arm64)
print("architecture: arm64")
#elseif arch(x86_64)
print("architecture: x86_64")
#else
print("architecture: unknown")
#endif
print("signing identity: \(identity == "-" ? "ad hoc" : identity)")

private var harness = Harness()

harness.check("baseline: SPI, production flags, full validation, and codesign agree") {
    try withFixture(identity: identity) {
        let main = try directStatus(app: $0.app, resource: $0.executable)
        let target = try directStatus(app: $0.app, resource: $0.target)
        let targeted = try targetedStatus(app: $0.app, resource: $0.executable)
        let full = try fullStatus($0.app)
        let codesign = codesignAccepts($0.app, reportFailure: true)
        let passed = main == errSecSuccess
            && target == errSecSuccess
            && targeted == errSecSuccess
            && full == errSecSuccess
            && codesign
        if !passed {
            print("      main=\(main) target=\(target) targeted=\(targeted) full=\(full) codesign=\(codesign)")
        }
        return passed
    }
}

harness.check("stored requirement accepts the original app identity") {
    try withFixture(identity: identity) {
        let requirement = try designatedRequirement($0.app)
        return try targetedStatus(app: $0.app, resource: $0.executable, requirement: requirement)
            == errSecSuccess
    }
}

harness.check("mismatched requirement fails closed") {
    try withFixture(identity: identity) {
        let wrong = try requirement("identifier \"com.automicvault.wrong\"")
        return try targetedStatus(app: $0.app, resource: $0.executable, requirement: wrong)
            != errSecSuccess
    }
}

harness.check("successful validation leaves the CFError pointer empty") {
    try withFixture(identity: identity) {
        var unmanagedError: Unmanaged<CFError>?
        let status = try directStatus(app: $0.app, resource: $0.target, error: &unmanagedError)
        return status == errSecSuccess && unmanagedError == nil
    }
}

harness.check("unrelated sealed-resource damage is ignored only by targeted validation") {
    try withFixture(identity: identity) {
        try Data("changed".utf8).write(to: $0.unrelated)
        return try directStatus(app: $0.app, resource: $0.executable) == errSecSuccess
            && directStatus(app: $0.app, resource: $0.target) == errSecSuccess
            && fullStatus($0.app) != errSecSuccess
            && !codesignAccepts($0.app)
    }
}

harness.check("selected resource modification fails") {
    try withFixture(identity: identity) {
        try Data("changed".utf8).write(to: $0.target)
        return try directStatus(app: $0.app, resource: $0.target) != errSecSuccess
    }
}

harness.check("selected resource deletion fails") {
    try withFixture(identity: identity) {
        try FileManager.default.removeItem(at: $0.target)
        return try directStatus(app: $0.app, resource: $0.target) != errSecSuccess
    }
}

harness.check("new unsealed resource fails") {
    try withFixture(identity: identity) {
        let added = $0.target.deletingLastPathComponent().appendingPathComponent("added")
        try Data("added".utf8).write(to: added)
        return try directStatus(app: $0.app, resource: added) != errSecSuccess
    }
}

harness.check("path outside the bundle returns errSecParam") {
    try withFixture(identity: identity) {
        try directStatus(app: $0.app, resource: URL(fileURLWithPath: "/usr/bin/true")) == errSecParam
    }
}

harness.check("a valid main-executable replacement is rejected by the stored identity requirement") {
    try withFixture(identity: identity) {
        let original = try designatedRequirement($0.app)
        try replaceExecutable($0.executable)
        return try directStatus(app: $0.app, resource: $0.executable) == errSecSuccess
            && targetedStatus(app: $0.app, resource: $0.executable, requirement: original)
                != errSecSuccess
    }
}

harness.check("SPI validation is static and does not bind a live process to its current bundle path") {
    let runningIdentifier = "com.automicvault.targeted-validation.running"
    let replacementIdentifier = "com.automicvault.targeted-validation.replacement"
    let running = try makeFixture(
        identity: identity,
        appIdentifier: runningIdentifier,
        executableSource: "/bin/sleep"
    )
    let replacement = try makeFixture(identity: identity, appIdentifier: replacementIdentifier)
    defer {
        try? FileManager.default.removeItem(at: running.root)
        try? FileManager.default.removeItem(at: replacement.root)
    }
    let process = Process()
    process.executableURL = running.executable
    process.arguments = ["30"]
    try process.run()
    defer {
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
    }
    let originalApp = running.root.appendingPathComponent("Running.app")
    try FileManager.default.moveItem(at: running.app, to: originalApp)
    try FileManager.default.moveItem(at: replacement.app, to: running.app)
    let currentExecutable = running.app.appendingPathComponent("Contents/MacOS/Example")
    return try liveSigningIdentifier(process.processIdentifier) == runningIdentifier
        && signingIdentifier(staticCode(running.app)) == replacementIdentifier
        && directStatus(app: running.app, resource: currentExecutable) == errSecSuccess
}

harness.check("Info.plist modification fails main-executable validation") {
    try withFixture(identity: identity) {
        try mutate($0.app.appendingPathComponent("Contents/Info.plist"))
        return try directStatus(app: $0.app, resource: $0.executable) != errSecSuccess
    }
}

harness.check("resource seal modification fails selected-resource validation") {
    try withFixture(identity: identity) {
        try overwriteFirstByte($0.app.appendingPathComponent("Contents/_CodeSignature/CodeResources"))
        return try directStatus(app: $0.app, resource: $0.target) != errSecSuccess
    }
}

harness.check("a forged matching CodeResources file cannot bless modified resource bytes") {
    try withFixture(identity: identity) { original in
        let resigned = try makeFixture(identity: identity)
        defer { try? FileManager.default.removeItem(at: resigned.root) }
        try Data("attacker-selected".utf8).write(to: original.target)
        try Data("attacker-selected".utf8).write(to: resigned.target)
        try sign(
            resigned.app,
            identity: identity,
            identifier: "com.automicvault.targeted-validation"
        )
        let originalSeal = original.app.appendingPathComponent("Contents/_CodeSignature/CodeResources")
        let forgedSeal = resigned.app.appendingPathComponent("Contents/_CodeSignature/CodeResources")
        try FileManager.default.removeItem(at: originalSeal)
        try FileManager.default.copyItem(at: forgedSeal, to: originalSeal)
        return try directStatus(app: original.app, resource: original.target) != errSecSuccess
    }
}

harness.check("signed nested helper validates") {
    try withFixture(identity: identity) {
        try directStatus(app: $0.app, resource: $0.helper) == errSecSuccess
    }
}

harness.check("unsigned nested-helper modification fails") {
    try withFixture(identity: identity) {
        try replaceExecutable($0.helper)
        return try directStatus(app: $0.app, resource: $0.helper) != errSecSuccess
    }
}

harness.check("sealed symlink validates, but retargeting it fails") {
    try withFixture(identity: identity) {
        guard try directStatus(app: $0.app, resource: $0.link) == errSecSuccess else { return false }
        try FileManager.default.removeItem(at: $0.link)
        try FileManager.default.createSymbolicLink(atPath: $0.link.path, withDestinationPath: "unrelated")
        return try directStatus(app: $0.app, resource: $0.link) != errSecSuccess
    }
}

harness.check("failure returns a retained CFError matching the OSStatus") {
    try withFixture(identity: identity) {
        try Data("changed".utf8).write(to: $0.target)
        var unmanagedError: Unmanaged<CFError>?
        let status = try directStatus(app: $0.app, resource: $0.target, error: &unmanagedError)
        guard let error = unmanagedError?.takeRetainedValue() else { return false }
        return status != errSecSuccess && CFErrorGetCode(error) == status
    }
}

#if arch(arm64)
harness.check("production flags reject a damaged non-native architecture") {
    try withFixture(identity: identity) {
        try tamperX86Slice($0)
        return try directStatus(app: $0.app, resource: $0.executable) == errSecSuccess
            && targetedStatus(app: $0.app, resource: $0.executable) != errSecSuccess
    }
}
#endif

if identity != "-" {
    harness.check("an app update signed by the same Developer ID satisfies the stored requirement") {
        try withFixture(identity: identity) {
            let original = try designatedRequirement($0.app)
            try replaceExecutable($0.executable)
            try sign(
                $0.app,
                identity: identity,
                identifier: "com.automicvault.targeted-validation"
            )
            return try targetedStatus(
                app: $0.app,
                resource: $0.executable,
                requirement: original
            ) == errSecSuccess
        }
    }

    harness.check("a helper update signed by the same Developer ID satisfies its sealed requirement") {
        try withFixture(identity: identity) {
            try replaceExecutable($0.helper)
            try sign(
                $0.helper,
                identity: identity,
                identifier: "com.automicvault.targeted-validation.helper"
            )
            return try directStatus(app: $0.app, resource: $0.helper) == errSecSuccess
        }
    }

    harness.check("re-signing the app ad hoc no longer satisfies its Developer ID requirement") {
        try withFixture(identity: identity) {
            let original = try designatedRequirement($0.app)
            try sign($0.helper, identity: "-", identifier: "com.automicvault.targeted-validation.helper")
            try sign($0.app, identity: "-", identifier: "com.automicvault.targeted-validation")
            return try targetedStatus(app: $0.app, resource: $0.executable, requirement: original)
                != errSecSuccess
        }
    }

    harness.check("helper re-signed ad hoc no longer satisfies its sealed Developer ID requirement") {
        try withFixture(identity: identity) {
            try sign($0.helper, identity: "-", identifier: "com.automicvault.targeted-validation.helper")
            return try directStatus(app: $0.app, resource: $0.helper) != errSecSuccess
        }
    }
}

print("RESULT \(harness.passed) passed, \(harness.failed) failed")
exit(harness.failed == 0 ? 0 : 1)
