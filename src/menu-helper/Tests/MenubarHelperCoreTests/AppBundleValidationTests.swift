import Foundation
import Security
import Testing
@testable import MenubarHelperCore

@Test(.enabled(if: targetedAppResourceValidationAvailable))
func targetedAppValidationIgnoresUnrelatedResourcesAndRejectsTargetChanges() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let app = root.appendingPathComponent("Example.app", isDirectory: true)
    let contents = app.appendingPathComponent("Contents", isDirectory: true)
    let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
    let resources = contents.appendingPathComponent("Resources", isDirectory: true)
    let executable = macOS.appendingPathComponent("Example")
    let trustedResource = resources.appendingPathComponent("trusted")
    let unrelatedResource = resources.appendingPathComponent("unrelated")
    defer { try? FileManager.default.removeItem(at: root) }

    try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: executable)
    try Data("trusted".utf8).write(to: trustedResource)
    try Data("unrelated".utf8).write(to: unrelatedResource)
    try Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>Example</string>
    <key>CFBundleIdentifier</key><string>com.example.targeted-validation</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    </dict></plist>
    """.utf8).write(to: contents.appendingPathComponent("Info.plist"))
    try signValidationTestApp(app)

    #expect(appValidationStatus(app) == errSecSuccess)
    #expect(appValidationStatus(app, resource: trustedResource) == errSecSuccess)
    try Data("changed".utf8).write(to: unrelatedResource)
    #expect(appValidationStatus(app) == errSecSuccess)
    #expect(appValidationStatus(app, resource: trustedResource) == errSecSuccess)
    #expect(fullAppValidationStatus(app) != errSecSuccess)
    try Data("changed".utf8).write(to: trustedResource)
    #expect(appValidationStatus(app, resource: trustedResource) != errSecSuccess)
}

private func appValidationStatus(_ app: URL, resource: URL? = nil) -> OSStatus {
    var code: SecStaticCode?
    let creation = SecStaticCodeCreateWithPath(app as CFURL, [], &code)
    guard creation == errSecSuccess, let code else { return creation }
    if let resource {
        return validateAppBundleResource(code, resourceURL: resource)
    }
    return validateAppBundleMainExecutable(code)
}

private func fullAppValidationStatus(_ app: URL) -> OSStatus {
    var code: SecStaticCode?
    let creation = SecStaticCodeCreateWithPath(app as CFURL, [], &code)
    guard creation == errSecSuccess, let code else { return creation }
    return SecStaticCodeCheckValidity(
        code,
        SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
        nil
    )
}

private func signValidationTestApp(_ app: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    process.arguments = [
        "--force", "--sign", "-", "--options", "runtime",
        "--identifier", "com.example.targeted-validation", app.path,
    ]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw CocoaError(.executableRuntimeMismatch)
    }
}
