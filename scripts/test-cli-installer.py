#!/usr/bin/env python3
"""Check the real installer script without elevation or changing the installed CLI."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
source = (repo / "src/menu-helper/Sources/MenubarHelper/MainWindow.swift").read_text()
installer = source.split("private func cliInstallDirectoryIsProtected(", 1)[1].split(
    "@MainActor\nfunc runUpdateToolbarSelfCheck", 1
)[0]
installer = "private func cliInstallDirectoryIsProtected(" + installer
# Substitute only the elevated script input when exercising the shared completion flow.
installer = installer.replace("runCLIInstallerScript(cliInstallerScript(sourcePath: bundledAVURL.path, requirement: requirement))",
                              "runCLIInstallerScript(fixtureInstallerScript(sourcePath: bundledAVURL.path, requirement: requirement))")
# Exercise actual installed-file checks with a user-owned fixture. Parent-path
# protection is tested separately; no test acquires root or edits system paths.
state_source = "enum CLIInstallState:" + source.split("enum CLIInstallState:", 1)[1].split(
    "private func cliInstallDirectoryIsProtected(", 1)[0]
state_source = state_source.replace("metadata.st_uid == 0", "metadata.st_uid == getuid()")
state_source = state_source.replace("cliInstallDirectoryIsProtected(parent.path)", "true")
fixture = r'''
import Foundation
import Security

let installedAVCLIPath = "/unused/av"
let cliInstallationDidFinish = Notification.Name("AutomicVaultCLIInstallationDidFinish")
@MainActor var fixtureURL: URL?
@MainActor func validatedBundledAVURL(mainExecutableURL: URL?) throws -> URL {
    guard let fixtureURL else { throw CLIInstallerError.bundledCLIUnavailable }
    return fixtureURL
}
func selfTeamIdentifier() -> String? { "TESTTEAM" }
@MainActor var fixtureScript = ""
@MainActor func fixtureInstallerScript(sourcePath: String, requirement: String) -> String {
    assert(requirement.contains("TESTTEAM") && requirement.contains("anchor apple generic"))
    assert(sourcePath == "/fixture/av")
    return fixtureScript
}
@MainActor final class CompletionObserver: NSObject {
    var count = 0
    @objc func completed() { count += 1 }
}
''' + (repo / "src/menu-helper/Sources/MenubarHelperCore/GitTransport.swift").read_text().split("public let gitTransportRoot", 1)[0] + state_source + installer + r'''
@main struct InstallerCheck {
@MainActor static func main() async throws {
do {
    _ = try await installBundledCLI()
    fatalError("missing CLI was accepted")
} catch CLIInstallerError.bundledCLIUnavailable {}
assert(!isInstallingCLI)
isInstallingCLI = true
let duplicate = try await installBundledCLI()
assert(!duplicate, "overlapping install was accepted")
isInstallingCLI = false
let observer = CompletionObserver()
NotificationCenter.default.addObserver(observer, selector: #selector(CompletionObserver.completed),
    name: cliInstallationDidFinish, object: nil)
fixtureURL = URL(fileURLWithPath: "/fixture/av")
for result in ["installed", "cancelled"] {
    fixtureScript = "return \"\(result)\""
    let installed = try await installBundledCLI()
    assert(installed == (result == "installed") && !isInstallingCLI)
    assert(observer.count == 1, "completion must refresh both surfaces only after success")
}
fixtureScript = "error number 42"
do {
    _ = try await installBundledCLI()
    fatalError("failed install was accepted")
} catch CLIInstallerError.commandFailed {}
assert(observer.count == 1 && !isInstallingCLI)
NotificationCenter.default.removeObserver(observer)
fixtureURL = nil

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let source = root.appendingPathComponent("AV ' \" \\ $(exit 73); `exit 74`\n\r.app/Contents/MacOS/av")
let prefix = root.appendingPathComponent("prefix")
let local = prefix.appendingPathComponent("local")
let bin = local.appendingPathComponent("bin")
let destination = bin.appendingPathComponent("av")
try FileManager.default.createDirectory(at: source.deletingLastPathComponent(), withIntermediateDirectories: true)
try Data("quarantined CLI fixture".utf8).write(to: source)
func quarantineSource() throws {
    let quarantine = Process()
    quarantine.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
    quarantine.arguments = ["-w", "com.apple.quarantine", "0083;00000000;Safari;", source.path]
    try quarantine.run()
    quarantine.waitUntilExit()
    assert(quarantine.terminationStatus == 0)
}
let productionScript = cliInstallerScript(sourcePath: source.path, requirement: #"identifier "com.automicvault.av""#)
assert(productionScript.contains("/usr/bin/install -S -m 0755 -o root -g wheel "))
let redirected = productionScript
    .replacingOccurrences(of: "for directory in / /usr /usr/local /usr/local/bin", with:
        "for directory in \(prefix.path) \(local.path) \(bin.path)")
    .replacingOccurrences(of: " with administrator privileges", with: "")
    .replacingOccurrences(of: " -o root -g wheel", with: "")
    .replacingOccurrences(of: "/usr/local/bin", with: bin.path)
// Test in a user-owned temporary tree; production always requires UID 0.
let script = redirected.replacingOccurrences(of: "!= 0", with: "!= \(getuid())")
var expectedData = Data()
for _ in 0..<2 {
    try FileManager.default.removeItem(at: source)
    try FileManager.default.copyItem(atPath: CommandLine.arguments[2], toPath: source.path)
    let signing = Process()
    signing.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    signing.arguments = ["--force", "--sign", "-", "--identifier", "com.automicvault.av", source.path]
    try signing.run()
    signing.waitUntilExit()
    assert(signing.terminationStatus == 0)
    let sourceACL = Process()
    sourceACL.executableURL = URL(fileURLWithPath: "/bin/chmod")
    sourceACL.arguments = ["+a", "user:\(NSUserName()) allow write", source.path]
    try sourceACL.run()
    sourceACL.waitUntilExit()
    assert(sourceACL.terminationStatus == 0 && !gitTransportPathHasNoACL(source.path))
    try quarantineSource()
    expectedData = try Data(contentsOf: source)
    let installed = try await runCLIInstallerScript(script)
    assert(installed)
    let installedData = try Data(contentsOf: destination)
    assert(installedData == expectedData)
    assert(gitTransportPathHasNoACL(destination.path), "source ACL escaped staging")
    let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
    assert((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o755)
}
// The fixture is ad-hoc signed, not notarized. Installation above preserves the
// quarantined input; remove its quarantine only to run the fixture's __version.
let clearFixtureQuarantine = Process()
clearFixtureQuarantine.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
clearFixtureQuarantine.arguments = ["-d", "com.apple.quarantine", destination.path]
try clearFixtureQuarantine.run()
clearFixtureQuarantine.waitUntilExit()
assert(clearFixtureQuarantine.terminationStatus == 0)
func installedState() -> CLIInstallState {
    currentCLIInstallState(installedURL: destination, bundledURL: source, expectedRevision: 1)
}
assert(installedState() == .current)
for mode in [0o775, 0o757] {
    try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: destination.path)
    assert(installedState() == .outdated, "writable installed CLI appeared current")
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: destination.path)
    assert(installedState() == .current)
}
let fileACL = Process()
fileACL.executableURL = URL(fileURLWithPath: "/bin/chmod")
fileACL.arguments = ["+a", "user:\(NSUserName()) allow write", destination.path]
try fileACL.run()
fileACL.waitUntilExit()
assert(fileACL.terminationStatus == 0)
assert(installedState() == .outdated, "ACL-bearing installed CLI appeared current")
let clearFileACL = Process()
clearFileACL.executableURL = URL(fileURLWithPath: "/bin/chmod")
clearFileACL.arguments = ["-N", destination.path]
try clearFileACL.run()
clearFileACL.waitUntilExit()
assert(clearFileACL.terminationStatus == 0 && installedState() == .current)
// Reject a writable component before changing the installed file.
func expectUnsafe(_ script: String) async throws {
    do {
        _ = try await runCLIInstallerScript(script)
        fatalError("unsafe install directory was accepted")
    } catch CLIInstallerError.commandFailed(let message) {
        assert(message.contains("Unsafe CLI installation directory"))
    }
    let data = try Data(contentsOf: destination)
    assert(data == expectedData)
}
for directory in [prefix, local, bin] {
    for mode in [0o775, 0o757] {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: directory.path)
        try await expectUnsafe(script)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
    }
}
for directory in [prefix, local, bin] {
    let chmod = Process()
    chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
    chmod.arguments = ["+a", "user:\(NSUserName()) allow add_file,delete_child", directory.path]
    try chmod.run()
    chmod.waitUntilExit()
    assert(chmod.terminationStatus == 0)
    assert(!gitTransportPathHasNoACL(directory.path))
    try await expectUnsafe(script)
    let clear = Process()
    clear.executableURL = URL(fileURLWithPath: "/bin/chmod")
    clear.arguments = ["-N", directory.path]
    try clear.run()
    clear.waitUntilExit()
    assert(clear.terminationStatus == 0)
}
// Reject unsigned, wrong-identity, and tampered replacements before publication.
try expectedData.write(to: source)
let wrongSigner = Process()
wrongSigner.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
wrongSigner.arguments = ["--force", "--sign", "-", "--identifier", "wrong.identity", source.path]
try wrongSigner.run()
wrongSigner.waitUntilExit()
assert(wrongSigner.terminationStatus == 0)
let wrongIdentity = try Data(contentsOf: source)
var tampered = expectedData
tampered[0] = 0
for invalid in [Data("unsigned replacement".utf8), wrongIdentity, tampered] {
    try invalid.write(to: source)
    do {
        _ = try await runCLIInstallerScript(script)
        fatalError("invalid executable was installed")
    } catch CLIInstallerError.commandFailed {}
    let preserved = try Data(contentsOf: destination)
    assert(preserved == expectedData)
    let leftovers = try FileManager.default.contentsOfDirectory(atPath: bin.path)
    assert(leftovers == ["av"], "staging files leaked after validation failure")
}
// The production ownership rule rejects this otherwise protected user-owned tree.
assert(getuid() != 0, "run this regression check without root")
try await expectUnsafe(redirected)
assert(!cliInstallDirectoryIsProtected(bin.path))
assert(cliInstallDirectoryIsProtected("/usr"))
let link = root.appendingPathComponent("link")
try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/usr")
assert(!cliInstallDirectoryIsProtected(link.path))
for directory in [prefix, local, bin] {
    let saved = URL(fileURLWithPath: directory.path + "-saved")
    try FileManager.default.moveItem(at: directory, to: saved)
    try FileManager.default.createSymbolicLink(atPath: directory.path, withDestinationPath: saved.path)
    try await expectUnsafe(script)
    try FileManager.default.removeItem(at: directory)
    try FileManager.default.moveItem(at: saved, to: directory)
}
// Exercise the production cancellation handler and subprocess error propagation.
let installLine = productionScript.split(separator: "\n").first { $0.contains("do shell script") }!
let cancelledScript = productionScript.replacingOccurrences(of: String(installLine), with: "error number -128")
let cancelled = try await runCLIInstallerScript(cancelledScript)
assert(!cancelled)
for failingScript in [
    productionScript.replacingOccurrences(of: String(installLine), with: "error \"fixture failure\" number 42"),
    "return \"unexpected output\"",
] {
    do {
        _ = try await runCLIInstallerScript(failingScript)
        fatalError("install failure was swallowed")
    } catch CLIInstallerError.commandFailed(let message) {
        assert(!message.isEmpty)
    }
}
// The subprocess cannot finish until the main actor runs and creates this file.
let ready = root.appendingPathComponent("ready")
let waiting = Task {
    try await runCLIInstallerScript("""
        do shell script "for attempt in $(/usr/bin/seq 1 200); do [ -e '\(ready.path)' ] && exit 0; /bin/sleep 0.01; done; exit 1"
        return "installed"
        """)
}
try await Task.sleep(for: .milliseconds(50))
try Data().write(to: ready)
let finished = try await waiting.value
assert(finished)
print("PASS: quarantined CLI install/update, quoting, cancellation, errors, protected directories, and main actor responsiveness")
}
}
'''
with tempfile.TemporaryDirectory(prefix="av-cli-installer-") as temporary:
    test = Path(temporary) / "main.swift"
    binary = Path(temporary) / "test"
    test.write_text(fixture)
    subprocess.run(["swiftc", "-swift-version", "6", "-parse-as-library", str(test), "-o", str(binary)],
                   check=True, timeout=60)
    cli_source = Path(temporary) / "cli.swift"
    cli_binary = Path(temporary) / "fixture-cli"
    cli_source.write_text('print("1")\n')
    subprocess.run(["swiftc", str(cli_source), "-o", str(cli_binary)], check=True, timeout=60)
    subprocess.run([str(binary), temporary, str(cli_binary)], check=True, timeout=60)
