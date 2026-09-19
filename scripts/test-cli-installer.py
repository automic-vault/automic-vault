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
fixture = r'''
import Foundation

@MainActor var bundledAVURL: URL? { nil }
''' + installer + r'''
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

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let source = root.appendingPathComponent("AV ' \" \\ $(exit 73); `exit 74`\n\r.app/Contents/MacOS/av")
let prefix = root.appendingPathComponent("prefix")
let local = prefix.appendingPathComponent("local")
let bin = local.appendingPathComponent("bin")
let destination = bin.appendingPathComponent("av")
try FileManager.default.createDirectory(at: source.deletingLastPathComponent(), withIntermediateDirectories: true)
try Data("quarantined CLI fixture".utf8).write(to: source)
let quarantine = Process()
quarantine.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
quarantine.arguments = ["-w", "com.apple.quarantine", "0083;00000000;Safari;", source.path]
try quarantine.run()
quarantine.waitUntilExit()
assert(quarantine.terminationStatus == 0)
let productionScript = cliInstallerScript(sourcePath: source.path)
assert(productionScript.contains("/usr/bin/install -S -m 0755 -o root -g wheel "))
let redirected = productionScript
    .replacingOccurrences(of: "for directory in / /usr /usr/local /usr/local/bin", with:
        "for directory in \(prefix.path) \(local.path) \(bin.path)")
    .replacingOccurrences(of: " with administrator privileges", with: "")
    .replacingOccurrences(of: " -o root -g wheel", with: "")
    .replacingOccurrences(of: "/usr/local/bin", with: bin.path)
// Test in a user-owned temporary tree; production always requires UID 0.
let script = redirected.replacingOccurrences(of: "!= 0", with: "!= \(getuid())")
for contents in ["quarantined CLI fixture", "updated CLI fixture"] {
    try Data(contents.utf8).write(to: source)
    let installed = try await runCLIInstallerScript(script)
    assert(installed)
    let installedData = try Data(contentsOf: destination)
    assert(installedData == Data(contents.utf8))
    let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
    assert((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o755)
}
// Reject a writable component before changing the installed file.
func expectUnsafe(_ script: String) async throws {
    do {
        _ = try await runCLIInstallerScript(script)
        fatalError("unsafe install directory was accepted")
    } catch CLIInstallerError.commandFailed(let message) {
        assert(message.contains("Unsafe CLI installation directory"))
    }
    let data = try Data(contentsOf: destination)
    assert(data == Data("updated CLI fixture".utf8))
}
for directory in [prefix, local, bin] {
    for mode in [0o775, 0o757] {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: directory.path)
        try await expectUnsafe(script)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
    }
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
    subprocess.run([str(binary), temporary], check=True, timeout=60)
