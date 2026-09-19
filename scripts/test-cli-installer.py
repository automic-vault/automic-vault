#!/usr/bin/env python3
"""Check the real installer script without elevation or changing the installed CLI."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
source = (repo / "src/menu-helper/Sources/MenubarHelper/MainWindow.swift").read_text()
installer = source.split("// Quote the path as AppleScript data,", 1)[1].split(
    "@MainActor\nfunc runUpdateToolbarSelfCheck", 1
)[0]
installer = "// Quote the path as AppleScript data," + installer
# Stub only the privileged execution; exercise the generated AppleScript for real below.
installer = installer.replace("NSAppleScript", "InstallerAppleScript")
fixture = r'''
import AppKit

var bundledAVURL: URL? = URL(fileURLWithPath: "/fixture/av")
@MainActor final class InstallerAppleScript {
    static let errorNumber = NSAppleScript.errorNumber
    static let errorMessage = NSAppleScript.errorMessage
    static var failure: Int?
    static var cannotPrepare = false
    static var calls = 0
    init?(source: String) {
        if Self.cannotPrepare { return nil }
        assert(source.hasSuffix("with administrator privileges"))
    }
    func executeAndReturnError(_ error: inout NSDictionary?) {
        Self.calls += 1
        if let code = Self.failure {
            error = [Self.errorNumber: code, Self.errorMessage: "fixture failure"]
        }
    }
}
''' + installer + r'''
let installed = try installBundledCLI()
assert(installed)
InstallerAppleScript.failure = -128
let canceled = try installBundledCLI()
assert(!canceled, "cancel must not report success")
InstallerAppleScript.failure = 1
do {
    _ = try installBundledCLI()
    fatalError("install failure was swallowed")
} catch {
    assert((error as NSError).code == 1)
    assert(error.localizedDescription == "fixture failure")
}
InstallerAppleScript.cannotPrepare = true
do {
    _ = try installBundledCLI()
    fatalError("invalid script was accepted")
} catch CLIInstallerError.invalidScript {}
let calls = InstallerAppleScript.calls
bundledAVURL = nil
do {
    _ = try installBundledCLI()
    fatalError("missing CLI was accepted")
} catch CLIInstallerError.bundledCLIUnavailable {}
assert(InstallerAppleScript.calls == calls)

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let source = root.appendingPathComponent("AV ' \" \\ $(exit 73); `exit 74`\n\r.app/Contents/MacOS/av")
let destination = root.appendingPathComponent("bin/av")
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
let script = productionScript
    .replacingOccurrences(of: " with administrator privileges", with: "")
    .replacingOccurrences(of: " -o root -g wheel", with: "")
    .replacingOccurrences(of: "/usr/local/bin", with: root.appendingPathComponent("bin").path)
for contents in ["quarantined CLI fixture", "updated CLI fixture"] {
    try Data(contents.utf8).write(to: source)
    var error: NSDictionary?
    NSAppleScript(source: script)!.executeAndReturnError(&error)
    assert(error == nil, "\(String(describing: error))")
    let installedData = try Data(contentsOf: destination)
    assert(installedData == Data(contents.utf8))
    let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
    assert((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o755)
}
print("PASS: quarantined CLI install/update, path quoting, cancellation, and failures")
'''
with tempfile.TemporaryDirectory(prefix="av-cli-installer-") as temporary:
    test = Path(temporary) / "main.swift"
    test.write_text(fixture)
    subprocess.run(["swift", "-swift-version", "6", str(test), temporary], check=True, timeout=60)
