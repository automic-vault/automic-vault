import Darwin
import Foundation
import Security
import Testing
@testable import MenubarHelperCore

private struct LiveValidationFixture {
    let root: URL
    let app: URL
    let executable: URL
    let process = Process()
    let input = Pipe()
    let output = Pipe()

    init(helper: Bool = false) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("av-live-validation-\(UUID().uuidString)")
        app = root.appendingPathComponent("Probe.app")
        executable = app.appendingPathComponent(helper ? "Contents/Helpers/Probe" : "Contents/MacOS/Probe")
        try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
        do {
            let source = root.appendingPathComponent("probe.c")
            try Data("""
            #include <stdio.h>
            #include <unistd.h>
            __attribute__((section("__TEXT,__avprobe")))
            const volatile unsigned char payload[32 * 1024 * 1024] = "AV_LIVE_VALIDATION_PAYLOAD";
            int main(void) {
                setbuf(stdout, NULL);
                puts("ready");
                int c;
                while ((c = getchar()) != EOF) {
                    if (c == 't') printf("%u\\n", payload[24 * 1024 * 1024]);
                    if (c == 'e') { execl("/bin/sleep", "sleep", "30", NULL); return 2; }
                }
                return 0;
            }
            """.utf8).write(to: source)
            try Self.run("/usr/bin/xcrun", ["clang", "-O0", source.path, "-o", executable.path])
            let plist: [String: String] = ["CFBundleExecutable": "Probe", "CFBundleIdentifier": "com.automicvault.live-validation", "CFBundlePackageType": "APPL"]
            try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
                .write(to: app.appendingPathComponent("Contents/Info.plist"))
            let identity = ProcessInfo.processInfo.environment["AV_TEST_SIGNING_IDENTITY"] ?? "-"
            if helper {
                let main = app.appendingPathComponent("Contents/MacOS/Probe")
                try FileManager.default.createDirectory(at: main.deletingLastPathComponent(), withIntermediateDirectories: true)
                try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: main)
                try Self.run("/usr/bin/codesign", ["--force", "--sign", identity, "--timestamp=none", "--options", "runtime", "--identifier", "com.automicvault.live-validation.helper", executable.path])
            }
            try Self.run("/usr/bin/codesign", ["--force", "--sign", identity, "--timestamp=none", "--options", "runtime", app.path])
            process.executableURL = executable
            process.standardInput = input
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            try process.run()
            guard try response() == "ready" else { throw CocoaError(.executableRuntimeMismatch) }
        } catch {
            cleanup()
            throw error
        }
    }

    static func run(_ path: String, _ arguments: [String]) throws {
        let command = Process()
        command.executableURL = URL(fileURLWithPath: path)
        command.arguments = arguments
        try command.run()
        command.waitUntilExit()
        guard command.terminationStatus == 0 else { throw CocoaError(.executableRuntimeMismatch) }
    }

    func response() throws -> String {
        var descriptor = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, 5_000) > 0 else { throw CocoaError(.fileReadUnknown) }
        var bytes = [UInt8](repeating: 0, count: 128)
        let count = read(descriptor.fd, &bytes, bytes.count)
        return count > 0 ? String(decoding: bytes.prefix(count), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) : ""
    }

    func identity() -> Data? {
        liveExecutableCodeIdentity(pid: process.processIdentifier, executableURL: executable)
    }

    func cleanup() {
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate(); process.waitUntilExit() }
        try? FileManager.default.removeItem(at: root)
    }
}

@Test func liveExecutableRejectsDifferentFileAndExitedProcess() throws {
    let fixture = try LiveValidationFixture()
    defer { fixture.cleanup() }
    #expect(fixture.identity() != nil)
    #expect(liveExecutableCodeIdentity(pid: fixture.process.processIdentifier, executableURL: URL(fileURLWithPath: "/bin/sleep")) == nil)
    fixture.process.terminate()
    fixture.process.waitUntilExit()
    #expect(fixture.identity() == nil)
}

@Test func liveExecutableFreshLookupRejectsExecAndPathReplacement() throws {
    let fixture = try LiveValidationFixture()
    defer { fixture.cleanup() }
    let original = try #require(fixture.identity())
    let saved = fixture.root.appendingPathComponent("Original.app")
    try FileManager.default.moveItem(at: fixture.app, to: saved)
    try FileManager.default.createDirectory(at: fixture.executable.deletingLastPathComponent(), withIntermediateDirectories: true)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/sleep"), to: fixture.executable)
    #expect(fixture.identity() == nil)
    try FileManager.default.removeItem(at: fixture.app)
    try FileManager.default.moveItem(at: saved, to: fixture.app)
    #expect(fixture.identity() == original)
    try fixture.input.fileHandleForWriting.write(contentsOf: Data("e".utf8))
    var requirement: SecRequirement?
    try #require(SecRequirementCreateWithString("identifier com.apple.sleep and anchor apple" as CFString, [], &requirement) == errSecSuccess)
    let expected = try #require(requirement)
    func runningSleep() -> Bool {
        var live: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: NSNumber(value: fixture.process.processIdentifier)] as CFDictionary, [], &live) == errSecSuccess,
              let live else { return false }
        return SecCodeCheckValidity(live, [], expected) == errSecSuccess
    }
    for _ in 0..<100 {
        if runningSleep() { break }
        usleep(10_000)
    }
    #expect(runningSleep())
    #expect(fixture.identity() == nil)
}

@Test func liveExecutableReliesOnKernelForUnreadPageIntegrity() throws {
    let fixture = try LiveValidationFixture()
    defer { fixture.cleanup() }
    let original = try #require(fixture.identity())
    let bytes = try Data(contentsOf: fixture.executable)
    let marker = try #require(bytes.range(of: Data("AV_LIVE_VALIDATION_PAYLOAD".utf8)))
    let file = try FileHandle(forWritingTo: fixture.executable)
    try file.seek(toOffset: UInt64(marker.lowerBound + 24 * 1024 * 1024))
    try file.write(contentsOf: Data([255]))
    try file.close()
    #expect(fixture.identity() == original)
    var disk: SecStaticCode?
    try #require(SecStaticCodeCreateWithPath(fixture.executable as CFURL, [], &disk) == errSecSuccess)
    #expect(SecStaticCodeCheckValidity(try #require(disk), [], nil) != errSecSuccess)
    try fixture.input.fileHandleForWriting.write(contentsOf: Data("t".utf8))
    let response = try fixture.response()
    // A cached original page is safe too; the modified byte must never be readable.
    if response == "0" {
        #expect(fixture.identity() == original)
        return
    }
    try #require(response == "", "Modified signed page became readable: \(response)")
    for _ in 0..<100 {
        if !fixture.process.isRunning { break }
        usleep(10_000)
    }
    try #require(!fixture.process.isRunning)
    fixture.process.waitUntilExit()
    #expect(fixture.process.terminationReason == .uncaughtSignal)
    #expect(fixture.process.terminationStatus == SIGKILL)
    #expect(fixture.identity() == nil)
}

@Test func liveExecutableIdentityDoesNotReplaceBundleSealValidation() throws {
    let fixture = try LiveValidationFixture(helper: true)
    defer { fixture.cleanup() }
    let original = try #require(fixture.identity())
    func bundleStatus() throws -> OSStatus {
        var disk: SecStaticCode?
        try #require(SecStaticCodeCreateWithPath(fixture.app as CFURL, [], &disk) == errSecSuccess)
        return validateAppBundleResource(try #require(disk), resourceURL: fixture.executable)
    }
    #expect(try bundleStatus() == errSecSuccess)
    try Data("corrupt".utf8).write(to: fixture.app.appendingPathComponent("Contents/_CodeSignature/CodeResources"))
    #expect(fixture.identity() == original)
    #expect(try bundleStatus() != errSecSuccess)
}

@Test func liveExecutableRejectsChangedSignedMetadata() throws {
    let fixture = try LiveValidationFixture()
    defer { fixture.cleanup() }
    try #require(fixture.identity() != nil)
    try Data("corrupt".utf8).write(to: fixture.app.appendingPathComponent("Contents/Info.plist"))
    #expect(fixture.identity() == nil)
}
