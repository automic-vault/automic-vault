import AppKit
import CProcessInfo
import MenubarHelperCore

extension Notification.Name {
    static let sshAgentConfigurationChanged = Notification.Name("SSHAgentConfigurationChanged")
}

@MainActor
final class SSHAgentRuntime: NSObject, ObservableObject {
    static let shared = SSHAgentRuntime()
    static var isSupported: Bool { av_original_parent_tracking_available() }
    @Published private(set) var status = ""
    private var process: Process?

    func startObserving() {
        NotificationCenter.default.removeObserver(self)
        NotificationCenter.default.addObserver(self, selector: #selector(refresh),
                                              name: .sshAgentConfigurationChanged, object: nil)
        refresh()
    }

    func stop() {
        NotificationCenter.default.removeObserver(self)
        if let process, process.isRunning { process.terminate(); process.waitUntilExit() }
        process = nil
    }

    @objc private func refresh() {
        guard loadSSHAgentConfiguration().enabled else {
            if let process, process.isRunning { process.terminate(); process.waitUntilExit() }
            process = nil
            status = ""
            return
        }
        guard Self.isSupported else {
            status = "This Mac cannot verify original process ancestry. SSH Agent remains unavailable."
            return
        }
        guard process?.isRunning != true else { return }
        status = ""
        do {
            let child = Process()
            child.executableURL = try validatedBundledAVURL(mainExecutableURL: Bundle.main.executableURL)
            child.arguments = ["ssh-agent", sshAgentSocketURL().path]
            child.standardInput = FileHandle.nullDevice
            child.standardOutput = FileHandle.nullDevice
            child.environment = ["PATH": "/usr/bin:/bin", "HOME": FileManager.default.homeDirectoryForCurrentUser.path]
            let errors = Pipe()
            child.standardError = errors
            child.terminationHandler = { [weak self] child in
                let detail = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                Task { @MainActor in
                    guard let self, self.process?.processIdentifier == child.processIdentifier else { return }
                    self.status = detail.isEmpty ? "SSH Agent stopped. Disable and re-enable it to retry." : detail
                }
            }
            try child.run()
            process = child
        } catch {
            status = error.localizedDescription
        }
    }
}
