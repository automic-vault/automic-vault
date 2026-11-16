import AppKit

@MainActor
final class SponsorshipAppeal {
    private static let suppressionKey = "hideSponsorshipAppeal"
    static let sponsorURL = URL(string: "https://github.com/sponsors/mxcl")!
    private let defaults: UserDefaults
    private var hasPresented = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var shouldPresent: Bool {
        !hasPresented && !defaults.bool(forKey: Self.suppressionKey)
    }

    func presentIfNeeded(on window: NSWindow) {
        guard shouldPresent, window.attachedSheet == nil else { return }
        hasPresented = true
        let alert = Self.makeAlert()
        // A window sheet leaves the approval service and its separate windows running.
        alert.beginSheetModal(for: window) { [self] response in
            saveSuppression(alert.suppressionButton?.state == .on)
            if response == .alertFirstButtonReturn {
                NSWorkspace.shared.open(Self.sponsorURL)
            }
        }
    }

    private func saveSuppression(_ suppressed: Bool) {
        defaults.set(suppressed, forKey: Self.suppressionKey)
    }

    static func makeAlert() -> NSAlert {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = String(localized: "Help me keep Automic Vault going")
        alert.informativeText = String(localized: "My financial situation has changed, and times are tight. If you enjoy Automic Vault, I could use a few bucks a month to help cover the costs of maintaining my open source projects.\n\nYou can sponsor me on GitHub. Thank you for using my work.\n\nMax Howell")
        alert.addButton(withTitle: String(localized: "Sponsor on GitHub"))
        alert.addButton(withTitle: String(localized: "Not now"))
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = String(localized: "Don’t show this again")
        return alert
    }

    #if DEBUG
    static func selfCheck() -> Int32 {
        _ = NSApplication.shared
        let suite = "com.automicvault.sponsorship-test.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let appeal = SponsorshipAppeal(defaults: defaults)
        guard appeal.shouldPresent else { return 1 }
        appeal.saveSuppression(false)
        guard SponsorshipAppeal(defaults: defaults).shouldPresent else { return 1 }
        appeal.saveSuppression(true)
        guard !SponsorshipAppeal(defaults: defaults).shouldPresent else { return 1 }
        appeal.saveSuppression(false)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.orderFront(nil)
        appeal.presentIfNeeded(on: window)
        guard !appeal.shouldPresent, let sheet = window.attachedSheet else { return 1 }
        appeal.presentIfNeeded(on: window)
        guard window.attachedSheet === sheet else { return 1 }
        window.endSheet(sheet, returnCode: .alertSecondButtonReturn)
        window.orderOut(nil)

        if let path = ProcessInfo.processInfo.environment["AV_SPONSORSHIP_RENDER_PATH"] {
            let alert = makeAlert()
            alert.layout()
            alert.window.center()
            alert.window.orderFront(nil)
            RunLoop.current.run(until: Date().addingTimeInterval(0.3))
            guard let view = alert.window.contentView?.superview,
                  let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return 1 }
            view.cacheDisplay(in: view.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { return 1 }
            do { try png.write(to: URL(fileURLWithPath: path)) } catch { return 1 }
            alert.window.orderOut(nil)
        }
        print("Sponsorship self-check passed")
        return 0
    }
    #endif
}

