import AppKit

@MainActor
final class SponsorshipAppeal {
    private static let sponsorClickedKey = "sponsorshipLinkClicked"
    private static let lastShownKey = "sponsorshipAppealLastShown"
    private static let reminderInterval: TimeInterval = 30 * 24 * 60 * 60
    static let sponsorURL = URL(string: "https://github.com/sponsors/mxcl")!
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func shouldPresent(at now: Date = Date()) -> Bool {
        guard !defaults.bool(forKey: Self.sponsorClickedKey) else { return false }
        guard let lastShown = defaults.object(forKey: Self.lastShownKey) as? Date else { return true }
        return now.timeIntervalSince(lastShown) >= Self.reminderInterval
    }

    func presentIfNeeded(on window: NSWindow, hasHardenedTools: Bool) {
        guard hasHardenedTools, shouldPresent(), window.attachedSheet == nil else { return }
        defaults.set(Date(), forKey: Self.lastShownKey)
        let alert = Self.makeAlert()
        // A window sheet leaves the approval service and its separate windows running.
        alert.beginSheetModal(for: window) { [self] response in
            recordResponse(response)
            if response == .alertFirstButtonReturn {
                NSWorkspace.shared.open(Self.sponsorURL)
            }
        }
    }

    private func recordResponse(_ response: NSApplication.ModalResponse) {
        if response == .alertFirstButtonReturn {
            defaults.set(true, forKey: Self.sponsorClickedKey)
        }
    }

    static func makeAlert() -> NSAlert {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = String(localized: "Help me keep Automic Vault going")
        alert.informativeText = String(localized: "My financial situation has changed, and times are tight. If you enjoy Automic Vault, I could use a few bucks a month to help cover the costs of maintaining my open source projects.\n\nYou can sponsor me on GitHub. Thank you for using my work.\n\nMax Howell")
        alert.addButton(withTitle: String(localized: "Sponsor on GitHub"))
        alert.addButton(withTitle: String(localized: "Remind me in 30 days"))
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        if let image = NSImage(named: "SponsorshipOffice") {
            image.isTemplate = true
            let illustration = NSImageView(frame: NSRect(x: 0, y: 0, width: 420, height: 140))
            illustration.image = image
            illustration.imageScaling = .scaleProportionallyUpOrDown
            illustration.contentTintColor = .secondaryLabelColor
            illustration.setAccessibilityElement(false)
            alert.accessoryView = illustration
        }
        return alert
    }

    #if DEBUG
    static func selfCheck() -> Int32 {
        _ = NSApplication.shared
        let suite = "com.automicvault.sponsorship-test.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let appeal = SponsorshipAppeal(defaults: defaults)
        guard appeal.shouldPresent() else { return 1 }
        let shown = Date(timeIntervalSince1970: 1_800_000_000)
        defaults.set(shown, forKey: lastShownKey)
        appeal.recordResponse(.alertSecondButtonReturn)
        let restarted = SponsorshipAppeal(defaults: defaults)
        guard !restarted.shouldPresent(at: shown.addingTimeInterval(-1)),
              !restarted.shouldPresent(at: shown.addingTimeInterval(reminderInterval - 1)),
              restarted.shouldPresent(at: shown.addingTimeInterval(reminderInterval)) else { return 1 }
        appeal.recordResponse(.alertFirstButtonReturn)
        appeal.recordResponse(.alertSecondButtonReturn)
        guard !SponsorshipAppeal(defaults: defaults).shouldPresent(at: .distantFuture) else { return 1 }
        defaults.removePersistentDomain(forName: suite)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.orderFront(nil)
        appeal.presentIfNeeded(on: window, hasHardenedTools: false)
        guard window.attachedSheet == nil, appeal.shouldPresent(),
              defaults.object(forKey: lastShownKey) == nil else { return 1 }
        appeal.presentIfNeeded(on: window, hasHardenedTools: true)
        guard !appeal.shouldPresent(), let sheet = window.attachedSheet else { return 1 }
        guard !SponsorshipAppeal(defaults: defaults).shouldPresent() else { return 1 }
        appeal.presentIfNeeded(on: window, hasHardenedTools: true)
        guard window.attachedSheet === sheet else { return 1 }
        window.endSheet(sheet, returnCode: .alertSecondButtonReturn)
        window.orderOut(nil)

        if let path = ProcessInfo.processInfo.environment["AV_SPONSORSHIP_RENDER_PATH"] {
            NSApp.appearance = NSAppearance(named:
                UserDefaults.standard.string(forKey: "AppleInterfaceStyle") == "Dark" ? .darkAqua : .aqua)
            let alert = makeAlert()
            guard alert.accessoryView != nil else { return 1 }
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

