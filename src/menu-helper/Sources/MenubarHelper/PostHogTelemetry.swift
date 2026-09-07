#if !DEBUG
import Darwin
import Foundation
import MenubarHelperCore

final class PostHogTelemetry: @unchecked Sendable {
    static let shared = PostHogTelemetry()

    private static let installIDDefaultsKey = "PostHogAnonymousInstallID"
    private static let lastHeartbeatDefaultsKey = "PostHogLastHeartbeatAttemptAt"
    private let endpoint = URL(string: "https://us.i.posthog.com/i/v0/e/")!
    private let bundle: Bundle
    private let defaults: UserDefaults
    private let apiKey: String?

    init(bundle: Bundle = .main, defaults: UserDefaults = .standard) {
        self.bundle = bundle
        self.defaults = defaults
        self.apiKey = (bundle.object(forInfoDictionaryKey: "PostHogAPIKey") as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func captureMainWindowOpened() {
        capture("automic_vault_main_window_opened")
    }

    func captureDetectorTriggered(count: Int) {
        capture("automic_vault_detector_triggered", properties: ["count": count])
    }

    func captureExplicitApproval() {
        capture("approve")
    }

    func captureDailyHeartbeat(now: Date = Date()) -> TimeInterval {
        guard let apiKey, apiKey.isEmpty == false else { return DailyHeartbeat.interval }
        let delay = DailyHeartbeat.delay(
            lastAttemptAt: defaults.object(forKey: Self.lastHeartbeatDefaultsKey) as? Date,
            now: now
        )
        guard delay == 0 else { return delay }

        defaults.set(now, forKey: Self.lastHeartbeatDefaultsKey)
        capture("automic_vault_heartbeat", apiKey: apiKey, properties: [:])
        return DailyHeartbeat.interval
    }

    private func capture(_ event: String, properties: [String: Any] = [:]) {
        guard let apiKey, apiKey.isEmpty == false else { return }
        capture(event, apiKey: apiKey, properties: properties)
    }

    private func capture(_ event: String, apiKey: String, properties: [String: Any]) {
        let payload: [String: Any] = [
            "api_key": apiKey,
            "event": event,
            "distinct_id": anonymousInstallID(),
            "properties": eventProperties().merging(properties) { _, new in new }
        ]

        guard JSONSerialization.isValidJSONObject(payload),
              let body = try? JSONSerialization.data(withJSONObject: payload) else {
            NSLog("posthog telemetry skipped: invalid payload")
            return
        }

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        request.timeoutInterval = 5

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error {
                NSLog("posthog telemetry failed: %@", error.localizedDescription)
                return
            }

            guard let statusCode = (response as? HTTPURLResponse)?.statusCode,
                  (200..<300).contains(statusCode) else {
                let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
                NSLog("posthog telemetry failed with status: %d", statusCode)
                return
            }
        }.resume()
    }

    private func anonymousInstallID() -> String {
        if let existing = defaults.string(forKey: Self.installIDDefaultsKey),
           existing.isEmpty == false {
            return existing
        }

        let installID = UUID().uuidString
        defaults.set(installID, forKey: Self.installIDDefaultsKey)
        return installID
    }

    private func eventProperties() -> [String: Any] {
        let processInfo = ProcessInfo.processInfo
        let gibibyte = Double(1024 * 1024 * 1024)
        let physicalMemoryGB = Double(processInfo.physicalMemory) / gibibyte

        return [
            "$process_person_profile": false,
            "app_name": "Automic Vault",
            "app_version": bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
                ?? "unknown",
            "build_id": bundle.object(forInfoDictionaryKey: "NukeBuildID") as? String
                ?? "unknown",
            "protocol_version": bundle.object(forInfoDictionaryKey: "NukeProtocolVersion") as? String
                ?? "unknown",
            "helper_version": bundle.object(forInfoDictionaryKey: "NukeHelperVersion") as? String
                ?? "unknown",
            "macos_version": processInfo.operatingSystemVersionString,
            "machine_arch": machineArchitecture(),
            "mac_model": sysctlString("hw.model") ?? "unknown",
            "processor_count": processInfo.processorCount,
            "active_processor_count": processInfo.activeProcessorCount,
            "physical_memory_gb": Int(physicalMemoryGB.rounded())
        ]
    }

    private func machineArchitecture() -> String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }

    private func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else {
            return nil
        }

        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else {
            return nil
        }

        let string = value.prefix { $0 != 0 }.map(UInt8.init(bitPattern:))
        return String(decoding: string, as: UTF8.self)
    }
}
#endif
