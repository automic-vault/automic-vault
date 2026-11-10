import Foundation
import Security

/// A closed catalog: no arbitrary defaults or policy keys can cross this API.
/// The type and Keychain service retain their original presentation-only names.
public enum PresentationSetting: String, CaseIterable, Sendable {
    case defaultSecretAvailability = "default-secret-availability"
    case feedback = "automatic-authorization-feedback"
    case compactNotifications = "compact-notifications"
    case autoCollapseGrantStrip = "auto-collapse-grant-strip"

    public var requiresApproval: Bool { self != .compactNotifications }
    public var acceptedValues: [String] {
        if self == .defaultSecretAvailability { return ["when-unlocked", "available-while-locked"] }
        return self == .feedback ? ["notification", "menu-bar-flash", "none"] : ["true", "false"]
    }
    public var defaultValue: String {
        switch self {
        case .defaultSecretAvailability: "when-unlocked"
        case .feedback: "notification"
        case .compactNotifications: "true"
        case .autoCollapseGrantStrip: "false"
        }
    }
    public var title: String {
        switch self {
        case .defaultSecretAvailability: "Default Secret Availability"
        case .feedback: "Automic Authorization Feedback"
        case .compactNotifications: "Compact Notifications"
        case .autoCollapseGrantStrip: "Auto-collapse Temporary Access Grant Strip"
        }
    }
    public func changeDetail(from old: String, to new: String) -> String {
        if self == .defaultSecretAvailability {
            return "\(title): \(old) → \(new). New Secrets without an explicit availability choice use this setting. Existing Secrets are unchanged. Available While Locked permits authorized use after the first unlock following a restart. Availability never grants authorization."
        }
        return "\(title): \(old) → \(new). " + (self == .feedback
            ? "Controls whether policy-authorized operations show a notification, flash the menu bar, or show no feedback. Approval prompts and policy-denial notifications are unaffected."
            : "Controls whether the full grant strip collapses after five seconds. The warning tab, orange shield, and End action remain available.")
    }
}

public func presentationSettingsRequestIsValid(
    operation: ApprovalServiceOperation, key: String?, value: String?
) -> Bool {
    switch operation {
    case .settingsList: return key == nil && value == nil
    case .settingsGet: return key.flatMap(PresentationSetting.init(rawValue:)) != nil && value == nil
    case .settingsSet:
        guard let key, let setting = PresentationSetting(rawValue: key), let value else { return false }
        return setting.acceptedValues.contains(value)
    default: return false
    }
}

public struct PresentationSettingSnapshot: Encodable {
    public let key: String
    public let value: String
    public let defaultValue: String
    public let acceptedValues: [String]
    public let requiresApproval: Bool

    public init(_ setting: PresentationSetting, value: String) {
        key = setting.rawValue
        self.value = value
        defaultValue = setting.defaultValue
        acceptedValues = setting.acceptedValues
        requiresApproval = setting.requiresApproval
    }
}

public enum PresentationSettingsError: Error, LocalizedError {
    case invalidValue, unavailable, changed, recordingFailed
    public var errorDescription: String? {
        switch self {
        case .invalidValue: "Unsupported setting value."
        case .unavailable: "Settings storage is unavailable or malformed."
        case .changed: "The setting changed during review; retry the change."
        case .recordingFailed: "Authorization History is unavailable."
        }
    }
}

private let presentationSettingsService = "com.automicvault.presentation-settings.v1"
public let compactNotificationsDefaultsKey = "compactAutomaticApprovalNotifications"

public func loadPresentationSetting(_ setting: PresentationSetting) throws -> String {
    if setting == .compactNotifications {
        return (UserDefaults.standard.object(forKey: compactNotificationsDefaultsKey) as? Bool ?? true) ? "true" : "false"
    }
    // Legacy defaults are intentionally not imported: same-user software could set them.
    return try decodePresentationSetting(setting, result: loadKeychainDataResult(
        service: presentationSettingsService, account: setting.rawValue
    ))
}

func decodePresentationSetting(_ setting: PresentationSetting, result: KeychainDataLoad) throws -> String {
    switch result {
    case .notFound: return setting.defaultValue
    case .success(let data):
        guard let value = String(data: data, encoding: .utf8), setting.acceptedValues.contains(value) else {
            throw PresentationSettingsError.unavailable
        }
        return value
    case .failure: throw PresentationSettingsError.unavailable
    }
}

/// Call on the main actor after Approval; compare and save without a suspension point.
@MainActor
public func commitPresentationSetting(
    _ setting: PresentationSetting, value: String, expected: String,
    read: () throws -> String,
    record: () -> Bool,
    write: (String) throws -> Void
) throws {
    guard setting.acceptedValues.contains(value) else { throw PresentationSettingsError.invalidValue }
    guard try read() == expected else { throw PresentationSettingsError.changed }
    guard expected != value else { return }
    if setting.requiresApproval && !record() { throw PresentationSettingsError.recordingFailed }
    try write(value)
}

@MainActor
public func savePresentationSetting(_ setting: PresentationSetting, value: String) throws {
    guard setting.acceptedValues.contains(value) else { throw PresentationSettingsError.invalidValue }
    if setting == .compactNotifications {
        UserDefaults.standard.set(value == "true", forKey: compactNotificationsDefaultsKey)
    } else {
        guard saveKeychainData(Data(value.utf8), service: presentationSettingsService,
            account: setting.rawValue, accessibility: .afterFirstUnlock) == errSecSuccess else {
            throw PresentationSettingsError.unavailable
        }
    }
    guard try loadPresentationSetting(setting) == value else { throw PresentationSettingsError.unavailable }
}

/// Existing Secrets retain their availability; an explicit choice overrides only creation.
public func secretSaveAccessibility(
    existing: StoredSecretAccessibility?, requested: StoredSecretAccessibility? = nil,
    readDefault: () throws -> String = { try loadPresentationSetting(.defaultSecretAvailability) }
) throws -> StoredSecretAccessibility {
    if let existing { return existing }
    if let requested { return requested }
    switch try readDefault() {
    case "when-unlocked": return .whenUnlocked
    case "available-while-locked": return .afterFirstUnlock
    default: throw PresentationSettingsError.unavailable
    }
}

public func secretSaveAvailabilityDetail(_ accessibility: StoredSecretAccessibility, explicit: Bool) -> String {
    if explicit {
        return "All Values of this Secret will be Available While Locked, after the first unlock following a restart. Authorization is still required. If saving the Value fails after availability changes, the availability change remains."
    }
    return accessibility.isAvailableWhileLocked
        ? "Secret Availability: Available While Locked, after the first unlock following a restart. Authorization is still required."
        : "Secret Availability: When Unlocked."
}
