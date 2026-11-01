import Foundation
import Security
import Testing
@testable import MenubarHelperCore

@Test func presentationSettingsAreAClosedCatalog() {
    #expect(PresentationSetting.allCases.count == 3)
    for key in ["phoneApprovalEnabled", "gate-policy", "denial-threshold", "automaticApprovalFeedback"] {
        #expect(PresentationSetting(rawValue: key) == nil)
    }
    #expect(!PresentationSetting.compactNotifications.requiresApproval)
    #expect(PresentationSetting.feedback.requiresApproval)
    #expect(PresentationSetting.autoCollapseGrantStrip.requiresApproval)
}

@Test func visibilityStorageFailsVisibleWithoutTrustingLegacyDefaults() throws {
    for setting in [PresentationSetting.feedback, .autoCollapseGrantStrip] {
        #expect(try decodePresentationSetting(setting, result: .notFound) == setting.defaultValue)
        for value in setting.acceptedValues {
            #expect(try decodePresentationSetting(setting, result: .success(Data(value.utf8))) == value)
        }
        for result in [KeychainDataLoad.failure(errSecInteractionNotAllowed), .success(Data()),
                       .success(Data("tampered".utf8)), .success(Data([0xff]))] {
            #expect(throws: PresentationSettingsError.self) { try decodePresentationSetting(setting, result: result) }
        }
    }
}

@Test @MainActor func settingsChangeRecordsBeforeWriteAndRejectsStaleOrInvalidChanges() throws {
    var events: [String] = []
    try commitPresentationSetting(.feedback, value: "none", expected: "notification",
        read: { "notification" }, record: { events.append("record"); return true },
        write: { events.append("write:\($0)") })
    #expect(events == ["record", "write:none"])
    for (value, current, recording) in [("invalid", "notification", true), ("none", "menu-bar-flash", true),
                                      ("none", "notification", false)] {
        events = []
        #expect(throws: PresentationSettingsError.self) {
            try commitPresentationSetting(.feedback, value: value, expected: "notification",
                read: { current }, record: { events.append("record"); return recording },
                write: { _ in events.append("write") })
        }
        #expect(!events.contains("write"))
    }
    events = []
    #expect(throws: PresentationSettingsError.self) {
        try commitPresentationSetting(.feedback, value: "none", expected: "notification",
            read: { throw PresentationSettingsError.unavailable }, record: { events.append("record"); return true },
            write: { _ in events.append("write") })
    }
    #expect(events.isEmpty)
}

@Test @MainActor func cosmeticAndUnchangedSettingsDoNotRequireRecording() throws {
    var writes = 0
    try commitPresentationSetting(.compactNotifications, value: "false", expected: "true",
        read: { "true" }, record: { Issue.record("Cosmetic write requested Approval record"); return false },
        write: { _ in writes += 1 })
    try commitPresentationSetting(.feedback, value: "notification", expected: "notification",
        read: { "notification" }, record: { Issue.record("No-op requested record"); return false },
        write: { _ in Issue.record("No-op wrote storage") })
    #expect(writes == 1)
}

@Test func presentationSettingsJSONDescribesTheContract() throws {
    let snapshot = PresentationSettingSnapshot(.feedback, value: "notification")
    let json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(snapshot)) as? [String: Any])
    #expect(json["requiresApproval"] as? Bool == true)
    #expect(json["acceptedValues"] as? [String] == ["notification", "menu-bar-flash", "none"])
    #expect(json["defaultValue"] as? String == "notification")
}

@Test func settingsServiceRejectsUnknownKeysAndMalformedRequests() {
    #expect(presentationSettingsRequestIsValid(operation: .settingsList, key: nil, value: nil))
    #expect(!presentationSettingsRequestIsValid(operation: .settingsList, key: "gate-policy", value: nil))
    for setting in PresentationSetting.allCases {
        #expect(presentationSettingsRequestIsValid(operation: .settingsGet, key: setting.rawValue, value: nil))
        #expect(!presentationSettingsRequestIsValid(operation: .settingsGet, key: setting.rawValue, value: "none"))
        #expect(!presentationSettingsRequestIsValid(operation: .settingsSet, key: setting.rawValue, value: nil))
        for value in setting.acceptedValues {
            #expect(presentationSettingsRequestIsValid(operation: .settingsSet, key: setting.rawValue, value: value))
        }
        for value in ["", "1", "TRUE", "false\0true", "notification "] {
            #expect(!presentationSettingsRequestIsValid(operation: .settingsSet, key: setting.rawValue, value: value))
        }
    }
    for operation in [ApprovalServiceOperation.settingsGet, .settingsSet, .save, .list] {
        #expect(!presentationSettingsRequestIsValid(operation: operation, key: "phoneApprovalEnabled", value: "false"))
    }
}

@Test @MainActor func settingsWriteFailureNeverReportsSuccess() {
    #expect(throws: PresentationSettingsError.self) {
        try commitPresentationSetting(.feedback, value: "none", expected: "notification",
            read: { "notification" }, record: { true },
            write: { _ in throw PresentationSettingsError.unavailable })
    }
}
