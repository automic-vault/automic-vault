import Foundation
import Testing
@testable import MenubarHelperCore

@Test func dailyHeartbeatSchedulesFromItsLastAttempt() {
    let now = Date(timeIntervalSince1970: 100_000)

    #expect(DailyHeartbeat.delay(lastAttemptAt: nil, now: now) == 0)
    #expect(
        DailyHeartbeat.delay(lastAttemptAt: now.addingTimeInterval(-86_399), now: now) == 1
    )
    #expect(DailyHeartbeat.delay(lastAttemptAt: now.addingTimeInterval(-86_400), now: now) == 0)
    #expect(DailyHeartbeat.delay(lastAttemptAt: now.addingTimeInterval(1), now: now) == 0)
}
