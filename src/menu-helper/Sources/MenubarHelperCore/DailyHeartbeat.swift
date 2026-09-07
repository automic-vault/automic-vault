import Foundation

public enum DailyHeartbeat {
    public static let interval: TimeInterval = 24 * 60 * 60

    public static func delay(lastAttemptAt: Date?, now: Date) -> TimeInterval {
        guard let lastAttemptAt else { return 0 }
        let elapsed = now.timeIntervalSince(lastAttemptAt)
        guard elapsed >= 0 else { return 0 }
        return max(0, interval - elapsed)
    }
}
