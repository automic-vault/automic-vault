import CSQLite
import Foundation
import Testing

@testable import MenubarHelperCore

@Test
func authorizationHistoryStoreRetainsMoreThanTheDashboardWindow() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<75 {
        #expect(fixture.store.append(fixture.record(index: index)))
    }

    let records = try fixture.store.records()
    #expect(records.count == 75)
    #expect(records.first?.command == "fixture 74")
    #expect(try fixture.store.records(limit: 50).count == 50)
}

@Test
func authorizationHistoryStoreFiltersAndExpiresByTime() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now)
    defer { fixture.remove() }
    let expired = fixture.record(index: 1, date: now.addingTimeInterval(-31 * 24 * 60 * 60))
    let retained = fixture.record(index: 2, date: now.addingTimeInterval(-8 * 24 * 60 * 60))
    let recent = fixture.record(index: 3, date: now.addingTimeInterval(-60 * 60))
    try fixture.store.importRecords([expired, retained])
    #expect(fixture.store.append(recent))

    #expect(try fixture.store.records().map(\.id) == [recent.id, retained.id])
    #expect(
        try fixture.store.records(since: now.addingTimeInterval(-24 * 60 * 60)).map(\.id) == [
            recent.id
        ]
    )
}

@Test
func authorizationHistoryStorePrunesOldestRecordsAtTheByteLimit() throws {
    let fixture = try HistoryStoreFixture(maximumEncryptedBytes: 1_800)
    defer { fixture.remove() }
    for index in 0..<8 {
        #expect(
            fixture.store.append(
                fixture.record(index: index, reason: String(repeating: "x", count: 500)))
        )
    }

    let records = try fixture.store.records()
    #expect(records.count < 8)
    #expect(records.first?.command == "fixture 7")
}

@Test
func authorizationHistoryStoreEncryptsContentsAndRejectsTheWrongKey() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let marker = "plaintext-history-marker-4b95e013"
    #expect(fixture.store.append(fixture.record(index: 1, reason: marker)))
    let bytes = try Data(contentsOf: fixture.url)
    #expect(bytes.range(of: Data(marker.utf8)) == nil)

    let wrongKeyStore = try AuthorizationHistoryStore(
        url: fixture.url,
        keyData: Data(repeating: 9, count: 32)
    )
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try wrongKeyStore.records()
    }
}

@Test
func authorizationHistoryStoreAuthenticatesRetentionMetadata() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let record = fixture.record(index: 1)
    #expect(fixture.store.append(record))

    var database: OpaquePointer?
    #expect(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    let sql =
        "UPDATE authorization_history SET retention_bucket = zeroblob(32) WHERE id = '\(record.id.uuidString)'"
    #expect(sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK)
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try fixture.store.records()
    }
}

@Test
func authorizationHistoryStoreImportIsIdempotentButNeverReplacesARecord() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let record = fixture.record(index: 1)
    try fixture.store.importRecords([record, record])
    #expect(try fixture.store.records() == [record])

    let altered = AccessRequestRecord(
        id: record.id,
        date: record.date,
        tool: record.tool,
        command: "altered",
        decision: record.decision,
        reason: record.reason,
        launcher: record.launcher,
        callerPath: record.callerPath,
        target: record.target,
        cwd: record.cwd,
        keys: record.keys,
        detail: record.detail
    )
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try fixture.store.importRecords([altered])
    }
    #expect(try fixture.store.records() == [record])
}

private final class HistoryStoreFixture {
    let directory: URL
    let url: URL
    let store: AuthorizationHistoryStore
    private let now: Date

    init(
        now: Date = Date(timeIntervalSince1970: 4_000_000),
        maximumEncryptedBytes: Int64 = 25 * 1024 * 1024
    ) throws {
        self.now = now
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("av-history-tests-\(UUID().uuidString)", isDirectory: true)
        url = directory.appendingPathComponent("history.sqlite3")
        store = try AuthorizationHistoryStore(
            url: url,
            keyData: Data(repeating: 7, count: 32),
            retention: AuthorizationHistoryRetention(
                maximumAge: 30 * 24 * 60 * 60,
                maximumEncryptedBytes: maximumEncryptedBytes
            ),
            now: { now }
        )
    }

    func record(index: Int, date: Date? = nil, reason: String = "Allowed") -> AccessRequestRecord {
        AccessRequestRecord(
            date: date ?? now.addingTimeInterval(TimeInterval(index)),
            tool: "fixture",
            command: "fixture \(index)",
            displayCommand: "fixture \(index)",
            decision: "Approved",
            approvalSource: "Policy",
            reason: reason,
            launcher: "Fixture",
            callerPath: "/fixture/av",
            target: "/fixture/tool",
            cwd: "/fixture",
            keys: ["SYNTHETIC_TOKEN"],
            detail: nil
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}
