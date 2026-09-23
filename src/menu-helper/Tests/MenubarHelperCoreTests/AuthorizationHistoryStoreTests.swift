import CSQLite
import Foundation
import Testing

@testable import MenubarHelperCore

@Test
func authorizationHistoryStoreRetainsMoreThanTheFirstDashboardPage() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<75 {
        #expect(fixture.store.append(fixture.record(index: index)))
    }

    let records = try fixture.store.records()
    #expect(records.count == 75)
    #expect(records.first?.command == "fixture 74")
    #expect(try fixture.store.records(limit: 50).count == 50)
    #expect(throws: AuthorizationHistoryStoreError.invalidLimit) {
        try fixture.store.records(limit: 0)
    }
    #expect(throws: AuthorizationHistoryStoreError.invalidLimit) {
        try fixture.store.records(limit: -1)
    }
}

@Test
func authorizationHistoryPagesReachEveryRecordAcrossNewWrites() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<75 {
        #expect(fixture.store.append(fixture.record(index: index)))
    }
    let first = try fixture.store.page(limit: 25)
    #expect(first.records.map(\.command) == (50..<75).reversed().map { "fixture \($0)" })
    #expect(fixture.store.append(fixture.record(index: 75)))
    let second = try fixture.store.page(beforeSequence: first.olderPageCursor, limit: 25)
    let third = try fixture.store.page(beforeSequence: second.olderPageCursor, limit: 25)
    let fourth = try fixture.store.page(beforeSequence: third.olderPageCursor, limit: 25)
    #expect((first.records + second.records + third.records).count == 75)
    #expect(second.records.map(\.command) == (25..<50).reversed().map { "fixture \($0)" })
    #expect(third.records.map(\.command) == (0..<25).reversed().map { "fixture \($0)" })
    #expect(fourth.records.isEmpty)
    #expect(fourth.olderPageCursor == nil)
    #expect(throws: AuthorizationHistoryStoreError.invalidLimit) {
        try fixture.store.page(beforeSequence: 0)
    }
}

@Test
func firstAuthorizationHistoryPageCountsEveryStoredDay() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now)
    defer { fixture.remove() }
    for (index, daysAgo) in [0, 0, 1, 3].enumerated() {
        #expect(fixture.store.append(fixture.record(
            index: index,
            date: now.addingTimeInterval(TimeInterval(-daysAgo * 86_400))
        )))
    }

    let first = try fixture.store.page(limit: 1)
    #expect(first.records.count == 1)
    #expect(first.storedDayCount == 3)
    #expect(try fixture.store.page(beforeSequence: first.olderPageCursor, limit: 1).storedDayCount == nil)
}

@Test
func authorizationHistoryStoreBoundsDisclosureDuringRead() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<3 {
        #expect(fixture.store.append(fixture.record(index: index)))
    }
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys]
    let records = try fixture.store.records()
    let bytes = try encoder.encode(records.map(\.redactedForDisclosure)).count
    #expect(try fixture.store.records(maximumDisclosureBytes: bytes).count == 3)
    #expect(throws: AuthorizationHistoryStoreError.disclosureTooLarge) {
        try fixture.store.records(maximumDisclosureBytes: bytes - 1)
    }
}

@Test
func productionAuthorizationHistoryStoreRetriesFailedOpen() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    var attempts = 0
    let holder = ProductionAuthorizationHistoryStore {
        attempts += 1
        return attempts == 1 ? nil : fixture.store
    }
    #expect(holder.get() == nil)
    #expect(holder.get() === fixture.store)
    #expect(holder.get() === fixture.store)
    #expect(attempts == 2)
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
    let firstPage = try fixture.store.page(limit: 1)
    #expect(firstPage.records.map(\.id) == [recent.id])
    let secondPage = try fixture.store.page(beforeSequence: firstPage.olderPageCursor, limit: 1)
    #expect(secondPage.records.map(\.id) == [retained.id])
    #expect(try fixture.store.page(beforeSequence: secondPage.olderPageCursor, limit: 1).records.isEmpty)
}

@Test
func authorizationHistoryStoreNeverDisclosesFutureRecordsBeforeMaintenance() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now)
    defer { fixture.remove() }
    #expect(fixture.store.append(
        fixture.record(index: 1, date: now.addingTimeInterval(3_600))
    ))
    #expect(try fixture.store.records().isEmpty)
    try fixture.store.maintain()
    #expect(try fixture.store.records().isEmpty)
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
func authorizationHistoryStoreEvictsByRecordDateNotCommitOrder() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now, maximumEncryptedBytes: 1_800)
    defer { fixture.remove() }
    let newer = fixture.record(index: 1, date: now.addingTimeInterval(-3_600),
                               reason: String(repeating: "x", count: 500))
    let older = fixture.record(index: 2, date: now.addingTimeInterval(-10_800),
                               reason: String(repeating: "x", count: 500))
    let middle = fixture.record(index: 3, date: now.addingTimeInterval(-7_200),
                                reason: String(repeating: "x", count: 500))
    #expect(fixture.store.append(newer))
    #expect(fixture.store.append(older))
    #expect(fixture.store.append(middle))
    #expect(Set(try fixture.store.records().map(\.id)) == Set([newer.id, middle.id]))
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
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try fixture.store.records(since: Date(timeIntervalSince1970: 4_000_000 - 60))
    }
}

@Test
func authorizationHistoryStoreRejectsCorruptRecordIDWithoutTrapping() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    #expect(fixture.store.append(fixture.record(index: 1)))

    var database: OpaquePointer?
    #expect(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(
        database,
        "UPDATE authorization_history SET id = CAST(x'80' AS TEXT)",
        nil, nil, nil
    ) == SQLITE_OK)
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try fixture.store.records()
    }
    #expect(!fixture.store.append(fixture.record(index: 2)))
}

@Test
func authorizationHistoryStoreRejectsCorruptCiphertextBeforeAppend() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    #expect(fixture.store.append(fixture.record(index: 1)))

    var database: OpaquePointer?
    #expect(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(
        database,
        "UPDATE authorization_history SET ciphertext = zeroblob(32)",
        nil, nil, nil
    ) == SQLITE_OK)
    #expect(!fixture.store.append(fixture.record(index: 2)))
}

@Test
func authorizationHistoryStorePrunesFutureRecordsInTheCurrentHour() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now)
    defer { fixture.remove() }
    try fixture.store.importRecords([
        fixture.record(index: 1, date: now.addingTimeInterval(60))
    ])
    #expect(try fixture.store.records().isEmpty)
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

@Test
func authorizationHistoryStoreFiltersExpiredRowsAndMaintainsOnDemand() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now)
    defer { fixture.remove() }
    #expect(fixture.store.append(fixture.record(index: 0)))

    let later = now.addingTimeInterval(30 * 24 * 60 * 60 + 1)
    let reopened = try AuthorizationHistoryStore(
        url: fixture.url,
        keyData: Data(repeating: 7, count: 32),
        now: { later }
    )
    #expect(try reopened.records().isEmpty)
    try reopened.maintain()

    var database: OpaquePointer?
    guard sqlite3_open(fixture.url.path, &database) == SQLITE_OK else {
        throw AuthorizationHistoryStoreError.sqlite("test database open failed")
    }
    defer { sqlite3_close(database) }
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(
        database, "SELECT count(*) FROM authorization_history", -1, &statement, nil
    ) == SQLITE_OK else {
        throw AuthorizationHistoryStoreError.sqlite("test count query failed")
    }
    defer { sqlite3_finalize(statement) }
    #expect(sqlite3_step(statement) == SQLITE_ROW)
    #expect(sqlite3_column_int(statement, 0) == 0)
}

@Test
func legacyDefaultsHistoryIsImportedOnlyWhenValid() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let record = fixture.record(index: 1)
    let data = try JSONEncoder().encode([record])

    try importLegacyAccessRequestRecords(
        keychainData: nil,
        defaultsData: data,
        into: fixture.store,
        readKeychain: { .notFound },
        readDefaults: { data }
    )
    #expect(try fixture.store.records() == [record])
    #expect(throws: DecodingError.self) {
        try importLegacyAccessRequestRecords(
            keychainData: nil,
            defaultsData: Data("malformed".utf8),
            into: fixture.store,
            readKeychain: { .notFound },
            readDefaults: { nil }
        )
    }
    #expect(try fixture.store.records() == [record])
    let outOfRange = fixture.record(index: 2, date: Date(timeIntervalSince1970: 1e24))
    let outOfRangeData = try JSONEncoder().encode([outOfRange])
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try importLegacyAccessRequestRecords(
            keychainData: nil,
            defaultsData: outOfRangeData,
            into: fixture.store,
            readKeychain: { .notFound },
            readDefaults: { outOfRangeData }
        )
    }
    #expect(try fixture.store.records() == [record])
}

@Test
func legacyHistoryImportFailsWhenAuthenticationFails() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    #expect(fixture.store.append(fixture.record(index: 1)))
    var database: OpaquePointer?
    #expect(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(
        database,
        "UPDATE authorization_history SET ciphertext = zeroblob(32)",
        nil, nil, nil
    ) == SQLITE_OK)

    let legacy = try JSONEncoder().encode([fixture.record(index: 2)])
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try importLegacyAccessRequestRecords(
            keychainData: nil,
            defaultsData: legacy,
            into: fixture.store,
            readKeychain: { .notFound },
            readDefaults: { legacy }
        )
    }
}

@Test
func changedLegacyHistoryAbortsImportAndCanBeRetried() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let original = fixture.record(index: 1)
    let snapshot = try JSONEncoder().encode([original])
    let changed = try JSONEncoder().encode([
        fixture.record(index: 1, reason: "Changed", id: original.id)
    ])
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try importLegacyAccessRequestRecords(
            keychainData: nil,
            defaultsData: snapshot,
            into: fixture.store,
            readKeychain: { .notFound },
            readDefaults: { changed }
        )
    }
    #expect(try fixture.store.records().isEmpty)
    try importLegacyAccessRequestRecords(
        keychainData: nil,
        defaultsData: changed,
        into: fixture.store,
        readKeychain: { .notFound },
        readDefaults: { changed }
    )
    #expect(try fixture.store.records().first?.reason == "Changed")
}

@Test
func newlyCreatedLegacyHistoryAbortsMigration() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let newData = try JSONEncoder().encode([fixture.record(index: 1)])
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try importLegacyAccessRequestRecords(
            keychainData: nil,
            defaultsData: nil,
            into: fixture.store,
            readKeychain: { .success(newData) },
            readDefaults: { nil }
        )
    }
    #expect(try fixture.store.records().isEmpty)
}

@Test
func authorizationHistorySizePreferenceDefaultsAndValidates() throws {
    let suite = "history-size-\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    #expect(AuthorizationHistoryRetention.configuredSizeMiB(defaults: defaults) == 25)
    #expect(AuthorizationHistoryRetention.standard.maximumEncryptedBytes == 25 * 1024 * 1024)
    for value in [0, -1, 1025, Int.max] {
        defaults.set(value, forKey: AuthorizationHistoryRetention.sizeDefaultsKey)
        #expect(AuthorizationHistoryRetention.configuredSizeMiB(defaults: defaults) == 25)
    }
    for value in [1, 50, 1024] {
        defaults.set(value, forKey: AuthorizationHistoryRetention.sizeDefaultsKey)
        #expect(AuthorizationHistoryRetention.configuredSizeMiB(defaults: defaults) == value)
    }
}

@Test
func productionAuthorizationHistorySizeChangesReachCachedStore() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let suite = "history-size-\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let holder = ProductionAuthorizationHistoryStore(defaults: defaults) { fixture.store }
    let store = try #require(holder.get())
    let older = fixture.record(index: 1, reason: String(repeating: "a", count: 600_000))
    let newer = fixture.record(index: 2, reason: String(repeating: "b", count: 600_000))
    #expect(store.append(older))
    #expect(store.append(newer))
    defaults.set(1, forKey: AuthorizationHistoryRetention.sizeDefaultsKey)
    #expect(holder.get() === store)
    #expect(try store.records().map(\.id) == [newer.id])
    let larger = fixture.record(index: 3, reason: String(repeating: "c", count: 1_100_000))
    #expect(!store.append(larger))
    defaults.set(2, forKey: AuthorizationHistoryRetention.sizeDefaultsKey)
    #expect(holder.get() === store)
    #expect(store.append(larger))
    #expect(try store.records().map(\.id) == [larger.id, newer.id])
    #expect(throws: AuthorizationHistoryStoreError.invalidLimit) {
        try store.setMaximumEncryptedBytes(0)
    }
}

@Test
func authorizationHistorySizeChangeRollsBackOnPruningFailure() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let record = fixture.record(index: 1)
    #expect(fixture.store.append(record))
    var database: OpaquePointer?
    #expect(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(database, """
        CREATE TRIGGER reject_history_delete BEFORE DELETE ON authorization_history
        BEGIN SELECT RAISE(ABORT, 'test deletion failure'); END
        """, nil, nil, nil) == SQLITE_OK)
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try fixture.store.setMaximumEncryptedBytes(1)
    }
    #expect(try fixture.store.records() == [record])
    #expect(fixture.store.append(fixture.record(index: 2)))
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

    func record(
        index: Int,
        date: Date? = nil,
        reason: String = "Allowed",
        id: UUID = UUID()
    ) -> AccessRequestRecord {
        AccessRequestRecord(
            id: id,
            date: date ?? now.addingTimeInterval(TimeInterval(index) - 100),
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
