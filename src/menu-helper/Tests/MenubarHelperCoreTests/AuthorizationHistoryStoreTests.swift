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
func sevenDayHistoryTransfersEveryRetainedRecordAboveOneMiB() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now)
    defer { fixture.remove() }
    let records = (1...8).map { day in
        fixture.record(index: day, date: now.addingTimeInterval(Double(-day * 86_400)),
                       reason: String(repeating: "x", count: 200_000))
    }
    try fixture.store.importRecords(records)
    let since = now.addingTimeInterval(-7 * 86_400)
    #expect(throws: AuthorizationHistoryStoreError.disclosureTooLarge) {
        try fixture.store.records(since: since, maximumDisclosureBytes: 1_048_576)
    }
    #expect(try fixture.store.records(since: now.addingTimeInterval(-3 * 86_400),
                                      maximumDisclosureBytes: 1_048_576).count == 3)
    let snapshot = try fixture.store.records(since: since).map(\.redactedForDisclosure)
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(snapshot)
    #expect(data.count > 1_048_576)
    let transfer = AuthorizationHistoryTransfer()
    #expect(transfer.begin())
    #expect(transfer.prepare(data))
    // New writes after preparation cannot change, skip, or duplicate snapshot records.
    #expect(fixture.store.append(fixture.record(index: 99)))
    var received = Data()
    while received.count < data.count {
        let chunk = try #require(transfer.next(offset: received.count))
        received.append(chunk.bytes)
    }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let result = try decoder.decode([AccessRequestRecord].self, from: received)
    #expect(result.map(\.id) == Array(records.prefix(7)).map(\.id))
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

    #expect(try fixture.store.records().count == 8)
    try fixture.store.maintain()
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
    try fixture.store.maintain()
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
    #expect(fixture.store.append(fixture.record(index: 2)))
    #expect(throws: AuthorizationHistoryStoreError.self) { try fixture.store.maintain() }
}

@Test
func authorizationHistoryStoreDefersHistoricalCorruptionToMaintenance() throws {
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
    #expect(fixture.store.append(fixture.record(index: 2)))
    #expect(throws: AuthorizationHistoryStoreError.self) { try fixture.store.maintain() }
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
func legacyHistoryImportOnlyAuthenticatesItsOwnRecords() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let corrupt = fixture.record(index: 1)
    #expect(fixture.store.append(corrupt))
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(database, "UPDATE authorization_history SET ciphertext = zeroblob(32)", nil, nil, nil) == SQLITE_OK)
    let legacy = try JSONEncoder().encode([fixture.record(index: 2)])
    try importLegacyAccessRequestRecords(keychainData: nil, defaultsData: legacy,
        into: fixture.store, readKeychain: { .notFound }, readDefaults: { legacy })
    #expect(throws: AuthorizationHistoryStoreError.self) { try fixture.store.maintain() }
    let conflicting = try JSONEncoder().encode([corrupt])
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try importLegacyAccessRequestRecords(keychainData: nil, defaultsData: conflicting,
            into: fixture.store, readKeychain: { .notFound }, readDefaults: { conflicting })
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
    try store.maintain()
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
func authorizationHistorySizeChangeDefersPruningFailure() throws {
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
    try fixture.store.setMaximumEncryptedBytes(1)
    #expect(throws: AuthorizationHistoryStoreError.self) {
        try fixture.store.maintain()
    }
    #expect(try fixture.store.records() == [record])
    #expect(!fixture.store.append(fixture.record(index: 2)))
}

@Test
func authorizationHistoryMaintenanceDoesNotBlockAppendOrDeleteNewRows() throws {
    let fixture = try HistoryStoreFixture(maximumEncryptedBytes: 1_800)
    defer { fixture.remove() }
    for index in 0..<8 { #expect(fixture.store.append(fixture.record(index: index))) }
    let newRecord = fixture.record(index: 99)
    try fixture.store.maintain(afterScan: {
        // append reacquires the same store lock; this would deadlock if maintenance retained it.
        #expect(fixture.store.append(newRecord))
    })
    #expect(try fixture.store.records().contains { $0.id == newRecord.id })
}

@Test
func authorizationHistoryMaintenanceRejectsChangedDeletionCandidate() throws {
    let fixture = try HistoryStoreFixture(maximumEncryptedBytes: 1_800)
    defer { fixture.remove() }
    for index in 0..<8 { #expect(fixture.store.append(fixture.record(index: index))) }
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try fixture.store.maintain(afterScan: {
            #expect(sqlite3_exec(database, "UPDATE authorization_history SET ciphertext = zeroblob(32)", nil, nil, nil) == SQLITE_OK)
        })
    }
    var statement: OpaquePointer?
    try #require(sqlite3_prepare_v2(database, "SELECT count(*) FROM authorization_history", -1, &statement, nil) == SQLITE_OK)
    defer { sqlite3_finalize(statement) }
    try #require(sqlite3_step(statement) == SQLITE_ROW)
    #expect(sqlite3_column_int(statement, 0) == 8)
}

@Test(arguments: [0, 600_000])
func authorizationHistoryMaintenanceBatchesReleaseTheReadBeforeAppend(reasonBytes: Int) throws {
    let fixture = try HistoryStoreFixture(maximumEncryptedBytes: 128 * 1024 * 1024)
    defer { fixture.remove() }
    let records = (0..<130).map {
        fixture.record(index: $0, date: Date(timeIntervalSince1970: 3_999_900),
                       reason: String(repeating: "x", count: reasonBytes))
    }
    try fixture.store.importRecords(records)
    let newRecord = fixture.record(index: 999)
    var batches = 0
    try fixture.store.maintain(afterScan: {}, afterBatch: {
        batches += 1
        if batches == 1 {
            // Another connection must be able to commit while authentication runs.
            let other = try AuthorizationHistoryStore(url: fixture.url, keyData: Data(repeating: 7, count: 32))
            #expect(other.append(newRecord))
            #expect(fixture.store.append(fixture.record(index: 998)))
        }
    })
    #expect(batches == (reasonBytes == 0 ? 3 : 65))
}

@Test
func authorizationHistoryMaintenanceAuthenticatesEveryBatchBeforeDeleting() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    try fixture.store.importRecords((0..<130).map { fixture.record(index: $0) })
    try fixture.store.setMaximumEncryptedBytes(1)
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    try #require(sqlite3_exec(database,
        "UPDATE authorization_history SET ciphertext = zeroblob(32) WHERE sequence = 130",
        nil, nil, nil) == SQLITE_OK)
    #expect(throws: AuthorizationHistoryStoreError.decoding) { try fixture.store.maintain() }
    var statement: OpaquePointer?
    try #require(sqlite3_prepare_v2(database, "SELECT count(*) FROM authorization_history", -1, &statement, nil) == SQLITE_OK)
    defer { sqlite3_finalize(statement) }
    try #require(sqlite3_step(statement) == SQLITE_ROW)
    #expect(sqlite3_column_int(statement, 0) == 130)
}

@Test
func authorizationHistoryNewRecordFailureStillDeniesPersistence() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(database, """
        CREATE TRIGGER corrupt_new_record AFTER INSERT ON authorization_history
        BEGIN UPDATE authorization_history SET ciphertext = zeroblob(32) WHERE id = NEW.id; END
        """, nil, nil, nil) == SQLITE_OK)
    #expect(!fixture.store.append(fixture.record(index: 1)))
    #expect(try fixture.store.records().isEmpty)
}

@Test
func authorizationHistoryMaintenanceRemovesExpiredBeforeEvictingValidRows() throws {
    let now = Date(timeIntervalSince1970: 4_000_000)
    let fixture = try HistoryStoreFixture(now: now, maximumEncryptedBytes: 1_800)
    defer { fixture.remove() }
    let retained = fixture.record(index: 1, reason: String(repeating: "x", count: 500))
    let future = fixture.record(index: 2, date: now.addingTimeInterval(3_600), reason: String(repeating: "x", count: 1_000))
    #expect(fixture.store.append(retained))
    #expect(fixture.store.append(future))
    try fixture.store.maintain()
    #expect(try fixture.store.records() == [retained])
}

@Test
func authorizationHistoryMaintenanceStopsWhenRetentionChanges() throws {
    let fixture = try HistoryStoreFixture(maximumEncryptedBytes: 1_800)
    defer { fixture.remove() }
    for index in 0..<8 { #expect(fixture.store.append(fixture.record(index: index))) }
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try fixture.store.maintain(afterScan: { try fixture.store.setMaximumEncryptedBytes(25 * 1024 * 1024) })
    }
    #expect(try fixture.store.records().count == 8)
}

@Test
func authorizationHistoryDashboardCombinesPageActivityAndDayCount() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<75 { #expect(fixture.store.append(fixture.record(index: index))) }
    let snapshot = try fixture.store.dashboard()
    #expect(snapshot.page.records == (try fixture.store.page()).records)
    #expect(snapshot.page.olderPageCursor == (try fixture.store.page()).olderPageCursor)
    #expect(snapshot.page.storedDayCount == (try fixture.store.page()).storedDayCount)
    #expect(snapshot.activityRecords == (try fixture.store.records()))
    var batches = 0
    _ = try fixture.store.dashboard(previous: snapshot, afterBatch: { batches += 1 })
    #expect(batches == 0)
    #expect(fixture.store.append(fixture.record(index: 76)))
    let updated = try fixture.store.dashboard(previous: snapshot, afterBatch: { batches += 1 })
    #expect(batches == 1)
    #expect(updated.page.records == (try fixture.store.page()).records)
    #expect(updated.activityRecords == (try fixture.store.records()))
}

@Test
func authorizationHistoryDashboardYieldsToAppendAndBoundsItsScan() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    #expect(fixture.store.append(fixture.record(index: 1)))
    let concurrent = fixture.record(index: 2)
    let snapshot = try fixture.store.dashboard(previous: nil, afterBatch: {
        #expect(fixture.store.append(concurrent))
    })
    #expect(!snapshot.page.records.contains(concurrent))
    let updated = try fixture.store.dashboard(previous: snapshot)
    #expect(updated.page.records.first == concurrent)
}

@Test
func authorizationHistoryDashboardInvalidatesAfterMaintenance() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<8 { #expect(fixture.store.append(fixture.record(index: index))) }
    let snapshot = try fixture.store.dashboard()
    try fixture.store.setMaximumEncryptedBytes(1_800)
    try fixture.store.maintain()
    let updated = try fixture.store.dashboard(previous: snapshot)
    #expect(updated.page.records.count < snapshot.page.records.count)
    #expect(updated.page.records == (try fixture.store.records()))
}

@Test
func authorizationHistoryDashboardRejectsCorruptionOnExplicitRefreshAndDisclosure() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    #expect(fixture.store.append(fixture.record(index: 1)))
    let snapshot = try fixture.store.dashboard()
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(sqlite3_exec(database, "UPDATE authorization_history SET ciphertext = zeroblob(32)", nil, nil, nil) == SQLITE_OK)
    #expect(throws: AuthorizationHistoryStoreError.self) { try fixture.store.dashboard() }
    #expect(throws: AuthorizationHistoryStoreError.self) { try fixture.store.records() }
    #expect(throws: AuthorizationHistoryStoreError.self) { try fixture.store.dashboard(previous: snapshot) }
}

@Test
func authorizationHistoryDashboardRefreshesAfterImportAndOverlappingMaintenance() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let original = fixture.record(index: 1)
    try #require(fixture.store.append(original))
    let snapshot = try fixture.store.dashboard()
    let replacement = fixture.record(index: 2, reason: "Imported")
    try fixture.store.importRecords([replacement])
    #expect(try fixture.store.dashboard(previous: snapshot).page.records == [replacement, original])
    for index in 3..<8 { try #require(fixture.store.append(fixture.record(index: index))) }
    try fixture.store.setMaximumEncryptedBytes(1_800)
    let refreshed = try fixture.store.dashboard(previous: nil, afterBatch: { try fixture.store.maintain() })
    #expect(refreshed.page.records == (try fixture.store.records()))
    #expect(refreshed.page.records.count < 8)
}

@Test
func authorizationHistoryDashboardRetryStillRejectsCorruption() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<8 { try #require(fixture.store.append(fixture.record(index: index))) }
    try fixture.store.setMaximumEncryptedBytes(1_800)
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(throws: AuthorizationHistoryStoreError.decoding) {
        try fixture.store.dashboard(previous: nil, afterBatch: {
            try fixture.store.maintain()
            try #require(sqlite3_exec(database,
                "UPDATE authorization_history SET ciphertext = zeroblob(32)", nil, nil, nil) == SQLITE_OK)
        })
    }
}

@Test
func authorizationHistoryDashboardRescansAfterOneMinuteAndFiltersExpiredRecords() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    let clock = HistoryDashboardClock()
    let store = try AuthorizationHistoryStore(url: fixture.url, keyData: Data(repeating: 7, count: 32),
        now: { clock.read() })
    let recent = fixture.record(index: 1)
    let expiring = fixture.record(index: 2, date: clock.read().addingTimeInterval(-30 * 86_400 + 60))
    try #require(store.append(expiring))
    try #require(store.append(recent))
    let snapshot = try store.dashboard()
    clock.advance(59)
    var batches = 0
    let delta = try store.dashboard(previous: snapshot, afterBatch: { batches += 1 })
    #expect(batches == 0)
    clock.advance(1)
    let refreshed = try store.dashboard(previous: delta, afterBatch: { batches += 1 })
    #expect(batches == 1)
    #expect(refreshed.page.records.count == 2)
    clock.advance(1)
    let expired = try store.dashboard(previous: refreshed)
    #expect(expired.page.records == [recent])
    #expect(expired.page.storedDayCount == 1)
    #expect(expired.activityRecords == [recent])
}

private final class HistoryDashboardClock: @unchecked Sendable {
    private let lock = NSLock()
    private var date = Date(timeIntervalSince1970: 4_000_000)
    func read() -> Date { lock.withLock { date } }
    func advance(_ seconds: TimeInterval) { lock.withLock { date.addTimeInterval(seconds) } }
}

@Test
func authorizationHistoryDashboardReadsOnlyNewRowsOnIncrementalRefresh() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<1_000 {
        try #require(fixture.store.append(fixture.record(index: index,
            date: Date(timeIntervalSince1970: 3_999_900), reason: String(repeating: "x", count: 2_000))))
    }
    let start = Date()
    _ = try fixture.store.page()
    _ = try fixture.store.records(since: Date(timeIntervalSince1970: 4_000_000 - 86_400))
    let oldSeconds = Date().timeIntervalSince(start)
    let snapshot = try fixture.store.dashboard()
    try #require(fixture.store.append(fixture.record(index: 1_001, date: Date(timeIntervalSince1970: 3_999_950))))
    var batches = 0
    let deltaStart = Date()
    let updated = try fixture.store.dashboard(previous: snapshot, afterBatch: { batches += 1 })
    let deltaSeconds = Date().timeIntervalSince(deltaStart)
    #expect(batches == 1)
    #expect(updated.activityRecords.count == 1_001)
    print("History dashboard benchmark, 1000 records: old dual scan=\(oldSeconds)s, incremental=\(deltaSeconds)s")
}

@Test
func authorizationHistoryReadYieldsToAppendsAndKeepsItsBoundary() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<130 {
        try #require(fixture.store.append(fixture.record(index: index, date: Date(timeIntervalSince1970: 3_999_900))))
    }
    var batches = 0
    let page = try fixture.store.readRecords(since: nil, limit: nil, maximumDisclosureBytes: nil,
        beforeSequence: nil, afterBatch: {
            batches += 1
            // This would deadlock if decryption still held the append lock.
            try #require(fixture.store.append(fixture.record(index: 200 + batches,
                date: Date(timeIntervalSince1970: 3_999_950))))
        })
    #expect(batches == 3)
    #expect(page.records.map(\.command) == (0..<130).reversed().map { "fixture \($0)" })
    #expect(try fixture.store.records().count == 133)
}

@Test
func authorizationHistoryReadCancelsBetweenBatchesWithoutReturningPartialData() throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<75 { try #require(fixture.store.append(fixture.record(index: index))) }
    var canceled = false
    var batches = 0
    #expect(throws: CancellationError.self) {
        try fixture.store.readRecords(since: nil, limit: nil, maximumDisclosureBytes: nil,
            beforeSequence: nil, isCanceled: { canceled }, afterBatch: {
                batches += 1
                canceled = true
            })
    }
    #expect(batches == 1)
    #expect(throws: CancellationError.self) { try fixture.store.records(isCanceled: { true }) }
}

@Test(arguments: [nil, 1] as [Int?])
func authorizationHistoryReadRejectsExternalMutationEvenOnLimitedReads(limit: Int?) throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    try #require(fixture.store.append(fixture.record(index: 1)))
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try fixture.store.readRecords(since: nil, limit: limit, maximumDisclosureBytes: nil,
            beforeSequence: nil, afterBatch: {
                try #require(sqlite3_exec(database,
                    "UPDATE authorization_history SET ciphertext = zeroblob(32)", nil, nil, nil) == SQLITE_OK)
            })
    }
}

@Test(arguments: [false, true])
func authorizationHistoryReadRejectsOverlappingImportOrMaintenance(maintenance: Bool) throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    for index in 0..<8 { try #require(fixture.store.append(fixture.record(index: index))) }
    try fixture.store.setMaximumEncryptedBytes(1_800)
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) {
        try fixture.store.readRecords(since: nil, limit: 1, maximumDisclosureBytes: nil,
            beforeSequence: nil, afterBatch: {
                if maintenance { try fixture.store.maintain() }
                else { try fixture.store.importRecords([fixture.record(index: 9)]) }
            })
    }
}

@Test(arguments: [Int64.min, -1, 0])
func authorizationHistoryReadRejectsInvalidSequenceBoundaries(sequence: Int64) throws {
    let fixture = try HistoryStoreFixture()
    defer { fixture.remove() }
    try #require(fixture.store.append(fixture.record(index: 1)))
    var database: OpaquePointer?
    try #require(sqlite3_open(fixture.url.path, &database) == SQLITE_OK)
    defer { sqlite3_close(database) }
    try #require(sqlite3_exec(database,
        "UPDATE authorization_history SET sequence = \(sequence)", nil, nil, nil) == SQLITE_OK)
    #expect(throws: AuthorizationHistoryStoreError.verificationFailed) { try fixture.store.records() }
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["AV_HISTORY_BENCHMARK"] == "1"))
func authorizationHistoryMaintenanceBenchmark() throws {
    let fixture = try HistoryStoreFixture(maximumEncryptedBytes: 64 * 1024 * 1024)
    defer { fixture.remove() }
    let date = Date(timeIntervalSince1970: 3_999_900)
    try fixture.store.importRecords((0..<16_273).map {
        fixture.record(index: $0, date: date, reason: String(repeating: "x", count: 1_800))
    })
    for _ in 0..<3 {
        let start = clock()
        try fixture.store.maintain()
        let seconds = Double(clock() - start) / Double(CLOCKS_PER_SEC)
        print("History maintenance: 16273 rows, \(seconds) CPU seconds")
        if let budget = ProcessInfo.processInfo.environment["AV_HISTORY_CPU_BUDGET"].flatMap(Double.init) {
            #expect(seconds < budget)
        }
    }
    try fixture.store.setMaximumEncryptedBytes(25 * 1024 * 1024)
    let start = clock()
    try fixture.store.maintain()
    print("History pruning to 25 MiB: \(Double(clock() - start) / Double(CLOCKS_PER_SEC)) CPU seconds")
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
