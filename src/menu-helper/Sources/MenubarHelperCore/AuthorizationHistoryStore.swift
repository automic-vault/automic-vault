import CSQLite
import CryptoKit
import Darwin
import Foundation

public struct AuthorizationHistoryRetention: Sendable {
    public static let sizeDefaultsKey = "authorizationHistorySizeMiB"
    public static let defaultSizeMiB = 25
    public static let sizeRangeMiB = 1...1024

    public static func configuredSizeMiB(defaults: UserDefaults = .standard) -> Int {
        let value = defaults.integer(forKey: sizeDefaultsKey)
        return sizeRangeMiB.contains(value) ? value : defaultSizeMiB
    }

    public static let standard = AuthorizationHistoryRetention(
        maximumAge: 30 * 24 * 60 * 60,
        maximumEncryptedBytes: Int64(defaultSizeMiB) * 1024 * 1024
    )

    public let maximumAge: TimeInterval
    public let maximumEncryptedBytes: Int64

    public init(maximumAge: TimeInterval, maximumEncryptedBytes: Int64) {
        self.maximumAge = maximumAge
        self.maximumEncryptedBytes = maximumEncryptedBytes
    }
}

public struct AuthorizationHistoryPage: Sendable {
    public let records: [AccessRequestRecord]
    public let olderPageCursor: Int64?
    public let storedDayCount: Int?
}

/// Display-only, authenticated history snapshot; never an authorization input.
public struct AuthorizationHistoryDashboard: Sendable {
    fileprivate struct Entry: Sendable {
        let sequence: Int64
        let record: AccessRequestRecord
    }
    fileprivate let owner: UUID
    fileprivate let revision: UInt64
    fileprivate let dataVersion: Int64
    fileprivate let calendar: Calendar
    fileprivate let scannedAt: Date
    fileprivate var throughSequence: Int64
    fileprivate var recent: [Entry] = []
    fileprivate var activity: [Entry] = []
    fileprivate var latestByDay: [Date: Date] = [:]

    public var page: AuthorizationHistoryPage {
        AuthorizationHistoryPage(records: recent.reversed().map(\.record),
            olderPageCursor: recent.count == 50 ? recent.first?.sequence : nil,
            storedDayCount: latestByDay.count)
    }
    public var activityRecords: [AccessRequestRecord] { activity.reversed().map(\.record) }
}

public enum AuthorizationHistoryStoreError: Error, Equatable {
    case invalidKey
    case sqlite(String)
    case encryption
    case decoding
    case recordTooLarge
    case invalidLimit
    case disclosureTooLarge
    case verificationFailed
}

public final class AuthorizationHistoryStore: @unchecked Sendable {
    private let database: OpaquePointer
    private let encryptionKey: SymmetricKey
    private let bucketKey: SymmetricKey
    private var retention: AuthorizationHistoryRetention
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private let maintenanceLock = NSLock()
    private let dashboardOwner = UUID()
    private var dashboardRevision: UInt64 = 0
    private var estimatedEncryptedBytes: Int64 = 0
    private var appendedBytes: Int64 = 0

    public var needsMaintenance: Bool {
        lock.withLock { estimatedEncryptedBytes >= retention.maximumEncryptedBytes }
    }

    public init(
        url: URL,
        keyData: Data,
        retention: AuthorizationHistoryRetention = .standard,
        now: @escaping @Sendable () -> Date = Date.init
    ) throws {
        guard keyData.count == 32 else { throw AuthorizationHistoryStoreError.invalidKey }
        guard retention.maximumAge > 0, retention.maximumEncryptedBytes > 0 else {
            throw AuthorizationHistoryStoreError.recordTooLarge
        }
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directory.path
        )
        var directoryValues = URLResourceValues()
        directoryValues.isExcludedFromBackup = true
        var mutableDirectory = directory
        try mutableDirectory.setResourceValues(directoryValues)
        var opened: OpaquePointer?
        let status = sqlite3_open_v2(
            url.path,
            &opened,
            SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard status == SQLITE_OK, let opened else {
            if let opened { sqlite3_close(opened) }
            throw AuthorizationHistoryStoreError.sqlite("open failed: \(status)")
        }
        database = opened
        let rootKey = SymmetricKey(data: keyData)
        encryptionKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: rootKey,
            salt: Data("com.automicvault.authorization-history.v1".utf8),
            info: Data("record-encryption".utf8),
            outputByteCount: 32
        )
        bucketKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: rootKey,
            salt: Data("com.automicvault.authorization-history.v1".utf8),
            info: Data("retention-buckets".utf8),
            outputByteCount: 32
        )
        self.retention = retention
        self.now = now
        do {
            try Self.execute(database, "PRAGMA journal_mode=DELETE")
            try Self.execute(database, "PRAGMA synchronous=FULL")
            try Self.execute(database, "PRAGMA secure_delete=ON")
            try Self.execute(
                database,
                """
                CREATE TABLE IF NOT EXISTS authorization_history (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT UNIQUE NOT NULL,
                    retention_bucket BLOB NOT NULL,
                    ciphertext BLOB NOT NULL
                )
                """)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableURL = url
            try mutableURL.setResourceValues(values)
        } catch {
            sqlite3_close(opened)
            throw error
        }
    }

    deinit {
        sqlite3_close(database)
    }

    public func append(_ record: AccessRequestRecord) -> Bool {
        lock.withLock {
            do {
                let (bucket, ciphertext) = try seal(record)
                guard Int64(ciphertext.count) <= retention.maximumEncryptedBytes else {
                    throw AuthorizationHistoryStoreError.recordTooLarge
                }
                try execute("BEGIN IMMEDIATE")
                do {
                    try insert(
                        record: record, bucket: bucket, ciphertext: ciphertext, replacing: false)
                    guard try restoredRecord(id: record.id) == record else {
                        throw AuthorizationHistoryStoreError.verificationFailed
                    }
                    try execute("COMMIT")
                } catch {
                    try? execute("ROLLBACK")
                    throw error
                }
                guard try restoredRecord(id: record.id) == record else {
                    throw AuthorizationHistoryStoreError.verificationFailed
                }
                estimatedEncryptedBytes += Int64(ciphertext.count)
                appendedBytes += Int64(ciphertext.count)
                return true
            } catch {
                return false
            }
        }
    }

    public func importRecords(
        _ records: [AccessRequestRecord],
        verifyBeforeCommit: () throws -> Void = {}
    ) throws {
        try lock.withLock {
            try execute("BEGIN IMMEDIATE")
            do {
                for record in records.sorted(by: { $0.date < $1.date }) {
                    let (bucket, ciphertext) = try seal(record)
                    guard Int64(ciphertext.count) <= retention.maximumEncryptedBytes else {
                        throw AuthorizationHistoryStoreError.recordTooLarge
                    }
                    try insert(
                        record: record, bucket: bucket, ciphertext: ciphertext, replacing: true)
                    guard try restoredRecord(id: record.id) == record else {
                        throw AuthorizationHistoryStoreError.verificationFailed
                    }
                }
                try verifyBeforeCommit()
                try execute("COMMIT")
                dashboardRevision &+= 1
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
            for record in records {
                guard try restoredRecord(id: record.id) == record else {
                    throw AuthorizationHistoryStoreError.verificationFailed
                }
            }
        }
    }

    public func records(
        since: Date? = nil,
        limit: Int? = nil,
        maximumDisclosureBytes: Int? = nil,
        isCanceled: () -> Bool = { false }
    ) throws -> [AccessRequestRecord] {
        try readRecords(
            since: since, limit: limit, maximumDisclosureBytes: maximumDisclosureBytes,
            beforeSequence: nil, isCanceled: isCanceled).records
    }

    public func page(beforeSequence: Int64? = nil, limit: Int = 50) throws -> AuthorizationHistoryPage {
        try readRecords(
            since: nil, limit: limit, maximumDisclosureBytes: nil,
            beforeSequence: beforeSequence, includeStoredDayCount: beforeSequence == nil)
    }

    func readRecords(
        since: Date?, limit: Int?, maximumDisclosureBytes: Int?, beforeSequence: Int64?,
        includeStoredDayCount: Bool = false,
        isCanceled: () -> Bool = { false },
        afterBatch: () throws -> Void = {}
    ) throws -> AuthorizationHistoryPage {
        guard limit.map({ $0 > 0 }) ?? true,
              beforeSequence.map({ $0 > 0 }) ?? true,
              maximumDisclosureBytes.map({ $0 >= 2 }) ?? true else {
            throw AuthorizationHistoryStoreError.invalidLimit
        }
        guard !isCanceled() else { throw CancellationError() }
        let (revision, dataVersion, upperSequence, maximumAge) = try lock.withLock {
            let version = try dashboardDataVersion()
            var statement: OpaquePointer?
            // Separate aggregates let SQLite seek both index endpoints instead of scanning under lock.
            try prepare("SELECT (SELECT COALESCE(MAX(sequence), 0) FROM authorization_history), (SELECT COALESCE(MIN(sequence), 1) FROM authorization_history)", into: &statement)
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else { throw sqliteError("history boundary failed") }
            guard sqlite3_column_int64(statement, 1) > 0 else {
                throw AuthorizationHistoryStoreError.verificationFailed
            }
            return (dashboardRevision, version, sqlite3_column_int64(statement, 0), retention.maximumAge)
        }
        let currentDate = now()
        let cutoff = currentDate.addingTimeInterval(-maximumAge)
        let effectiveSince = max(since ?? cutoff, cutoff)
        var records: [AccessRequestRecord] = []
        var olderPageCursor: Int64?
        var storedDays: Set<Date> = []
        var dayByHour: [Int64: Date] = [:]
        let calendar = Calendar.autoupdatingCurrent
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        var disclosureBytes = 2 // JSON array brackets.
        var cursor = min(upperSequence, beforeSequence.map { $0 - 1 } ?? upperSequence)
        scan: while cursor > 0 {
            guard !isCanceled() else { throw CancellationError() }
            let rows: [(Int64, String, Data, Data)] = try lock.withLock {
                var statement: OpaquePointer?
                try prepare("SELECT id, retention_bucket, ciphertext, sequence FROM authorization_history WHERE sequence <= ? ORDER BY sequence DESC LIMIT 64", into: &statement)
                defer { sqlite3_finalize(statement) }
                guard sqlite3_bind_int64(statement, 1, cursor) == SQLITE_OK else {
                    throw sqliteError("history cursor bind failed")
                }
                var rows: [(Int64, String, Data, Data)] = []
                var bytes = 0
                while true {
                    switch sqlite3_step(statement) {
                    case SQLITE_ROW:
                        guard sqlite3_column_type(statement, 3) == SQLITE_INTEGER,
                              sqlite3_column_int64(statement, 3) > 0 else {
                            throw AuthorizationHistoryStoreError.decoding
                        }
                        let ciphertext = data(at: 2, from: statement)
                        rows.append((sqlite3_column_int64(statement, 3), try storedRecordID(from: statement),
                                     data(at: 1, from: statement), ciphertext))
                        bytes += ciphertext.count
                        if bytes >= 1_048_576 { return rows }
                    case SQLITE_DONE: return rows
                    default: throw sqliteError("read failed")
                    }
                }
            }
            guard !rows.isEmpty else { break }
            try afterBatch()
            for (sequence, id, bucket, ciphertext) in rows {
                guard !isCanceled() else { throw CancellationError() }
                let record = try decode(ciphertext, id: id, bucket: bucket)
                cursor = sequence - 1
                if record.date < effectiveSince || record.date > currentDate { continue }
                if includeStoredDayCount {
                    let hour = Int64(floor(record.date.timeIntervalSince1970 / 3_600))
                    let day = dayByHour[hour] ?? calendar.startOfDay(for: record.date)
                    dayByHour[hour] = day
                    storedDays.insert(day)
                }
                if limit.map({ records.count >= $0 }) == true { continue }
                if let maximumDisclosureBytes {
                    let encoded = try encoder.encode(record.redactedForDisclosure)
                    let (bytes, overflow) = disclosureBytes.addingReportingOverflow(
                        encoded.count + (records.isEmpty ? 0 : 1)
                    )
                    guard !overflow, bytes <= maximumDisclosureBytes else {
                        throw AuthorizationHistoryStoreError.disclosureTooLarge
                    }
                    disclosureBytes = bytes
                }
                records.append(record)
                if let limit, records.count == limit {
                    olderPageCursor = sequence
                    if !includeStoredDayCount {
                        break scan
                    }
                }
            }
        }
        try lock.withLock {
            guard dashboardRevision == revision, try dashboardDataVersion() == dataVersion else {
                throw AuthorizationHistoryStoreError.verificationFailed
            }
        }
        guard !isCanceled() else { throw CancellationError() }
        return AuthorizationHistoryPage(records: records, olderPageCursor: olderPageCursor,
            storedDayCount: includeStoredDayCount ? storedDays.count : nil)
    }

    public func dashboard(previous: AuthorizationHistoryDashboard? = nil) throws -> AuthorizationHistoryDashboard {
        try dashboard(previous: previous, afterBatch: {})
    }

    func dashboard(previous: AuthorizationHistoryDashboard?, afterBatch: () throws -> Void) throws -> AuthorizationHistoryDashboard {
        do {
            return try scanDashboard(previous: previous, afterBatch: afterBatch)
        } catch AuthorizationHistoryStoreError.verificationFailed {
            // Startup cleanup can invalidate a scan; wait for it and authenticate a fresh snapshot once.
            return try maintenanceLock.withLock {
                try scanDashboard(previous: nil, afterBatch: {})
            }
        }
    }

    private func scanDashboard(previous: AuthorizationHistoryDashboard?, afterBatch: () throws -> Void) throws -> AuthorizationHistoryDashboard {
        let calendar = Calendar.current
        let (revision, dataVersion, upperSequence, maximumAge) = try lock.withLock {
            let version = try dashboardDataVersion()
            var statement: OpaquePointer?
            try prepare("SELECT COALESCE(MAX(sequence), 0) FROM authorization_history", into: &statement)
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else { throw sqliteError("dashboard boundary failed") }
            return (dashboardRevision, version, sqlite3_column_int64(statement, 0), retention.maximumAge)
        }
        let currentDate = now()
        let cutoff = currentDate.addingTimeInterval(-maximumAge)
        let activityCutoff = max(cutoff, currentDate.addingTimeInterval(-86_400))
        // Refresh explicit reads and snapshots older than a minute to observe external changes.
        var result: AuthorizationHistoryDashboard
        if let previous, previous.owner == dashboardOwner, previous.revision == revision,
           previous.dataVersion == dataVersion, previous.calendar == calendar, previous.throughSequence <= upperSequence,
           (0..<60).contains(currentDate.timeIntervalSince(previous.scannedAt)),
           previous.recent.allSatisfy({ $0.record.date >= cutoff && $0.record.date <= currentDate }) {
            result = previous
        } else {
            result = AuthorizationHistoryDashboard(owner: dashboardOwner, revision: revision,
                dataVersion: dataVersion, calendar: calendar, scannedAt: currentDate, throughSequence: 0)
        }
        var cursor = result.throughSequence
        while cursor < upperSequence {
            let rows: [(Int64, String, Data, Data)] = try lock.withLock {
                var statement: OpaquePointer?
                try prepare("SELECT id, retention_bucket, ciphertext, sequence FROM authorization_history WHERE sequence > ? AND sequence <= ? ORDER BY sequence LIMIT 64", into: &statement)
                defer { sqlite3_finalize(statement) }
                sqlite3_bind_int64(statement, 1, cursor)
                sqlite3_bind_int64(statement, 2, upperSequence)
                var rows: [(Int64, String, Data, Data)] = []
                var bytes = 0
                while true {
                    switch sqlite3_step(statement) {
                    case SQLITE_ROW:
                        let ciphertext = data(at: 2, from: statement)
                        rows.append((sqlite3_column_int64(statement, 3), try storedRecordID(from: statement),
                                     data(at: 1, from: statement), ciphertext))
                        bytes += ciphertext.count
                        if bytes >= 1_048_576 { return rows }
                    case SQLITE_DONE: return rows
                    default: throw sqliteError("dashboard scan failed")
                    }
                }
            }
            guard !rows.isEmpty else { break }
            try afterBatch()
            for (sequence, id, bucket, ciphertext) in rows {
                let record = try decode(ciphertext, id: id, bucket: bucket)
                cursor = sequence
                guard record.date >= cutoff, record.date <= currentDate else { continue }
                result.recent.append(.init(sequence: sequence, record: record))
                if record.date >= activityCutoff { result.activity.append(.init(sequence: sequence, record: record)) }
                let day = calendar.startOfDay(for: record.date)
                result.latestByDay[day] = max(result.latestByDay[day] ?? record.date, record.date)
            }
            result.recent = Array(result.recent.suffix(50))
        }
        result.throughSequence = upperSequence
        result.activity.removeAll { $0.record.date < activityCutoff || $0.record.date > currentDate }
        result.latestByDay = result.latestByDay.filter { $0.value >= cutoff && $0.value <= currentDate }
        try lock.withLock {
            guard dashboardRevision == revision, try dashboardDataVersion() == dataVersion else {
                throw AuthorizationHistoryStoreError.verificationFailed
            }
        }
        return result
    }

    // Called under lock; commits by other SQLite connections invalidate display snapshots.
    private func dashboardDataVersion() throws -> Int64 {
        var statement: OpaquePointer?
        try prepare("PRAGMA data_version", into: &statement)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw sqliteError("dashboard version failed") }
        return sqlite3_column_int64(statement, 0)
    }

    public func setMaximumEncryptedBytes(_ bytes: Int64) throws {
        guard bytes > 0 else { throw AuthorizationHistoryStoreError.invalidLimit }
        lock.withLock {
            retention = AuthorizationHistoryRetention(
                maximumAge: retention.maximumAge, maximumEncryptedBytes: bytes)
        }
    }

    public func maintain() throws {
        try maintain(afterScan: {})
    }

    // Hooks exercise concurrent writes during the scan and before deletion.
    func maintain(afterScan: () throws -> Void, afterBatch: () throws -> Void = {}) throws {
        guard maintenanceLock.try() else { return }
        defer { maintenanceLock.unlock() }
        let (policy, appendedAtStart, upperSequence) = try lock.withLock {
            var statement: OpaquePointer?
            try prepare("SELECT COALESCE(MAX(sequence), 0) FROM authorization_history", into: &statement)
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else { throw sqliteError("maintenance boundary failed") }
            return (retention, appendedBytes, sqlite3_column_int64(statement, 0))
        }
        struct Candidate {
            let sequence: Int64
            let id: String
            let digest: SHA256.Digest
            let date: Date
            let size: Int64
        }
        let currentDate = now()
        let cutoff = currentDate.addingTimeInterval(-policy.maximumAge)
        var candidates: [Candidate] = []
        var cursor: Int64 = 0
        var total: Int64 = 0
        var scan: OpaquePointer?
        try lock.withLock {
            try prepare("SELECT id, retention_bucket, ciphertext, sequence FROM authorization_history WHERE sequence > ? AND sequence <= ? ORDER BY sequence LIMIT 64", into: &scan)
        }
        defer { lock.withLock { sqlite3_finalize(scan) } }
        let decoder = JSONDecoder()
        while cursor < upperSequence {
            let rows: [(Int64, String, Data, Data)] = try lock.withLock {
                // End the read before unlocking so appends never inherit an active cursor.
                defer { sqlite3_reset(scan) }
                sqlite3_bind_int64(scan, 1, cursor)
                sqlite3_bind_int64(scan, 2, upperSequence)
                var rows: [(Int64, String, Data, Data)] = []
                var bytes = 0
                while true {
                    switch sqlite3_step(scan) {
                    case SQLITE_ROW:
                        let ciphertext = data(at: 2, from: scan)
                        rows.append((sqlite3_column_int64(scan, 3), try storedRecordID(from: scan),
                                     data(at: 1, from: scan), ciphertext))
                        bytes += ciphertext.count
                        if bytes >= 1_048_576 { return rows }
                    case SQLITE_DONE: return rows
                    default: throw sqliteError("maintenance scan failed")
                    }
                }
            }
            guard !rows.isEmpty else { break }
            try afterBatch()
            for (sequence, id, bucket, ciphertext) in rows {
                let record = try decode(ciphertext, id: id, bucket: bucket, decoder: decoder)
                candidates.append(Candidate(sequence: sequence, id: id,
                    digest: SHA256.hash(data: bucket + ciphertext), date: record.date, size: Int64(ciphertext.count)))
                total += Int64(ciphertext.count)
                cursor = sequence
            }
        }
        try afterScan()
        func expired(_ candidate: Candidate) -> Bool {
            candidate.date < cutoff || candidate.date > currentDate
        }
        candidates.sort {
            if expired($0) != expired($1) { return expired($0) }
            return $0.date == $1.date ? $0.sequence < $1.sequence : $0.date < $1.date
        }
        var removed: Int64 = 0
        var recheck: OpaquePointer?
        var deletion: OpaquePointer?
        defer {
            lock.withLock {
                sqlite3_finalize(recheck)
                sqlite3_finalize(deletion)
            }
        }
        for candidate in candidates {
            guard expired(candidate) || total - removed > policy.maximumEncryptedBytes else { continue }
            try lock.withLock {
                // A changed setting requires a new selection, never deletion under the old policy.
                guard retention.maximumEncryptedBytes == policy.maximumEncryptedBytes else {
                    throw AuthorizationHistoryStoreError.verificationFailed
                }
                if recheck == nil {
                    try prepare("SELECT id, retention_bucket, ciphertext FROM authorization_history WHERE sequence = ?", into: &recheck)
                }
                if deletion == nil {
                    try prepare("DELETE FROM authorization_history WHERE id = ?", into: &deletion)
                }
                try execute("BEGIN IMMEDIATE")
                do {
                    sqlite3_bind_int64(recheck, 1, candidate.sequence)
                    do {
                        defer { sqlite3_reset(recheck) }
                        switch sqlite3_step(recheck) {
                        case SQLITE_ROW:
                            guard try storedRecordID(from: recheck) == candidate.id,
                                  SHA256.hash(data: data(at: 1, from: recheck) + data(at: 2, from: recheck)) == candidate.digest
                            else { throw AuthorizationHistoryStoreError.verificationFailed }
                        case SQLITE_DONE: throw AuthorizationHistoryStoreError.verificationFailed
                        default: throw sqliteError("maintenance recheck failed")
                        }
                    }
                    do {
                        defer { sqlite3_reset(deletion) }
                        sqlite3_bind_text(deletion, 1, candidate.id, -1, SQLITE_TRANSIENT)
                        guard sqlite3_step(deletion) == SQLITE_DONE else {
                            throw sqliteError("expiry pruning failed")
                        }
                    }
                    try execute("COMMIT")
                    dashboardRevision &+= 1
                    removed += candidate.size
                } catch {
                    try? execute("ROLLBACK")
                    throw error
                }
            }
        }
        lock.withLock {
            estimatedEncryptedBytes = total - removed + (appendedBytes - appendedAtStart)
        }
    }

    private func insert(
        record: AccessRequestRecord,
        bucket: Data,
        ciphertext: Data,
        replacing: Bool
    ) throws {
        var statement: OpaquePointer?
        try prepare(
            "INSERT \(replacing ? "OR IGNORE " : "")INTO authorization_history (id, retention_bucket, ciphertext) VALUES (?, ?, ?)",
            into: &statement
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(statement, 1, record.id.uuidString, -1, SQLITE_TRANSIENT)
        _ = bucket.withUnsafeBytes { bytes in
            sqlite3_bind_blob(statement, 2, bytes.baseAddress, Int32(bytes.count), SQLITE_TRANSIENT)
        }
        _ = ciphertext.withUnsafeBytes { bytes in
            sqlite3_bind_blob(statement, 3, bytes.baseAddress, Int32(bytes.count), SQLITE_TRANSIENT)
        }
        guard sqlite3_step(statement) == SQLITE_DONE else { throw sqliteError("insert failed") }
    }

    private func restoredRecord(id: UUID) throws -> AccessRequestRecord? {
        var statement: OpaquePointer?
        try prepare(
            "SELECT retention_bucket, ciphertext FROM authorization_history WHERE id = ?",
            into: &statement
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(statement, 1, id.uuidString, -1, SQLITE_TRANSIENT)
        switch sqlite3_step(statement) {
        case SQLITE_ROW:
            let bucket = data(at: 0, from: statement)
            return try decode(data(at: 1, from: statement), id: id.uuidString, bucket: bucket)
        case SQLITE_DONE: return nil
        default: throw sqliteError("verification read failed")
        }
    }

    private func seal(_ record: AccessRequestRecord) throws -> (Data, Data) {
        let bucket = try retentionBucket(for: record.date)
        do {
            let plaintext = try JSONEncoder().encode(record)
            guard
                let ciphertext = try AES.GCM.seal(
                    plaintext,
                    using: encryptionKey,
                    authenticating: authenticatedData(id: record.id.uuidString, bucket: bucket)
                ).combined
            else {
                throw AuthorizationHistoryStoreError.encryption
            }
            return (bucket, ciphertext)
        } catch let error as AuthorizationHistoryStoreError {
            throw error
        } catch {
            throw AuthorizationHistoryStoreError.encryption
        }
    }

    private func decode(_ ciphertext: Data, id: String, bucket: Data, decoder: JSONDecoder = JSONDecoder()) throws -> AccessRequestRecord
    {
        do {
            let plaintext = try AES.GCM.open(
                AES.GCM.SealedBox(combined: ciphertext),
                using: encryptionKey,
                authenticating: authenticatedData(id: id, bucket: bucket)
            )
            let record = try decoder.decode(AccessRequestRecord.self, from: plaintext)
            guard record.id.uuidString == id else {
                throw AuthorizationHistoryStoreError.verificationFailed
            }
            return record
        } catch {
            throw AuthorizationHistoryStoreError.decoding
        }
    }

    private func data(at column: Int32, from statement: OpaquePointer?) -> Data {
        let count = Int(sqlite3_column_bytes(statement, column))
        guard count > 0, let bytes = sqlite3_column_blob(statement, column) else { return Data() }
        return Data(bytes: bytes, count: count)
    }

    private func storedRecordID(from statement: OpaquePointer?) throws -> String {
        guard sqlite3_column_type(statement, 0) == SQLITE_TEXT,
              let bytes = sqlite3_column_text(statement, 0),
              let id = String(data: Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0))), encoding: .utf8),
              UUID(uuidString: id)?.uuidString == id
        else { throw AuthorizationHistoryStoreError.decoding }
        return id
    }

    private func retentionBucket(for date: Date) throws -> Data {
        let hourValue = floor(date.timeIntervalSince1970 / 3_600)
        guard hourValue.isFinite,
              hourValue >= Double(Int64.min),
              hourValue < 9_223_372_036_854_775_808.0
        else { throw AuthorizationHistoryStoreError.decoding }
        var hour = Int64(hourValue).bigEndian
        let value = withUnsafeBytes(of: &hour) { Data($0) }
        return Data(HMAC<SHA256>.authenticationCode(for: value, using: bucketKey))
    }

    private func authenticatedData(id: String, bucket: Data) -> Data {
        var data = Data(id.utf8)
        data.append(0)
        data.append(bucket)
        return data
    }

    private func execute(_ sql: String) throws {
        try Self.execute(database, sql)
    }

    private static func execute(_ database: OpaquePointer, _ sql: String) throws {
        guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            let message = String(cString: sqlite3_errmsg(database))
            throw AuthorizationHistoryStoreError.sqlite(message)
        }
    }

    private func prepare(_ sql: String, into statement: inout OpaquePointer?) throws {
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError("prepare failed")
        }
    }

    private func sqliteError(_ context: String) -> AuthorizationHistoryStoreError {
        .sqlite("\(context): \(String(cString: sqlite3_errmsg(database)))")
    }
}

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
