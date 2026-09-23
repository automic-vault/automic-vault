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
                    try prune(preserving: record.id)
                    try execute("COMMIT")
                } catch {
                    try? execute("ROLLBACK")
                    throw error
                }
                guard try restoredRecord(id: record.id) == record else {
                    throw AuthorizationHistoryStoreError.verificationFailed
                }
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
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
            for record in records {
                guard try restoredRecord(id: record.id) == record else {
                    throw AuthorizationHistoryStoreError.verificationFailed
                }
            }
            try execute("BEGIN IMMEDIATE")
            do {
                try prune(preserving: nil)
                try execute("COMMIT")
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
        }
    }

    public func records(
        since: Date? = nil,
        limit: Int? = nil,
        maximumDisclosureBytes: Int? = nil
    ) throws -> [AccessRequestRecord] {
        try readRecords(
            since: since, limit: limit, maximumDisclosureBytes: maximumDisclosureBytes,
            beforeSequence: nil).records
    }

    public func page(beforeSequence: Int64? = nil, limit: Int = 50) throws -> AuthorizationHistoryPage {
        try readRecords(
            since: nil, limit: limit, maximumDisclosureBytes: nil,
            beforeSequence: beforeSequence, includeStoredDayCount: beforeSequence == nil)
    }

    private func readRecords(
        since: Date?, limit: Int?, maximumDisclosureBytes: Int?, beforeSequence: Int64?,
        includeStoredDayCount: Bool = false
    ) throws -> AuthorizationHistoryPage {
        guard limit.map({ $0 > 0 }) ?? true,
              beforeSequence.map({ $0 > 0 }) ?? true,
              maximumDisclosureBytes.map({ $0 >= 2 }) ?? true else {
            throw AuthorizationHistoryStoreError.invalidLimit
        }
        return try lock.withLock {
            var statement: OpaquePointer?
            let sql = beforeSequence == nil
                ? "SELECT id, retention_bucket, ciphertext, sequence FROM authorization_history ORDER BY sequence DESC"
                : "SELECT id, retention_bucket, ciphertext, sequence FROM authorization_history WHERE sequence < ? ORDER BY sequence DESC"
            try prepare(sql, into: &statement)
            defer { sqlite3_finalize(statement) }
            if let beforeSequence {
                guard sqlite3_bind_int64(statement, 1, beforeSequence) == SQLITE_OK else {
                    throw sqliteError("history cursor bind failed")
                }
            }
            let currentDate = now()
            let cutoff = currentDate.addingTimeInterval(-retention.maximumAge)
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
            while true {
                switch sqlite3_step(statement) {
                case SQLITE_ROW:
                    guard sqlite3_column_type(statement, 3) == SQLITE_INTEGER else {
                        throw AuthorizationHistoryStoreError.decoding
                    }
                    let sequence = sqlite3_column_int64(statement, 3)
                    let id = try storedRecordID(from: statement)
                    let bucket = data(at: 1, from: statement)
                    let record = try decode(
                        data(at: 2, from: statement),
                        id: id,
                        bucket: bucket
                    )
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
                            return AuthorizationHistoryPage(
                                records: records, olderPageCursor: sequence, storedDayCount: nil)
                        }
                    }
                case SQLITE_DONE:
                    return AuthorizationHistoryPage(
                        records: records,
                        olderPageCursor: olderPageCursor,
                        storedDayCount: includeStoredDayCount ? storedDays.count : nil
                    )
                default:
                    throw sqliteError("read failed")
                }
            }
        }
    }

    public func setMaximumEncryptedBytes(_ bytes: Int64) throws {
        guard bytes > 0 else { throw AuthorizationHistoryStoreError.invalidLimit }
        try lock.withLock {
            guard bytes != retention.maximumEncryptedBytes else { return }
            let previous = retention
            try execute("BEGIN IMMEDIATE")
            do {
                retention = AuthorizationHistoryRetention(
                    maximumAge: previous.maximumAge, maximumEncryptedBytes: bytes)
                try prune(preserving: nil)
                try execute("COMMIT")
            } catch {
                retention = previous
                try? execute("ROLLBACK")
                throw error
            }
        }
    }

    public func maintain() throws {
        try lock.withLock {
            try execute("BEGIN IMMEDIATE")
            do {
                try prune(preserving: nil)
                try execute("COMMIT")
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
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

    private func decode(_ ciphertext: Data, id: String, bucket: Data) throws -> AccessRequestRecord
    {
        do {
            let plaintext = try AES.GCM.open(
                AES.GCM.SealedBox(combined: ciphertext),
                using: encryptionKey,
                authenticating: authenticatedData(id: id, bucket: bucket)
            )
            let record = try JSONDecoder().decode(AccessRequestRecord.self, from: plaintext)
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

    private func prune(preserving recordID: UUID?) throws {
        // ponytail: O(rows) inside the configured ciphertext cap; larger caps add latency. Authenticate every row
        // before allowing Secret Use; a cleartext date index would leak activity.
        let currentDate = now()
        let cutoff = currentDate.addingTimeInterval(-retention.maximumAge)
        var rows: [(id: String, size: Int64, expired: Bool, date: Date)] = []
        var totalBytes: Int64 = 0
        do {
            var statement: OpaquePointer?
            try prepare(
                "SELECT id, retention_bucket, ciphertext FROM authorization_history ORDER BY sequence ASC",
                into: &statement
            )
            defer { sqlite3_finalize(statement) }
            scan: while true {
                switch sqlite3_step(statement) {
                case SQLITE_ROW:
                    let id = try storedRecordID(from: statement)
                    let bucket = data(at: 1, from: statement)
                    let ciphertext = data(at: 2, from: statement)
                    let record = try decode(ciphertext, id: id, bucket: bucket)
                    let expired = id != recordID?.uuidString
                        && (record.date < cutoff || record.date > currentDate)
                    let size = Int64(ciphertext.count)
                    totalBytes += size
                    rows.append((id, size, expired, record.date))
                case SQLITE_DONE:
                    break scan
                default:
                    throw sqliteError("expiry query failed")
                }
            }
        }
        for row in rows where row.expired {
            try delete(id: row.id)
            totalBytes -= row.size
        }
        rows.sort { $0.date < $1.date }
        for row in rows where !row.expired && totalBytes > retention.maximumEncryptedBytes {
            guard row.id != recordID?.uuidString else { continue }
            try delete(id: row.id)
            totalBytes -= row.size
        }
        guard totalBytes <= retention.maximumEncryptedBytes else {
            throw AuthorizationHistoryStoreError.recordTooLarge
        }
    }

    private func delete(id: String) throws {
        var statement: OpaquePointer?
        try prepare("DELETE FROM authorization_history WHERE id = ?", into: &statement)
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(statement, 1, id, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError("expiry pruning failed")
        }
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
