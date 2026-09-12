import CSQLite
import CryptoKit
import Darwin
import Foundation

public struct AuthorizationHistoryRetention: Sendable {
    public static let standard = AuthorizationHistoryRetention(
        maximumAge: 30 * 24 * 60 * 60,
        maximumEncryptedBytes: 25 * 1024 * 1024
    )

    public let maximumAge: TimeInterval
    public let maximumEncryptedBytes: Int64

    public init(maximumAge: TimeInterval, maximumEncryptedBytes: Int64) {
        self.maximumAge = maximumAge
        self.maximumEncryptedBytes = maximumEncryptedBytes
    }
}

public enum AuthorizationHistoryStoreError: Error, Equatable {
    case invalidKey
    case sqlite(String)
    case encryption
    case decoding
    case recordTooLarge
    case verificationFailed
}

public final class AuthorizationHistoryStore: @unchecked Sendable {
    private let database: OpaquePointer
    private let encryptionKey: SymmetricKey
    private let bucketKey: SymmetricKey
    private let retention: AuthorizationHistoryRetention
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

    public func importRecords(_ records: [AccessRequestRecord]) throws {
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

    public func records(since: Date? = nil, limit: Int? = nil) throws -> [AccessRequestRecord] {
        try lock.withLock {
            var statement: OpaquePointer?
            let sql =
                "SELECT id, retention_bucket, ciphertext FROM authorization_history ORDER BY sequence DESC"
            try prepare(sql, into: &statement)
            defer { sqlite3_finalize(statement) }
            let currentDate = now()
            let effectiveSince = since.map {
                max($0, currentDate.addingTimeInterval(-retention.maximumAge))
            }
            let includedBuckets = effectiveSince.map {
                retainedBuckets(from: $0, through: currentDate)
            }
            var records: [AccessRequestRecord] = []
            while true {
                switch sqlite3_step(statement) {
                case SQLITE_ROW:
                    if let includedBuckets,
                        !includedBuckets.contains(data(at: 1, from: statement))
                    {
                        continue
                    }
                    let id = String(cString: sqlite3_column_text(statement, 0))
                    let bucket = data(at: 1, from: statement)
                    let record = try decode(
                        data(at: 2, from: statement),
                        id: id,
                        bucket: bucket
                    )
                    if effectiveSince.map({ record.date < $0 }) == true { continue }
                    records.append(record)
                    if let limit, records.count == limit { return records }
                case SQLITE_DONE:
                    return records
                default:
                    throw sqliteError("read failed")
                }
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
        let bucket = retentionBucket(for: record.date)
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

    private func prune(preserving recordID: UUID?) throws {
        let currentDate = now()
        let retained = retainedBuckets(
            from: currentDate.addingTimeInterval(-retention.maximumAge),
            through: currentDate
        )
        var expired: OpaquePointer?
        try prepare("SELECT id, retention_bucket FROM authorization_history", into: &expired)
        var expiredIDs: [String] = []
        while true {
            switch sqlite3_step(expired) {
            case SQLITE_ROW:
                let id = String(cString: sqlite3_column_text(expired, 0))
                if id != recordID?.uuidString,
                    !retained.contains(data(at: 1, from: expired))
                {
                    expiredIDs.append(id)
                }
            case SQLITE_DONE:
                sqlite3_finalize(expired)
                expired = nil
                break
            default:
                sqlite3_finalize(expired)
                throw sqliteError("expiry query failed")
            }
            if expired == nil { break }
        }
        for id in expiredIDs { try delete(id: id) }

        while try encryptedByteCount() > retention.maximumEncryptedBytes {
            var statement: OpaquePointer?
            let sql =
                recordID == nil
                ? "DELETE FROM authorization_history WHERE sequence = (SELECT sequence FROM authorization_history ORDER BY sequence ASC LIMIT 1)"
                : "DELETE FROM authorization_history WHERE sequence = (SELECT sequence FROM authorization_history WHERE id != ? ORDER BY sequence ASC LIMIT 1)"
            try prepare(sql, into: &statement)
            defer { sqlite3_finalize(statement) }
            if let recordID {
                sqlite3_bind_text(statement, 1, recordID.uuidString, -1, SQLITE_TRANSIENT)
            }
            guard sqlite3_step(statement) == SQLITE_DONE, sqlite3_changes(database) == 1 else {
                throw AuthorizationHistoryStoreError.recordTooLarge
            }
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

    private func retentionBucket(for date: Date) -> Data {
        var hour = Int64(floor(date.timeIntervalSince1970 / 3_600)).bigEndian
        let value = withUnsafeBytes(of: &hour) { Data($0) }
        return Data(HMAC<SHA256>.authenticationCode(for: value, using: bucketKey))
    }

    private func authenticatedData(id: String, bucket: Data) -> Data {
        var data = Data(id.utf8)
        data.append(0)
        data.append(bucket)
        return data
    }

    private func retainedBuckets(from start: Date, through end: Date) -> Set<Data> {
        let first = Int64(floor(start.timeIntervalSince1970 / 3_600))
        let last = Int64(floor(end.timeIntervalSince1970 / 3_600))
        guard first <= last else { return [] }
        return Set(
            (first...last).map { hour in
                retentionBucket(for: Date(timeIntervalSince1970: TimeInterval(hour) * 3_600))
            })
    }

    private func encryptedByteCount() throws -> Int64 {
        var statement: OpaquePointer?
        try prepare(
            "SELECT COALESCE(SUM(length(ciphertext)), 0) FROM authorization_history",
            into: &statement
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw sqliteError("size query failed") }
        return sqlite3_column_int64(statement, 0)
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

extension NSLock {
    fileprivate func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
