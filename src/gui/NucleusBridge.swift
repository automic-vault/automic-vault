import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum NucleusBridgeError: Error, LocalizedError {
    case binaryNotFound
    case commandFailed(String)
    case connectionFailed(String)
    case invalidResponse(String)
    case protocolError(String)

    var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            return "Bundled av binary is unavailable."
        case .commandFailed(let output):
            return output
        case .connectionFailed(let reason):
            return reason
        case .invalidResponse(let reason):
            return reason
        case .protocolError(let reason):
            return reason
        }
    }
}

final class NucleusBridge {
    enum CompatibilityPolicy {
        case strict
        case protocolOnly
    }

    enum DaemonOwnership {
        case client
        case owner
    }

    private struct EmptyParams: Encodable {}

    private struct SearchParams: Encodable {
        let query: String
        let offset: Int
        let limit: Int
    }

    private struct PageParams: Encodable {
        let offset: Int
        let limit: Int
        let category: String?
        let sort: String?
    }

    private struct PackageInfoParams: Encodable {
        let package: String
    }

    private struct IsotopeParams: Encodable {
        let isotope: String
    }

    private struct ProtocolRequest<Params: Encodable>: Encodable {
        let id: Int
        let method: String
        let params: Params
    }

    private struct ProtocolResponse<Result: Decodable>: Decodable {
        let id: Int
        let result: Result?
        let error: ProtocolFailure?
    }

    private struct ProtocolFailure: Decodable {
        let code: Int
        let message: String
    }

    private struct ProtocolConnection {
        let descriptor: Int32
    }

    private struct ListInstalledResponse: Decodable {
        let packages: [PackageRecord]
    }

    private struct ListOutdatedResponse: Decodable {
        let packages: [OutdatedPackageRecord]
    }

    private struct SystemInfoResponse: Decodable {
        let protocolVersion: String
        let version: String
        let buildId: String
    }

    struct IsotopeMigrationPlan: Decodable {
        let isotopeName: String
        let replacesPackage: String?
        let modifiesPackage: String?
        let isRadioisotope: Bool?
        let hasMigration: Bool
    }

    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()
    private let encoder = JSONEncoder()
    private let protocolQueue = DispatchQueue(label: "com.automic.vault.nucleus.protocol")
    private var connection: ProtocolConnection?
    private var daemonProcess: Process?
    private var nextRequestID = 0
    private var readBuffer = Data()
    private var forcedFreshDaemonThisLaunch = false
    private let compatibilityPolicy: CompatibilityPolicy
    private let daemonOwnership: DaemonOwnership
    private let expectedProtocolVersion = Bundle.main.object(
        forInfoDictionaryKey: "NukeProtocolVersion"
    ) as? String ?? "1.16"
    private let expectedBuildID = Bundle.main.object(
        forInfoDictionaryKey: "NukeBuildID"
    ) as? String ?? "unknown"

    init(
        compatibilityPolicy: CompatibilityPolicy = .strict,
        daemonOwnership: DaemonOwnership = .client
    ) {
        self.compatibilityPolicy = compatibilityPolicy
        self.daemonOwnership = daemonOwnership
    }

    func isAvInstalledAtSystemPath() -> Bool {
        FileManager.default.isExecutableFile(atPath: "/usr/local/bin/av")
    }

    func cliToolsRecommendation() -> PackageRecommendation? {
        let toolNames = ["av"]
        let missingToolNames = toolNames.filter { toolName in
            FileManager.default.isExecutableFile(atPath: "/usr/local/bin/\(toolName)") == false
        }
        let appVersion = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String ?? "0.0.0"
        let installedVersion = installedAvVersion()
        let isOutdated = installedVersion.map { $0 != appVersion } ?? false
        guard missingToolNames.isEmpty == false || isOutdated else {
            return nil
        }
        return PackageRecommendation.automicVaultCLT(
            installedVersion: installedVersion,
            latestVersion: appVersion,
            missingToolNames: missingToolNames
        )
    }

    func xcodeCLTRecommendation() -> PackageRecommendation? {
        guard isXcodeCLTInstalled() == false else {
            return nil
        }
        return PackageRecommendation.xcodeCLT()
    }

    private func isXcodeCLTInstalled() -> Bool {
        FileManager.default.isExecutableFile(
            atPath: "/Library/Developer/CommandLineTools/usr/bin/clang"
        )
    }

    func exportBundledCLTForHelperInstall() throws -> URL {
        let stagingDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: stagingDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        for toolName in ["av"] {
            let bundled = try resolveBinaryURL(named: toolName)
            let stagedBinary = stagingDirectory.appendingPathComponent(
                toolName,
                isDirectory: false
            )
            try FileManager.default.copyItem(at: bundled, to: stagedBinary)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: stagedBinary.path
            )
        }
        return stagingDirectory
    }

    func fetchPackages() throws -> [PackageRecord] {
        try performProtocolRequest(
            method: "packages.listInstalled",
            params: EmptyParams(),
            as: ListInstalledResponse.self
        ).packages
    }

    func fetchAvailablePackages(
        offset: Int,
        limit: Int,
        category: String? = nil,
        sortOrder: CategoryPackageSortOrder = .rank
    ) throws -> PackageSearchPage {
        try performProtocolRequest(
            method: "packages.listAvailable",
            params: PageParams(
                offset: offset,
                limit: limit,
                category: category,
                sort: sortOrder.protocolValue
            ),
            as: PackageSearchPage.self
        )
    }

    func fetchPulsePackages(
        offset: Int,
        limit: Int
    ) throws -> PackageSearchPage {
        try performProtocolRequest(
            method: "packages.listPulse",
            params: PageParams(offset: offset, limit: limit, category: nil, sort: nil),
            as: PackageSearchPage.self
        )
    }

    func fetchGeigerPackages(
        offset: Int,
        limit: Int
    ) throws -> PackageSearchPage {
        try performProtocolRequest(
            method: "packages.listGeiger",
            params: PageParams(offset: offset, limit: limit, category: nil, sort: nil),
            as: PackageSearchPage.self
        )
    }

    func fetchSecurityRecommendationPackages(
        offset: Int,
        limit: Int
    ) throws -> PackageSearchPage {
        try performProtocolRequest(
            method: "packages.listSecurityRecommendations",
            params: PageParams(offset: offset, limit: limit, category: nil, sort: nil),
            as: PackageSearchPage.self
        )
    }

    func fetchOutdatedPackages() throws -> [OutdatedPackageRecord] {
        try performProtocolRequest(
            method: "packages.listOutdated",
            params: EmptyParams(),
            as: ListOutdatedResponse.self
        ).packages
    }

    func fetchSearchResults(
        query: String,
        offset: Int,
        limit: Int
    ) throws -> PackageSearchPage {
        try performProtocolRequest(
            method: "packages.search",
            params: SearchParams(query: query, offset: offset, limit: limit),
            as: PackageSearchPage.self
        )
    }

    func fetchDetail(packageName: String) throws -> PackageDetail {
        try performProtocolRequest(
            method: "packages.info",
            params: PackageInfoParams(package: packageName),
            as: PackageDetail.self
        )
    }

    func fetchIsotopeMigrationPlan(isotopeName: String) throws -> IsotopeMigrationPlan {
        try performProtocolRequest(
            method: "packages.isotopeMigrationPlan",
            params: IsotopeParams(isotope: isotopeName),
            as: IsotopeMigrationPlan.self
        )
    }

    func migrateIsotope(isotopeName: String) throws -> IsotopeMigrationPlan {
        try performProtocolRequest(
            method: "packages.migrateIsotope",
            params: IsotopeParams(isotope: isotopeName),
            as: IsotopeMigrationPlan.self
        )
    }

    func invalidate() {
        protocolQueue.sync {
            resetProtocolConnection()
            terminateDaemonIfNeeded()
        }
    }

    func invalidateSharedProtocolDaemon() {
        protocolQueue.sync {
            resetProtocolConnection()
            terminateDaemonIfNeeded()
            try? stopStaleProtocolDaemon()
        }
    }

    private func performProtocolRequest<Params: Encodable, Result: Decodable>(
        method: String,
        params: Params,
        as type: Result.Type
    ) throws -> Result {
        try protocolQueue.sync {
            try sendProtocolRequest(
                method: method,
                params: params,
                as: type,
                allowReconnect: true
            )
        }
    }

    private func sendProtocolRequest<Params: Encodable, Result: Decodable>(
        method: String,
        params: Params,
        as type: Result.Type,
        allowReconnect: Bool
    ) throws -> Result {
        do {
            let connection = try ensureProtocolConnection()
            return try sendProtocolRequest(
                over: connection,
                method: method,
                params: params,
                as: type
            )
        } catch {
            if allowReconnect, isRecoverableProtocolError(error) {
                resetProtocolConnection()
                return try sendProtocolRequest(
                    method: method,
                    params: params,
                    as: type,
                    allowReconnect: false
                )
            }
            throw error
        }
    }

    private func ensureProtocolConnection() throws -> ProtocolConnection {
        if let connection {
            return connection
        }

        guard daemonOwnership == .owner else {
            return try connectToProtocolDaemon()
        }

        return try withProtocolStartupLock {
            if self.shouldForceFreshDaemonOnLaunch,
               self.forcedFreshDaemonThisLaunch == false {
                try self.stopStaleProtocolDaemon()
                self.daemonProcess = nil
                self.forcedFreshDaemonThisLaunch = true
            }
            return try self.startAndConnectToProtocolDaemon()
        }
    }

    private func connectToProtocolDaemon() throws -> ProtocolConnection {
        let deadline = Date().addingTimeInterval(2.0)
        while Date() < deadline {
            if let connected = try connectToProtocolSocket() {
                try validateCompatibility(of: connected)
                connection = connected
                return connected
            }
            Thread.sleep(forTimeInterval: 0.05)
        }

        throw NucleusBridgeError.connectionFailed(
            "nucleus daemon is unavailable"
        )
    }

    private func startAndConnectToProtocolDaemon() throws -> ProtocolConnection {
        let binaryURL = try resolveBinaryURL()
        if try protocolSocketIsOwnedByDifferentBinary(expectedBinaryURL: binaryURL) {
            try stopStaleProtocolDaemon()
            daemonProcess = nil
        }

        if let connected = try connectToProtocolSocket() {
            do {
                try validateCompatibility(of: connected)
                connection = connected
                return connected
            } catch {
                guard isCompatibilityMismatch(error) else {
                    throw error
                }
                try stopStaleProtocolDaemon()
                daemonProcess = nil
            }
        }

        try startProtocolDaemonIfNeeded(binaryURL: binaryURL)
        return try connectToProtocolDaemon()
    }

    private func connectToProtocolSocket() throws -> ProtocolConnection? {
        let socketPath = protocolSocketURL().path
        guard FileManager.default.fileExists(atPath: socketPath) else {
            return nil
        }

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw NucleusBridgeError.connectionFailed(lastPOSIXError())
        }

        do {
            try configureSocket(descriptor)
            var address = try makeSocketAddress(path: socketPath)
            let addressLength = socklen_t(MemoryLayout.size(ofValue: address))
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { addressPointer in
                    connect(
                        descriptor,
                        addressPointer,
                        addressLength
                    )
                }
            }

            if result != 0 {
                let code = errno
                close(descriptor)
                if code == ENOENT || code == ECONNREFUSED {
                    return nil
                }
                throw NucleusBridgeError.connectionFailed(String(cString: strerror(code)))
            }

            return ProtocolConnection(
                descriptor: descriptor
            )
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func startProtocolDaemonIfNeeded(binaryURL: URL? = nil) throws {
        if let daemonProcess, daemonProcess.isRunning {
            return
        }

        let binaryURL = try binaryURL ?? resolveBinaryURL()
        let process = Process()
        process.executableURL = binaryURL
        process.arguments = [ "serve" ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] terminated in
            self?.protocolQueue.async {
                if self?.daemonProcess === terminated {
                    self?.daemonProcess = nil
                }
            }
        }
        try process.run()
        daemonProcess = process
    }

    private func protocolSocketIsOwnedByDifferentBinary(expectedBinaryURL: URL) throws -> Bool {
        let socketPath = protocolSocketURL().path
        guard FileManager.default.fileExists(atPath: socketPath) else {
            return false
        }

        let expectedPath = canonicalExecutablePath(expectedBinaryURL.path)
        let ownerPIDs = try processIDsUsingSocket(at: socketPath)
        for pid in ownerPIDs {
            guard let ownerPath = executablePath(for: pid) else {
                continue
            }
            if canonicalExecutablePath(ownerPath) != expectedPath {
                return true
            }
        }
        return false
    }

    private func canonicalExecutablePath(_ path: String) -> String {
        URL(fileURLWithPath: path)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
    }

    private func terminateDaemonIfNeeded() {
        guard let daemonProcess else {
            return
        }
        if daemonProcess.isRunning {
            daemonProcess.terminate()
            daemonProcess.waitUntilExit()
        }
        self.daemonProcess = nil
    }

    private func validateCompatibility(of connection: ProtocolConnection) throws {
        let info = try sendProtocolRequest(
            over: connection,
            method: "system.info",
            params: EmptyParams(),
            as: SystemInfoResponse.self
        )
        guard info.protocolVersion == expectedProtocolVersion else {
            close(connection.descriptor)
            throw NucleusBridgeError.connectionFailed(
                "protocol mismatch: expected \(expectedProtocolVersion), got \(info.protocolVersion)"
            )
        }
        guard compatibilityPolicy == .strict else {
            return
        }
        guard info.buildId == expectedBuildID else {
            close(connection.descriptor)
            throw NucleusBridgeError.connectionFailed(
                "daemon build mismatch: expected \(expectedBuildID), got \(info.buildId)"
            )
        }
    }

    private func sendProtocolRequest<Params: Encodable, Result: Decodable>(
        over connection: ProtocolConnection,
        method: String,
        params: Params,
        as type: Result.Type
    ) throws -> Result {
        nextRequestID += 1
        let request = ProtocolRequest(id: nextRequestID, method: method, params: params)
        let requestData = try encoder.encode(request)
        try writeAll(requestData + Data([0x0a]), to: connection.descriptor)

        let responseData = try readProtocolLine(from: connection.descriptor)
        let response = try decoder.decode(ProtocolResponse<Result>.self, from: responseData)

        guard response.id == request.id else {
            throw NucleusBridgeError.invalidResponse(
                "mismatched protocol response id \(response.id) for request \(request.id)"
            )
        }
        if let error = response.error {
            throw NucleusBridgeError.protocolError("protocol \(error.code): \(error.message)")
        }
        guard let result = response.result else {
            throw NucleusBridgeError.invalidResponse("protocol response missing result")
        }
        return result
    }

    private func readProtocolLine(from descriptor: Int32) throws -> Data {
        while true {
            if let newlineIndex = readBuffer.firstIndex(of: 0x0a) {
                let line = readBuffer.prefix(upTo: newlineIndex)
                readBuffer.removeSubrange(...newlineIndex)
                return Data(line)
            }

            var buffer = [UInt8](repeating: 0, count: 4096)
            let count = read(descriptor, &buffer, buffer.count)
            if count < 0 {
                throw NucleusBridgeError.connectionFailed(lastPOSIXError())
            }
            guard count > 0 else {
                throw NucleusBridgeError.connectionFailed("nucleus protocol connection closed")
            }
            readBuffer.append(buffer, count: count)
        }
    }

    private func resetProtocolConnection() {
        if let descriptor = connection?.descriptor {
            close(descriptor)
        }
        connection = nil
        readBuffer.removeAll(keepingCapacity: true)
    }

    private func stopStaleProtocolDaemon() throws {
        let socketPath = protocolSocketURL().path
        guard FileManager.default.fileExists(atPath: socketPath) else {
            return
        }

        let ownerPIDs = try processIDsUsingSocket(at: socketPath)
        for pid in ownerPIDs {
            if kill(pid_t(pid), SIGTERM) != 0 && errno != ESRCH {
                throw NucleusBridgeError.connectionFailed(lastPOSIXError())
            }
        }

        let deadline = Date().addingTimeInterval(1.0)
        while Date() < deadline {
            let remaining = try processIDsUsingSocket(at: socketPath)
            if remaining.isEmpty {
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }

        if FileManager.default.fileExists(atPath: socketPath) {
            try? FileManager.default.removeItem(atPath: socketPath)
        }
    }

    private func processIDsUsingSocket(at path: String) throws -> [Int32] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-t", path]

        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 || process.terminationStatus == 1 else {
            throw NucleusBridgeError.connectionFailed("unable to inspect protocol socket owner")
        }

        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: outputData, encoding: .utf8) else {
            return []
        }
        return output
            .split(whereSeparator: \.isNewline)
            .compactMap { Int32($0) }
    }

    private func executablePath(for pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let count = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard count > 0 else {
            return nil
        }
        return String(cString: buffer)
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else {
                return
            }

            var totalWritten = 0
            while totalWritten < rawBuffer.count {
                let bytesWritten = write(
                    descriptor,
                    baseAddress.advanced(by: totalWritten),
                    rawBuffer.count - totalWritten
                )
                if bytesWritten < 0 {
                    throw NucleusBridgeError.connectionFailed(lastPOSIXError())
                }
                totalWritten += bytesWritten
            }
        }
    }

    private func isRecoverableProtocolError(_ error: Error) -> Bool {
        if case NucleusBridgeError.connectionFailed = error {
            return true
        }
        if let cocoaError = error as? CocoaError {
            return cocoaError.code == .fileReadUnknown || cocoaError.code == .fileWriteUnknown
        }
        return false
    }

    private func isCompatibilityMismatch(_ error: Error) -> Bool {
        guard case NucleusBridgeError.connectionFailed(let reason) = error else {
            return false
        }
        return reason.hasPrefix("protocol mismatch:")
            || reason.hasPrefix("daemon build mismatch:")
    }

    private func protocolSocketURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Automic Vault", isDirectory: true)
            .appendingPathComponent("nucleus.sock", isDirectory: false)
    }

    private func protocolStartupLockURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Automic Vault", isDirectory: true)
            .appendingPathComponent("nucleus-start.lock", isDirectory: false)
    }

    private var shouldForceFreshDaemonOnLaunch: Bool {
        daemonOwnership == .owner
            && Bundle.main.bundleURL.path.contains("/target/gui/")
    }

    private func withProtocolStartupLock<Result>(
        _ body: () throws -> Result
    ) throws -> Result {
        let lockURL = protocolStartupLockURL()
        try FileManager.default.createDirectory(
            at: lockURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: nil
        )

        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else {
            throw NucleusBridgeError.connectionFailed(lastPOSIXError())
        }

        guard flock(descriptor, LOCK_EX) == 0 else {
            let error = lastPOSIXError()
            close(descriptor)
            throw NucleusBridgeError.connectionFailed(error)
        }

        defer {
            flock(descriptor, LOCK_UN)
            close(descriptor)
        }
        return try body()
    }

    private func configureSocket(_ descriptor: Int32) throws {
        var noSigPipe: Int32 = 1
        let result = setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSigPipe,
            socklen_t(MemoryLayout.size(ofValue: noSigPipe))
        )
        guard result == 0 else {
            throw NucleusBridgeError.connectionFailed(lastPOSIXError())
        }
    }

    private func makeSocketAddress(path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        #if os(macOS)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        #endif
        address.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = Array(path.utf8)
        let maxLength = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count < maxLength else {
            throw NucleusBridgeError.connectionFailed("protocol socket path is too long")
        }

        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            rawBuffer.initializeMemory(as: UInt8.self, repeating: 0)
            rawBuffer.copyBytes(from: pathBytes)
        }
        return address
    }

    private func lastPOSIXError() -> String {
        String(cString: strerror(errno))
    }

    private func resolveBinaryURL() throws -> URL {
        try resolveBinaryURL(named: "av")
    }

    private func resolveBinaryURL(named binaryName: String) throws -> URL {
        if let bundled = Bundle.main.url(forResource: binaryName, withExtension: nil),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }

        let development = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("target/release/\(binaryName)")
        if FileManager.default.isExecutableFile(atPath: development.path) {
            return development
        }

        let debug = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("target/debug/\(binaryName)")
        if FileManager.default.isExecutableFile(atPath: debug.path) {
            return debug
        }

        throw NucleusBridgeError.binaryNotFound
    }

    private func installedAvVersion() -> String? {
        let avPath = "/usr/local/bin/av"
        guard FileManager.default.isExecutableFile(atPath: avPath) else {
            return nil
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: avPath)
        process.arguments = ["--version"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        guard process.terminationStatus == 0 else {
            return nil
        }

        let outputData = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: outputData, encoding: .utf8) else {
            return nil
        }
        return output
            .split(whereSeparator: \.isWhitespace)
            .last
            .map(String.init)
    }
}
