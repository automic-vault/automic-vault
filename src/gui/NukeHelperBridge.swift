import Foundation
import LocalAuthentication
import Security
import ServiceManagement
import ServiceManagementShim

enum NukeHelperBridgeError: Error, LocalizedError {
    case unsignedBuild(String)
    case authorizationFailed(String)
    case blessingFailed(String)
    case connectionFailed(String)
    case invalidResponse(String)
    case operationFailed(String)
    case biometricUnavailable(String)
    case biometricDenied(String)
    case biometricCanceled

    var errorDescription: String? {
        switch self {
        case .unsignedBuild(let message),
             .authorizationFailed(let message),
             .blessingFailed(let message),
             .connectionFailed(let message),
             .invalidResponse(let message),
             .operationFailed(let message),
             .biometricUnavailable(let message),
             .biometricDenied(let message):
            return message
        case .biometricCanceled:
            return L10n.string("Authentication canceled.")
        }
    }
}

struct NukeHelperResult {
    let message: String
    let processedPackages: [String]
    let value: String?
}

enum DotenvApprovalPolicy: String, Equatable {
    case approveEveryTime = "approve_every_time"
    case rememberApproved = "remember_approved"
}

enum NukeHelperProgressEvent {
    case resolving
    case downloading(package: String, bytesPerSecond: UInt64, progress: Double)
    case installing(package: String)
    case log(package: String, message: String)
    case completed(package: String)
    case error(message: String)
}

enum NukeHelperMaintenanceResult {
    case completed(updated: Bool)
    case pendingHelperInstallation
}

enum NukeHelperMaintenanceState {
    case notInstalled
    case current
    case needsUpdate
}

@objc(AVPackageSpec)
final class AVPackageSpec: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let name: String
    let version: String?

    init(name: String, version: String? = nil) {
        self.name = name
        self.version = version
        super.init()
    }

    required init?(coder: NSCoder) {
        guard let name = coder.decodeObject(of: NSString.self, forKey: "name") as String? else {
            return nil
        }
        self.name = name
        self.version = coder.decodeObject(of: NSString.self, forKey: "version") as String?
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(name as NSString, forKey: "name")
        if let version {
            coder.encode(version as NSString, forKey: "version")
        }
    }
}

@objc protocol NukeHelperProtocol {
    func install(_ packages: [AVPackageSpec], reply: @escaping ([String: Any]) -> Void)
    func update(_ packages: [AVPackageSpec], reply: @escaping ([String: Any]) -> Void)
    func uninstall(_ packages: [AVPackageSpec], reply: @escaping ([String: Any]) -> Void)
    func makeDefault(_ packages: [AVPackageSpec], reply: @escaping ([String: Any]) -> Void)
    func updateAll(_ reply: @escaping ([String: Any]) -> Void)
    func installAv(_ sourcePath: String, reply: @escaping ([String: Any]) -> Void)
    func installIsotopeRoot(_ isotopeName: String, reply: @escaping ([String: Any]) -> Void)
    func convertRadioisotope(_ isotopeName: String, reply: @escaping ([String: Any]) -> Void)
    func installIsotopeStubs(_ isotopeName: String, reply: @escaping ([String: Any]) -> Void)
    func rememberIsotopeAlwaysAllow(
        _ executablePath: String,
        scriptPath: String?,
        scriptSha256: String?,
        keys: [String],
        reply: @escaping ([String: Any]) -> Void
    )
    func dotenvApprovalPolicy(_ reply: @escaping ([String: Any]) -> Void)
    func setDotenvApprovalPolicy(
        _ policy: String,
        reply: @escaping ([String: Any]) -> Void
    )
    func rememberDotenvApproval(
        _ mode: String,
        envFilePath: String,
        projectRoot: String,
        envSha256: String,
        publicKeyFingerprint: String,
        keys: [String],
        reply: @escaping ([String: Any]) -> Void
    )
    func refreshRemoteDatabase(_ reply: @escaping (Bool) -> Void)
    func checkForUpdates(_ reply: @escaping (Bool) -> Void)
}

@objc protocol NukeHelperProgressProtocol {
    func progressEvent(_ event: [String: Any])
}

private final class NukeHelperProgressRelay: NSObject, NukeHelperProgressProtocol {
    var onEvent: ((NukeHelperProgressEvent) -> Void)?

    func progressEvent(_ event: [String: Any]) {
        guard let parsed = Self.parse(event) else { return }
        DispatchQueue.main.async {
            self.onEvent?(parsed)
        }
    }

    private static func parse(_ event: [String: Any]) -> NukeHelperProgressEvent? {
        if event["Resolving"] != nil {
            return .resolving
        }
        if let payload = event["Installing"] as? [String: Any],
           let package = payload["package"] as? String {
            return .installing(package: package)
        }
        if let payload = event["Log"] as? [String: Any],
           let package = payload["package"] as? String,
           let message = payload["message"] as? String {
            return .log(package: package, message: message)
        }
        if let payload = event["Completed"] as? [String: Any],
           let package = payload["package"] as? String {
            return .completed(package: package)
        }
        if let payload = event["Error"] as? [String: Any],
           let message = payload["message"] as? String {
            return .error(message: message)
        }
        if let payload = event["Downloading"] as? [String: Any],
           let package = payload["package"] as? String {
            let bytesPerSecond = (payload["bytes_per_sec"] as? NSNumber)?.uint64Value ?? 0
            let progress = (payload["progress"] as? NSNumber)?.doubleValue ?? 0
            return .downloading(
                package: package,
                bytesPerSecond: bytesPerSecond,
                progress: progress
            )
        }
        return nil
    }
}

final class NukeHelperStartupReplyGuard<Value> {
    private let lock = NSLock()
    private let operationName: String
    private let startupTimeout: TimeInterval
    private let activityTimeout: TimeInterval?
    private let completion: (Result<Value, Error>) -> Void
    private let onFailure: () -> Void
    private var didStart = false
    private var didFinish = false
    private var activityGeneration = 0

    init(
        operationName: String,
        startupTimeout: TimeInterval,
        activityTimeout: TimeInterval?,
        completion: @escaping (Result<Value, Error>) -> Void,
        onFailure: @escaping () -> Void
    ) {
        self.operationName = operationName
        self.startupTimeout = startupTimeout
        self.activityTimeout = activityTimeout
        self.completion = completion
        self.onFailure = onFailure
    }

    func startWatchdog() {
        DispatchQueue.main.asyncAfter(deadline: .now() + startupTimeout) {
            self.failIfNotStarted()
        }
    }

    func markStarted() {
        lock.lock()
        didStart = true
        activityGeneration += 1
        let generation = activityGeneration
        lock.unlock()
        scheduleActivityWatchdog(generation: generation)
    }

    func complete(_ result: Result<Value, Error>) {
        finish(result, shouldInvalidate: false)
    }

    func fail(_ error: Error) {
        finish(.failure(error), shouldInvalidate: true)
    }

    private func failIfNotStarted() {
        lock.lock()
        let shouldFail = !didStart && !didFinish
        lock.unlock()
        guard shouldFail else { return }

        fail(NukeHelperBridgeError.connectionFailed(
            "\(operationName) did not receive a response from the privileged helper. The helper may have crashed or failed its startup checks."
        ))
    }

    private func scheduleActivityWatchdog(generation: Int) {
        guard let activityTimeout else { return }

        DispatchQueue.main.asyncAfter(deadline: .now() + activityTimeout) {
            self.failIfInactive(since: generation)
        }
    }

    private func failIfInactive(since generation: Int) {
        lock.lock()
        let shouldFail = didStart && !didFinish && activityGeneration == generation
        lock.unlock()
        guard shouldFail else { return }

        fail(NukeHelperBridgeError.connectionFailed(
            "\(operationName) stopped receiving responses from the privileged helper. The helper may have crashed during the operation."
        ))
    }

    private func finish(
        _ result: Result<Value, Error>,
        shouldInvalidate: Bool
    ) {
        lock.lock()
        guard didFinish == false else {
            lock.unlock()
            return
        }
        didFinish = true
        lock.unlock()

        if shouldInvalidate {
            onFailure()
        }
        DispatchQueue.main.async {
            self.completion(result)
        }
    }
}

private struct NukeHelperCodeIdentity {
    let identifier: String
    let teamIdentifier: String?
    let bundleVersion: String
}

final class NukeHelperBridge {
    static let serviceName = "com.automicvault.nuke-helper"
    static let appBundleIdentifier = "com.automicvault"

    private static let helperStartupTimeout: TimeInterval = 15
    private static let helperActivityTimeout: TimeInterval = 120

    private let queue = DispatchQueue(label: "com.automicvault.helper.bridge")
    private var connection: NSXPCConnection?
    private let progressRelay = NukeHelperProgressRelay()

    #if DEBUG
    static let debugFakeUpdatePackages = [
        "brew:sqlite",
        "npm:tsx",
        "pypi:uv",
        "cask:keepingyouawake",
        "isotope:gh"
    ]

    func debugFakeUpdate(
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        var events: [(TimeInterval, NukeHelperProgressEvent)] = [(0.20, .resolving)]
        func appendDownload(package: String, start: TimeInterval, speed: UInt64) -> TimeInterval {
            let steps: [Double] = [0.05, 0.14, 0.25, 0.38, 0.51, 0.66, 0.81, 0.94, 0.99]
            let stepInterval = 0.24
            for (index, step) in steps.enumerated() {
                events.append((
                    start + (Double(index) * stepInterval),
                    .downloading(
                        package: package,
                        bytesPerSecond: speed + UInt64(index * 72_000),
                        progress: step
                    )
                ))
            }
            let installAt = start + (Double(steps.count) * stepInterval) + 0.18
            events.append((installAt, .installing(package: package)))
            events.append((installAt + 0.24, .completed(package: package)))
            return installAt + 0.48
        }

        var cursor = 0.45
        cursor = appendDownload(package: "sqlite", start: cursor, speed: 1_240_000)
        events.append((0.60, .downloading(package: "zstd", bytesPerSecond: 680_000, progress: 0.32)))
        events.append((0.70, .log(package: "zstd", message: "dependency already current")))
        cursor = appendDownload(package: "npm:tsx", start: cursor, speed: 910_000)
        cursor = appendDownload(package: "pypi:uv", start: cursor, speed: 1_450_000)
        cursor = appendDownload(package: "keepingyouawake", start: cursor, speed: 840_000)
        cursor = appendDownload(package: "isotope:gh", start: cursor, speed: 1_320_000)
        for (delay, event) in events {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                progress(event)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + cursor + 0.20) {
            completion(.success(NukeHelperResult(
                message: "Debug fake update complete",
                processedPackages: Self.debugFakeUpdatePackages,
                value: nil
            )))
        }
    }
    #endif

    private enum HelperBlessingPolicy {
        case blessIfNeeded
        case installedOnly
        case compatibleInstalledOnly
    }

    func authenticateBiometrics(reason: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let context = LAContext()
        context.localizedCancelTitle = L10n.string("Abort")
        var authError: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) {
            evaluateAuthentication(
                context: context,
                policy: .deviceOwnerAuthenticationWithBiometrics,
                reason: reason,
                completion: completion
            )
            return
        }

        var ownerAuthError: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &ownerAuthError) {
            evaluateAuthentication(
                context: context,
                policy: .deviceOwnerAuthentication,
                reason: reason,
                completion: completion
            )
            return
        }

        completion(.failure(NukeHelperBridgeError.biometricUnavailable(
            ownerAuthError?.localizedDescription
                ?? authError?.localizedDescription
                ?? L10n.string("Touch ID and password authentication are unavailable.")
        )))
    }

    private func evaluateAuthentication(
        context: LAContext,
        policy: LAPolicy,
        reason: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            if !success,
               policy == .deviceOwnerAuthenticationWithBiometrics,
               let nsError = error as NSError?,
               LAError(_nsError: nsError).code == .biometryLockout,
               context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
                self.evaluateAuthentication(
                    context: context,
                    policy: .deviceOwnerAuthentication,
                    reason: reason,
                    completion: completion
                )
                return
            }

            DispatchQueue.main.async {
                if success {
                    completion(.success(()))
                } else if Self.isUserAuthenticationCancel(error) {
                    completion(.failure(NukeHelperBridgeError.biometricCanceled))
                } else {
                    completion(.failure(NukeHelperBridgeError.biometricDenied(
                        error?.localizedDescription ?? L10n.string("Biometric authorization failed.")
                    )))
                }
            }
        }
    }

    private static func isUserAuthenticationCancel(_ error: Error?) -> Bool {
        guard let nsError = error as NSError? else {
            return false
        }
        return LAError(_nsError: nsError).code == .userCancel
    }

    func checkForUpdates(completion: @escaping (Result<Bool, Error>) -> Void) {
        queue.async {
            do {
                guard let proxy = try self.remoteProxy(
                    progressHandler: nil,
                    blessingPolicy: .compatibleInstalledOnly
                ) else {
                    DispatchQueue.main.async {
                        completion(.success(false))
                    }
                    return
                }
                proxy.checkForUpdates { hasUpdates in
                    DispatchQueue.main.async {
                        completion(.success(hasUpdates))
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func refreshRemoteDatabase(
        completion: ((Result<NukeHelperMaintenanceResult, Error>) -> Void)? = nil
    ) {
        queue.async {
            do {
                guard let proxy = try self.remoteProxy(
                    progressHandler: nil,
                    blessingPolicy: .compatibleInstalledOnly
                ) else {
                    DispatchQueue.main.async {
                        completion?(.success(.pendingHelperInstallation))
                    }
                    return
                }
                proxy.refreshRemoteDatabase { updated in
                    if updated {
                        self.queue.async {
                            self.connection?.invalidate()
                            self.connection = nil
                            NucleusBridge(
                                compatibilityPolicy: .protocolOnly,
                                daemonOwnership: .owner
                            ).invalidateSharedProtocolDaemon()
                            DispatchQueue.main.async {
                                completion?(.success(.completed(updated: updated)))
                            }
                        }
                        return
                    }
                    DispatchQueue.main.async {
                        completion?(.success(.completed(updated: updated)))
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion?(.failure(error))
                }
            }
        }
    }

    func helperNeedsInstallationOrUpdate(completion: @escaping (Result<Bool, Error>) -> Void) {
        queue.async {
            do {
                let needsInstallationOrUpdate = try self.helperRequiresBlessing()
                DispatchQueue.main.async {
                    completion(.success(needsInstallationOrUpdate))
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func helperMaintenanceState(
        completion: @escaping (Result<NukeHelperMaintenanceState, Error>) -> Void
    ) {
        queue.async {
            do {
                let state = try self.currentHelperMaintenanceState()
                DispatchQueue.main.async {
                    completion(.success(state))
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func installOrUpdateHelper(
        completion: @escaping (Result<NukeHelperMaintenanceResult, Error>) -> Void
    ) {
        queue.async {
            let replyGuard = NukeHelperStartupReplyGuard<NukeHelperMaintenanceResult>(
                operationName: L10n.string("Update Helper"),
                startupTimeout: Self.helperStartupTimeout,
                activityTimeout: nil,
                completion: completion
            ) { [weak self] in
                self?.invalidateConnection()
            }

            do {
                let hadPendingMaintenance = try self.helperRequiresBlessing()
                let proxy = try self.privilegedRemoteProxy(
                    progressHandler: nil,
                    errorHandler: { error in
                        replyGuard.fail(NukeHelperBridgeError.connectionFailed(
                            "Privileged helper connection failed: \(error.localizedDescription)"
                        ))
                    }
                )
                replyGuard.startWatchdog()
                proxy.checkForUpdates { _ in
                    replyGuard.complete(.success(.completed(updated: hadPendingMaintenance)))
                }
            } catch {
                replyGuard.fail(error)
            }
        }
    }

    func updateAll(
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Update All"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.updateAll(reply)
        }
    }

    func installAv(
        sourcePath: String,
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Install Automic Vault CLT"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.installAv(sourcePath, reply: reply)
        }
    }

    func installIsotopeStubs(
        isotopeName: String,
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Install Isotope Stubs"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.installIsotopeStubs(isotopeName, reply: reply)
        }
    }

    func installIsotopeRoot(
        isotopeName: String,
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Install Isotope Root"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.installIsotopeRoot(isotopeName, reply: reply)
        }
    }

    func convertRadioisotope(
        isotopeName: String,
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Convert Radioisotope"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.convertRadioisotope(isotopeName, reply: reply)
        }
    }

    func rememberIsotopeAlwaysAllow(
        executablePath: String,
        scriptPath: String?,
        scriptSha256: String?,
        keys: [String],
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        queue.async {
            do {
                let proxy = try self.privilegedRemoteProxy(
                    progressHandler: nil,
                    errorHandler: { error in
                        DispatchQueue.main.async {
                            completion(.failure(error))
                        }
                    }
                )
                proxy.rememberIsotopeAlwaysAllow(
                    executablePath,
                    scriptPath: scriptPath,
                    scriptSha256: scriptSha256,
                    keys: keys
                ) { result in
                    self.complete(result, completion: completion)
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func dotenvApprovalPolicy(
        completion: @escaping (Result<DotenvApprovalPolicy, Error>) -> Void
    ) {
        queue.async {
            do {
                guard let proxy = try self.remoteProxy(
                    progressHandler: nil,
                    blessingPolicy: .installedOnly
                ) else {
                    DispatchQueue.main.async {
                        completion(.success(.approveEveryTime))
                    }
                    return
                }
                proxy.dotenvApprovalPolicy { result in
                    self.complete(result) { parsed in
                        switch parsed {
                        case .success(let helperResult):
                            let policy = helperResult.value
                                .flatMap(DotenvApprovalPolicy.init(rawValue:))
                                ?? .approveEveryTime
                            completion(.success(policy))
                        case .failure(let error):
                            completion(.failure(error))
                        }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func setDotenvApprovalPolicy(
        _ policy: DotenvApprovalPolicy,
        completion: @escaping (Result<DotenvApprovalPolicy, Error>) -> Void
    ) {
        queue.async {
            do {
                let proxy = try self.privilegedRemoteProxy(
                    progressHandler: nil,
                    errorHandler: { error in
                        DispatchQueue.main.async {
                            completion(.failure(error))
                        }
                    }
                )
                proxy.setDotenvApprovalPolicy(policy.rawValue) { result in
                    self.complete(result) { parsed in
                        switch parsed {
                        case .success(let helperResult):
                            let policy = helperResult.value
                                .flatMap(DotenvApprovalPolicy.init(rawValue:))
                                ?? policy
                            completion(.success(policy))
                        case .failure(let error):
                            completion(.failure(error))
                        }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func rememberDotenvApproval(
        _ approval: DotenvApprovalRequestSnapshot,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        queue.async {
            do {
                let proxy = try self.privilegedRemoteProxy(
                    progressHandler: nil,
                    errorHandler: { error in
                        DispatchQueue.main.async {
                            completion(.failure(error))
                        }
                    }
                )
                proxy.rememberDotenvApproval(
                    approval.mode.rawValue,
                    envFilePath: approval.envFilePath,
                    projectRoot: approval.projectRoot,
                    envSha256: approval.envSha256,
                    publicKeyFingerprint: approval.publicKeyFingerprint,
                    keys: approval.keys
                ) { result in
                    self.complete(result, completion: completion)
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func install(
        packages: [AVPackageSpec],
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Install Package"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.install(packages, reply: reply)
        }
    }

    func update(
        packages: [AVPackageSpec],
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Update Package"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.update(packages, reply: reply)
        }
    }

    func uninstall(
        packages: [AVPackageSpec],
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Uninstall Package"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.uninstall(packages, reply: reply)
        }
    }

    func makeDefault(
        packages: [AVPackageSpec],
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        performPrivilegedResultCommand(
            operationName: L10n.string("Make Package Default"),
            progress: progress,
            completion: completion
        ) { proxy, reply in
            proxy.makeDefault(packages, reply: reply)
        }
    }

    private func performPrivilegedResultCommand(
        operationName: String,
        progress: @escaping (NukeHelperProgressEvent) -> Void,
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void,
        invoke: @escaping (NukeHelperProtocol, @escaping ([String: Any]) -> Void) -> Void
    ) {
        queue.async {
            let replyGuard = NukeHelperStartupReplyGuard(
                operationName: operationName,
                startupTimeout: Self.helperStartupTimeout,
                activityTimeout: Self.helperActivityTimeout,
                completion: completion
            ) { [weak self] in
                self?.invalidateConnection()
            }
            let guardedProgress: (NukeHelperProgressEvent) -> Void = { event in
                replyGuard.markStarted()
                progress(event)
            }

            do {
                let proxy = try self.privilegedRemoteProxy(
                    progressHandler: guardedProgress,
                    errorHandler: { error in
                        replyGuard.fail(NukeHelperBridgeError.connectionFailed(
                            "Privileged helper connection failed: \(error.localizedDescription)"
                        ))
                    }
                )
                replyGuard.startWatchdog()
                invoke(proxy) { result in
                    replyGuard.complete(self.parseResult(result))
                }
            } catch {
                replyGuard.fail(error)
            }
        }
    }

    private func complete(
        _ result: [String: Any],
        completion: @escaping (Result<NukeHelperResult, Error>) -> Void
    ) {
        DispatchQueue.main.async {
            completion(self.parseResult(result))
        }
    }

    private func parseResult(_ result: [String: Any]) -> Result<NukeHelperResult, Error> {
        if let failure = result["Err"] as? String {
            return .failure(NukeHelperBridgeError.operationFailed(failure))
        }
        guard let success = result["Ok"] as? [String: Any] else {
            return .failure(NukeHelperBridgeError.invalidResponse("Helper reply missing result payload."))
        }
        let message = success["message"] as? String ?? "Operation complete"
        let processedPackages = success["processed_packages"] as? [String] ?? []
        let value = success["value"] as? String
        return .success(NukeHelperResult(
            message: message,
            processedPackages: processedPackages,
            value: value
        ))
    }

    private func privilegedRemoteProxy(
        progressHandler: ((NukeHelperProgressEvent) -> Void)?
    ) throws -> NukeHelperProtocol {
        try privilegedRemoteProxy(progressHandler: progressHandler) { error in
            NSLog("nuke-helper XPC error: %@", error.localizedDescription)
        }
    }

    private func privilegedRemoteProxy(
        progressHandler: ((NukeHelperProgressEvent) -> Void)?,
        errorHandler: @escaping (Error) -> Void
    ) throws -> NukeHelperProtocol {
        guard let proxy = try remoteProxy(
            progressHandler: progressHandler,
            blessingPolicy: .blessIfNeeded,
            errorHandler: errorHandler
        ) else {
            throw NukeHelperBridgeError.connectionFailed("Unable to acquire helper proxy.")
        }
        return proxy
    }

    private func remoteProxy(
        progressHandler: ((NukeHelperProgressEvent) -> Void)?,
        blessingPolicy: HelperBlessingPolicy
    ) throws -> NukeHelperProtocol? {
        try remoteProxy(progressHandler: progressHandler, blessingPolicy: blessingPolicy) { error in
            NSLog("nuke-helper XPC error: %@", error.localizedDescription)
        }
    }

    private func remoteProxy(
        progressHandler: ((NukeHelperProgressEvent) -> Void)?,
        blessingPolicy: HelperBlessingPolicy = .blessIfNeeded,
        errorHandler: @escaping (Error) -> Void
    ) throws -> NukeHelperProtocol? {
        let requiresBlessing: Bool
        switch blessingPolicy {
        case .compatibleInstalledOnly:
            guard compatibleInstalledHelperAvailable() else {
                return nil
            }
            requiresBlessing = false
        case .blessIfNeeded, .installedOnly:
            do {
                requiresBlessing = try helperRequiresBlessing()
            } catch {
                if blessingPolicy == .installedOnly {
                    return nil
                }
                throw error
            }
        }

        if requiresBlessing {
            guard blessingPolicy == .blessIfNeeded else {
                return nil
            }
            try ensureBlessableBuild()
            try blessHelper()
            connection?.invalidate()
            connection = nil
        }
        let connection = try ensureConnection(progressHandler: progressHandler)
        let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler)
        guard let typed = proxy as? NukeHelperProtocol else {
            throw NukeHelperBridgeError.connectionFailed("Unable to acquire helper proxy.")
        }
        return typed
    }

    private func helperToolInstalled() -> Bool {
        FileManager.default.fileExists(atPath: helperToolURL().path)
    }

    private func currentHelperMaintenanceState() throws -> NukeHelperMaintenanceState {
        guard helperToolInstalled() else {
            return .notInstalled
        }
        return try helperRequiresBlessing() ? .needsUpdate : .current
    }

    private func helperRequiresBlessing() throws -> Bool {
        guard helperToolInstalled() else {
            return true
        }
        let bundledHelperURL = bundledHelperToolURL()
        guard FileManager.default.fileExists(atPath: bundledHelperURL.path) else {
            throw NukeHelperBridgeError.connectionFailed("Bundled privileged helper is missing.")
        }
        let bundledIdentity = try helperCodeIdentity(
            at: bundledHelperURL,
            context: "bundled"
        )
        guard bundledIdentity.identifier == Self.serviceName else {
            throw NukeHelperBridgeError.connectionFailed(
                "Bundled privileged helper identifier is invalid."
            )
        }
        let installedIdentity: NukeHelperCodeIdentity
        do {
            installedIdentity = try helperCodeIdentity(
                at: helperToolURL(),
                context: "installed"
            )
        } catch {
            return true
        }
        if installedIdentity.identifier != bundledIdentity.identifier {
            return true
        }
        if installedIdentity.teamIdentifier != bundledIdentity.teamIdentifier {
            return true
        }
        return compareHelperVersion(
            installedIdentity.bundleVersion,
            bundledIdentity.bundleVersion
        ) == .orderedAscending
    }

    private func compatibleInstalledHelperAvailable() -> Bool {
        guard helperToolInstalled(),
              let installedIdentity = try? helperCodeIdentity(
                at: helperToolURL(),
                context: "installed"
              ),
              installedIdentity.identifier == Self.serviceName else {
            return false
        }

        guard let expectedTeamIdentifier = currentBundleTeamIdentifier(),
              !expectedTeamIdentifier.isEmpty else {
            return true
        }
        return installedIdentity.teamIdentifier == expectedTeamIdentifier
    }

    private func helperToolURL() -> URL {
        URL(fileURLWithPath: "/Library/PrivilegedHelperTools", isDirectory: true)
            .appendingPathComponent(Self.serviceName, isDirectory: false)
    }

    private func bundledHelperToolURL() -> URL {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LaunchServices", isDirectory: true)
            .appendingPathComponent(Self.serviceName, isDirectory: false)
    }

    private func ensureConnection(
        progressHandler: ((NukeHelperProgressEvent) -> Void)?
    ) throws -> NSXPCConnection {
        if let connection {
            progressRelay.onEvent = progressHandler
            return connection
        }

        let connection = NSXPCConnection(machServiceName: Self.serviceName, options: .privileged)
        connection.remoteObjectInterface = makeRemoteInterface()
        connection.exportedInterface = makeProgressInterface()
        progressRelay.onEvent = progressHandler
        connection.exportedObject = progressRelay
        connection.invalidationHandler = { [weak self] in
            self?.queue.async {
                self?.connection = nil
            }
        }
        connection.interruptionHandler = { [weak self] in
            self?.queue.async {
                self?.connection = nil
            }
        }
        connection.resume()
        self.connection = connection
        return connection
    }

    private func invalidateConnection() {
        queue.async {
            self.connection?.invalidate()
            self.connection = nil
        }
    }

    private func makeRemoteInterface() -> NSXPCInterface {
        let interface = NSXPCInterface(with: NukeHelperProtocol.self)
        let packageClasses = (NSSet(array: [NSArray.self, AVPackageSpec.self]) as? Set<AnyHashable>) ?? []
        interface.setClasses(
            packageClasses,
            for: #selector(NukeHelperProtocol.install(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            packageClasses,
            for: #selector(NukeHelperProtocol.update(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            packageClasses,
            for: #selector(NukeHelperProtocol.uninstall(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        let stringClasses = (NSSet(array: [NSString.self]) as? Set<AnyHashable>) ?? []
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.installAv(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.installIsotopeRoot(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.convertRadioisotope(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.installIsotopeStubs(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberIsotopeAlwaysAllow(_:scriptPath:scriptSha256:keys:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberIsotopeAlwaysAllow(_:scriptPath:scriptSha256:keys:reply:)),
            argumentIndex: 1,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberIsotopeAlwaysAllow(_:scriptPath:scriptSha256:keys:reply:)),
            argumentIndex: 2,
            ofReply: false
        )
        let stringArrayClasses = (NSSet(array: [NSArray.self, NSString.self]) as? Set<AnyHashable>) ?? []
        interface.setClasses(
            stringArrayClasses,
            for: #selector(NukeHelperProtocol.rememberIsotopeAlwaysAllow(_:scriptPath:scriptSha256:keys:reply:)),
            argumentIndex: 3,
            ofReply: false
        )
        let resultClasses = (NSSet(
            array: [NSDictionary.self, NSArray.self, NSString.self, NSNumber.self, NSNull.self]
        ) as? Set<AnyHashable>) ?? []
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.install(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.update(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.uninstall(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.updateAll(_:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.installAv(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.installIsotopeRoot(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.convertRadioisotope(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.installIsotopeStubs(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.rememberIsotopeAlwaysAllow(_:scriptPath:scriptSha256:keys:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.dotenvApprovalPolicy(_:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.setDotenvApprovalPolicy(_:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.setDotenvApprovalPolicy(_:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 1,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 2,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 3,
            ofReply: false
        )
        interface.setClasses(
            stringClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 4,
            ofReply: false
        )
        interface.setClasses(
            stringArrayClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 5,
            ofReply: false
        )
        interface.setClasses(
            resultClasses,
            for: #selector(NukeHelperProtocol.rememberDotenvApproval(_:envFilePath:projectRoot:envSha256:publicKeyFingerprint:keys:reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        return interface
    }

    private func makeProgressInterface() -> NSXPCInterface {
        let interface = NSXPCInterface(with: NukeHelperProgressProtocol.self)
        let classes = (NSSet(
            array: [NSDictionary.self, NSArray.self, NSString.self, NSNumber.self, NSNull.self]
        ) as? Set<AnyHashable>) ?? []
        interface.setClasses(
            classes,
            for: #selector(NukeHelperProgressProtocol.progressEvent(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        return interface
    }

    private func blessHelper() throws {
        var authRef: AuthorizationRef?
        let createStatus = AuthorizationCreate(nil, nil, [], &authRef)
        guard createStatus == errAuthorizationSuccess, let authRef else {
            throw NukeHelperBridgeError.authorizationFailed(
                "Unable to create authorization reference (\(createStatus))."
            )
        }
        defer {
            AuthorizationFree(authRef, [.destroyRights])
        }

        let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]
        let status = kSMRightBlessPrivilegedHelper.withCString { rightName in
            var item = AuthorizationItem(
                name: rightName,
                valueLength: 0,
                value: nil,
                flags: 0
            )
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(authRef, &rights, nil, flags, nil)
            }
        }
        guard status == errAuthorizationSuccess else {
            throw NukeHelperBridgeError.authorizationFailed(
                "Unable to acquire blessing rights (\(status))."
            )
        }

        let errorMessage = AVBlessPrivilegedHelper(Self.serviceName as CFString, authRef)
        if errorMessage == nil {
            return
        }

        defer {
            free(errorMessage)
        }
        let message = errorMessage.map { String(cString: $0) } ?? "SMJobBless failed."
        throw NukeHelperBridgeError.blessingFailed(message)
    }

    private func ensureBlessableBuild() throws {
        let staticCode = try bundleStaticCode()
        let signingInfo = try copySigningInformation(for: staticCode)

        let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String
        if identifier != Self.appBundleIdentifier {
            throw NukeHelperBridgeError.unsignedBuild(
                """
                This build is not blessable yet. Expected app identifier \
                \(Self.appBundleIdentifier), got \(identifier ?? "unknown").
                Rebuild with a real Apple signing identity.
                """
            )
        }

        let teamIdentifier = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
        if teamIdentifier == nil {
            throw NukeHelperBridgeError.unsignedBuild(
                """
                Privileged updates require a developer-signed build. \
                The current app is ad hoc or unsigned. Set \
                CODESIGN_IDENTITY to an Apple signing identity, rebuild, \
                and relaunch Automic Vault before blessing the helper.
                """
            )
        }
    }

    private func helperCodeIdentity(
        at url: URL,
        context: String
    ) throws -> NukeHelperCodeIdentity {
        let staticCode = try staticCode(at: url, context: context)
        let signingInfo = try copySigningInformation(
            for: staticCode,
            context: "\(context) helper"
        )

        guard let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String,
              !identifier.isEmpty else {
            throw NukeHelperBridgeError.connectionFailed(
                "Unable to read the \(context) helper identifier."
            )
        }

        let teamIdentifier = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
        let plist = signingInfo[kSecCodeInfoPList as String] as? [String: Any]
        guard let bundleVersion = plist?["CFBundleVersion"] as? String,
              !bundleVersion.isEmpty else {
            throw NukeHelperBridgeError.connectionFailed(
                "Unable to read the \(context) helper version."
            )
        }

        return NukeHelperCodeIdentity(
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            bundleVersion: bundleVersion
        )
    }

    private func compareHelperVersion(
        _ installedVersion: String,
        _ bundledVersion: String
    ) -> ComparisonResult {
        installedVersion.compare(
            bundledVersion,
            options: [.numeric]
        )
    }

    private func bundleStaticCode() throws -> SecStaticCode {
        try staticCode(at: Bundle.main.bundleURL, context: "app")
    }

    private func currentBundleTeamIdentifier() -> String? {
        guard let signingInfo = try? copySigningInformation(
            for: bundleStaticCode(),
            context: "app"
        ) else {
            return nil
        }
        return signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
    }

    private func copySigningInformation(
        for staticCode: SecStaticCode,
        context: String = "app"
    ) throws -> [String: Any] {
        var signingInfo: CFDictionary?
        let status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInfo
        )
        guard status == errSecSuccess,
              let dictionary = signingInfo as NSDictionary?,
              let decoded = dictionary as? [String: Any] else {
            throw NukeHelperBridgeError.unsignedBuild(
                "Unable to read \(context) signing information (\(status))."
            )
        }
        return decoded
    }

    private func staticCode(
        at url: URL,
        context: String
    ) throws -> SecStaticCode {
        var staticCode: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(
            url as CFURL,
            SecCSFlags(),
            &staticCode
        )
        guard status == errSecSuccess, let staticCode else {
            if context == "app" {
                throw NukeHelperBridgeError.unsignedBuild(
                    "Unable to inspect the \(context) signature (\(status))."
                )
            }
            throw NukeHelperBridgeError.connectionFailed(
                "Unable to inspect the \(context) helper signature (\(status))."
            )
        }
        return staticCode
    }
}
