import CryptoKit
import Darwin
import Foundation
import Security

public let launcherBundlesKeychainService = "com.automicvault.launcher-bundles"
public let launcherBundlesKeychainAccount = "LauncherBundlesV1"
public let launcherBundleIdentifierPrefix = "com.automicvault.launcher-bundle."
public let launcherBundleGenerationInfoKey = "AVLauncherBundleGeneration"
public let launcherBundlePayloadSHA256InfoKey = "AVLauncherBundlePayloadSHA256"
public let launcherBundleCommandNameInfoKey = "AVLauncherBundleCommandName"
public let launcherBundlePayloadName = "payload"
public let launcherBundleMaximumPayloadBytes: Int64 = 512 * 1024 * 1024

public enum LauncherBundleSigningKind: String, Codable, Equatable, Sendable {
    case adHoc
    // Compatibility with Developer ID-signed enrollments created by 3.9.0.
    case developerID

    public var title: String {
        switch self {
        case .adHoc: "Ad Hoc"
        case .developerID: "Developer ID"
        }
    }
}

public struct LauncherBundleEnrollment: Codable, Equatable, Identifiable, Sendable {
    public let generation: UUID
    public let displayName: String
    public let commandName: String?
    public let bundleIdentifier: String
    public let bundlePath: String
    public let launcherIdentifier: String
    public let launcherRequirement: String
    public let bundleCodeIdentifiers: [Data]
    public let launcherCodeIdentifiers: [Data]
    public let payloadCodeIdentifiers: [Data]
    public let sourceSHA256: String
    public let payloadSHA256: String
    public let payloadEntitlements: [String]
    public let runtimeRequirement: LauncherRuntimeRequirement
    public let signingKind: LauncherBundleSigningKind
    public let signingIdentity: String?
    public let createdAt: Date

    public var id: UUID { generation }

    public init(
        generation: UUID,
        displayName: String,
        commandName: String? = nil,
        bundleIdentifier: String,
        bundlePath: String,
        launcherIdentifier: String,
        launcherRequirement: String,
        bundleCodeIdentifiers: [Data],
        launcherCodeIdentifiers: [Data],
        payloadCodeIdentifiers: [Data],
        sourceSHA256: String,
        payloadSHA256: String,
        payloadEntitlements: [String],
        runtimeRequirement: LauncherRuntimeRequirement,
        signingKind: LauncherBundleSigningKind,
        signingIdentity: String?,
        createdAt: Date = Date()
    ) {
        self.generation = generation
        self.displayName = displayName
        self.commandName = commandName
        self.bundleIdentifier = bundleIdentifier
        self.bundlePath = bundlePath
        self.launcherIdentifier = launcherIdentifier
        self.launcherRequirement = launcherRequirement
        self.bundleCodeIdentifiers = normalizedCodeIdentifiers(bundleCodeIdentifiers)
        self.launcherCodeIdentifiers = normalizedCodeIdentifiers(launcherCodeIdentifiers)
        self.payloadCodeIdentifiers = normalizedCodeIdentifiers(payloadCodeIdentifiers)
        self.sourceSHA256 = sourceSHA256
        self.payloadSHA256 = payloadSHA256
        self.payloadEntitlements = payloadEntitlements.sorted()
        self.runtimeRequirement = runtimeRequirement
        self.signingKind = signingKind
        self.signingIdentity = signingIdentity
        self.createdAt = createdAt
    }

    public var commandPath: String? {
        commandName.map { launcherBundleCommandURL(named: $0).path }
    }
}

public enum LauncherBundleEnrollmentsLoad: Equatable, Sendable {
    case success([LauncherBundleEnrollment])
    case notFound
    case failure(OSStatus)
}

public func loadLauncherBundleEnrollments(
    service: String = launcherBundlesKeychainService,
    account: String = launcherBundlesKeychainAccount
) -> [LauncherBundleEnrollment] {
    guard case .success(let enrollments) = loadLauncherBundleEnrollmentsResult(
        service: service,
        account: account
    ) else { return [] }
    return enrollments.sorted(by: launcherBundleEnrollmentPrecedes)
}

public func loadLauncherBundleEnrollmentsResult(
    service: String = launcherBundlesKeychainService,
    account: String = launcherBundlesKeychainAccount
) -> LauncherBundleEnrollmentsLoad {
    switch loadKeychainDataResult(service: service, account: account) {
    case .notFound:
        return .notFound
    case .failure(let status):
        return .failure(status)
    case .success(let data):
        do {
            let records = try JSONDecoder().decode([LauncherBundleEnrollment].self, from: data)
            guard Set(records.map(\.generation)).count == records.count,
                  Set(records.map(\.bundleIdentifier)).count == records.count
            else { return .failure(errSecDecode) }
            return .success(records.sorted(by: launcherBundleEnrollmentPrecedes))
        } catch {
            return .failure(errSecDecode)
        }
    }
}

@discardableResult
public func saveLauncherBundleEnrollment(
    _ enrollment: LauncherBundleEnrollment,
    replacing generation: UUID? = nil,
    service: String = launcherBundlesKeychainService,
    account: String = launcherBundlesKeychainAccount
) -> OSStatus {
    var enrollments: [LauncherBundleEnrollment]
    switch loadLauncherBundleEnrollmentsResult(service: service, account: account) {
    case .success(let loaded): enrollments = loaded
    case .notFound: enrollments = []
    case .failure(let status): return status
    }
    if let generation { enrollments.removeAll { $0.generation == generation } }
    enrollments.removeAll {
        $0.generation == enrollment.generation || $0.bundleIdentifier == enrollment.bundleIdentifier
    }
    enrollments.append(enrollment)
    let sorted = enrollments.sorted(by: launcherBundleEnrollmentPrecedes)
    guard let data = try? JSONEncoder().encode(sorted) else { return errSecParam }
    let status = saveKeychainData(
        data,
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    )
    guard status == errSecSuccess else { return status }
    guard case .success(let stored) = loadLauncherBundleEnrollmentsResult(
        service: service,
        account: account
    ) else { return errSecDecode }
    return stored == sorted ? errSecSuccess : errSecDecode
}

@discardableResult
public func removeLauncherBundleEnrollment(
    generation: UUID,
    service: String = launcherBundlesKeychainService,
    account: String = launcherBundlesKeychainAccount
) -> OSStatus {
    let enrollments: [LauncherBundleEnrollment]
    switch loadLauncherBundleEnrollmentsResult(service: service, account: account) {
    case .success(let loaded): enrollments = loaded.filter { $0.generation != generation }
    case .notFound: return errSecSuccess
    case .failure(let status): return status
    }
    if enrollments.isEmpty {
        let status = deleteStoredSecret(account: account, service: service)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
    guard let data = try? JSONEncoder().encode(enrollments) else { return errSecParam }
    return saveKeychainData(
        data,
        service: service,
        account: account,
        accessibility: .afterFirstUnlock
    )
}

@discardableResult
public func removeLauncherBundleAuthorization(
    requirement: String
) -> OSStatus {
    let gateStatus = removeSecretGatePolicies(forLauncherRequirement: requirement)
    guard gateStatus == errSecSuccess else { return gateStatus }
    let namesStatus = removeSecretNameAccess(forLauncherRequirement: requirement)
    guard namesStatus == errSecSuccess else { return namesStatus }
    let historyStatus = removeAuthorizationHistoryAccess(forLauncherRequirement: requirement)
    guard historyStatus == errSecSuccess else { return historyStatus }
    let directStatus = removeDirectAccess(forLauncherRequirement: requirement)
    guard directStatus == errSecSuccess else { return directStatus }
    return removeLauncherFromBlessedScripts(requirement: requirement)
}

public struct LauncherBundleCodeEvidence: Equatable, Sendable {
    public let identifier: String
    public let teamIdentifier: String?
    public let designatedRequirement: String
    public let codeIdentifiers: [Data]
    public let isAdHoc: Bool
    public let runtimeProtection: LauncherRuntimeProtection
    public let enabledEntitlements: [String]

    public init(
        identifier: String,
        teamIdentifier: String?,
        designatedRequirement: String,
        codeIdentifiers: [Data],
        isAdHoc: Bool,
        runtimeProtection: LauncherRuntimeProtection,
        enabledEntitlements: [String]
    ) {
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.designatedRequirement = designatedRequirement
        self.codeIdentifiers = normalizedCodeIdentifiers(codeIdentifiers)
        self.isAdHoc = isAdHoc
        self.runtimeProtection = runtimeProtection
        self.enabledEntitlements = enabledEntitlements.sorted()
    }
}

public enum LauncherBundleVerificationError: Error, Equatable, LocalizedError {
    case invalidBundle
    case enrollmentUnavailable
    case notEnrolled
    case identityMismatch
    case payloadMismatch
    case runtimeMismatch

    public var errorDescription: String? {
        switch self {
        case .invalidBundle: "Launcher Bundle integrity could not be verified"
        case .enrollmentUnavailable: "Launcher Bundle enrollment is unavailable"
        case .notEnrolled: "Launcher Bundle is not enrolled"
        case .identityMismatch: "Launcher Bundle signed identity changed"
        case .payloadMismatch: "Launcher Bundle payload changed"
        case .runtimeMismatch: "Launcher Bundle runtime protections changed"
        }
    }
}

public func verifyLauncherBundle(
    at appURL: URL,
    liveLauncherIdentifier: String,
    liveLauncherCodeIdentifier: Data,
    liveRuntimeProtection: LauncherRuntimeProtection,
    enrollments: LauncherBundleEnrollmentsLoad? = nil
) throws -> LauncherBundleEnrollment {
    let evidence = try launcherBundleVerificationEvidence(at: appURL, enrollments: enrollments)
    let enrollment = evidence.enrollment
    guard evidence.launcher.identifier == liveLauncherIdentifier,
          enrollment.launcherCodeIdentifiers.contains(liveLauncherCodeIdentifier)
    else { throw LauncherBundleVerificationError.identityMismatch }
    guard enrollment.runtimeRequirement.allows(liveRuntimeProtection),
          enrollment.runtimeRequirement.allows(evidence.payload.runtimeProtection)
    else { throw LauncherBundleVerificationError.runtimeMismatch }
    return enrollment
}

public func verifyLauncherBundlePayload(
    at appURL: URL,
    livePayloadIdentifier: String,
    livePayloadCodeIdentifier: Data,
    liveRuntimeProtection: LauncherRuntimeProtection,
    enrollments: LauncherBundleEnrollmentsLoad? = nil
) throws -> LauncherBundleEnrollment {
    let evidence = try launcherBundleVerificationEvidence(at: appURL, enrollments: enrollments)
    let enrollment = evidence.enrollment
    guard evidence.payload.identifier == livePayloadIdentifier,
          enrollment.payloadCodeIdentifiers.contains(livePayloadCodeIdentifier)
    else { throw LauncherBundleVerificationError.identityMismatch }
    guard enrollment.runtimeRequirement.allows(liveRuntimeProtection),
          enrollment.runtimeRequirement.allows(evidence.payload.runtimeProtection)
    else { throw LauncherBundleVerificationError.runtimeMismatch }
    return enrollment
}

public func verifyLauncherBundleProcess(
    at appURL: URL,
    executableURL: URL,
    liveIdentifier: String,
    liveCodeIdentifier: Data,
    liveRuntimeProtection: LauncherRuntimeProtection,
    enrollments: LauncherBundleEnrollmentsLoad? = nil
) throws -> LauncherBundleEnrollment {
    let info = try launcherBundleInfo(at: appURL)
    let executable = executableURL.standardizedFileURL
    let launcher = appURL.appendingPathComponent(
        "Contents/MacOS/\(info.executable)"
    ).standardizedFileURL
    let payload = appURL.appendingPathComponent(
        "Contents/Resources/\(launcherBundlePayloadName)"
    ).standardizedFileURL
    if executable == launcher {
        return try verifyLauncherBundle(
            at: appURL,
            liveLauncherIdentifier: liveIdentifier,
            liveLauncherCodeIdentifier: liveCodeIdentifier,
            liveRuntimeProtection: liveRuntimeProtection,
            enrollments: enrollments
        )
    }
    if executable == payload {
        return try verifyLauncherBundlePayload(
            at: appURL,
            livePayloadIdentifier: liveIdentifier,
            livePayloadCodeIdentifier: liveCodeIdentifier,
            liveRuntimeProtection: liveRuntimeProtection,
            enrollments: enrollments
        )
    }
    throw LauncherBundleVerificationError.identityMismatch
}

private struct LauncherBundleVerificationEvidence {
    let enrollment: LauncherBundleEnrollment
    let launcher: LauncherBundleCodeEvidence
    let payload: LauncherBundleCodeEvidence
}

private func launcherBundleVerificationEvidence(
    at appURL: URL,
    enrollments: LauncherBundleEnrollmentsLoad?
) throws -> LauncherBundleVerificationEvidence {
    let info = try launcherBundleInfo(at: appURL)
    guard info.bundleIdentifier.hasPrefix(launcherBundleIdentifierPrefix) else {
        throw LauncherBundleVerificationError.invalidBundle
    }
    let records = switch enrollments ?? loadLauncherBundleEnrollmentsResult() {
    case .success(let loaded): loaded
    case .notFound: throw LauncherBundleVerificationError.notEnrolled
    case .failure: throw LauncherBundleVerificationError.enrollmentUnavailable
    }
    guard let enrollment = records.first(where: {
        $0.generation == info.generation && $0.bundleIdentifier == info.bundleIdentifier
    }) else { throw LauncherBundleVerificationError.notEnrolled }
    if appURL.deletingLastPathComponent().standardizedFileURL
        == launcherBundleManagedDirectory().standardizedFileURL {
        guard launcherBundleTreeIsSystemProtected(at: appURL),
              launcherBundleTreeIsSystemProtected(at: launcherBundleManagedDirectory())
        else { throw LauncherBundleVerificationError.identityMismatch }
    }

    let macOSURL = appURL.appendingPathComponent("Contents/MacOS", isDirectory: true)
    let launcherURL = macOSURL.appendingPathComponent(info.executable)
    let payloadURL = appURL.appendingPathComponent(
        "Contents/Resources/\(launcherBundlePayloadName)"
    )
    let bundle = try launcherBundleCodeEvidence(at: appURL, bundle: true)
    let launcher = try launcherBundleCodeEvidence(at: launcherURL)
    let payload = try launcherBundleCodeEvidence(at: payloadURL)

    guard bundle.identifier == enrollment.bundleIdentifier,
          appURL.standardizedFileURL.path == URL(fileURLWithPath: enrollment.bundlePath).standardizedFileURL.path,
          bundle.designatedRequirement == enrollment.launcherRequirement,
          bundle.codeIdentifiers == enrollment.bundleCodeIdentifiers,
          launcher.identifier == enrollment.launcherIdentifier,
          launcher.codeIdentifiers == enrollment.launcherCodeIdentifiers,
          payload.identifier == "\(enrollment.bundleIdentifier).payload",
          payload.codeIdentifiers == enrollment.payloadCodeIdentifiers,
          payload.enabledEntitlements == enrollment.payloadEntitlements,
          info.commandName == enrollment.commandName,
          bundle.isAdHoc == (enrollment.signingKind == .adHoc),
          launcher.isAdHoc == bundle.isAdHoc,
          payload.isAdHoc == bundle.isAdHoc
    else { throw LauncherBundleVerificationError.identityMismatch }

    guard try sha256OfRegularFile(at: payloadURL) == enrollment.payloadSHA256,
          info.payloadSHA256 == enrollment.payloadSHA256
    else { throw LauncherBundleVerificationError.payloadMismatch }
    return LauncherBundleVerificationEvidence(
        enrollment: enrollment,
        launcher: launcher,
        payload: payload
    )
}

public func launcherBundleCodeEvidence(
    at url: URL,
    bundle: Bool = false
) throws -> LauncherBundleCodeEvidence {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
          let code
    else { throw LauncherBundleVerificationError.invalidBundle }
    var rawFlags = kSecCSStrictValidate | kSecCSCheckAllArchitectures
    if bundle { rawFlags |= kSecCSCheckNestedCode }
    guard SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: rawFlags), nil) == errSecSuccess
    else { throw LauncherBundleVerificationError.invalidBundle }

    var rawInfo: CFDictionary?
    let informationFlags = SecCSFlags(
        rawValue: kSecCSSigningInformation | kSecCSRequirementInformation
    )
    guard SecCodeCopySigningInformation(code, informationFlags, &rawInfo) == errSecSuccess,
          let dictionary = rawInfo as? [CFString: Any],
          let identifier = dictionary[kSecCodeInfoIdentifier] as? String,
          let requirementText = launcherBundleDesignatedRequirement(from: dictionary)
    else { throw LauncherBundleVerificationError.invalidBundle }
    var identifiers = (dictionary[kSecCodeInfoCdHashes] as? [Data])
        ?? [dictionary[kSecCodeInfoUnique] as? Data].compactMap(\.self)
    for architecture in ["arm64", "arm64e", "x86_64"] {
        let attributes = [kSecCodeAttributeArchitecture as String: architecture] as CFDictionary
        var slice: SecStaticCode?
        guard SecStaticCodeCreateWithPathAndAttributes(
            url as CFURL,
            [],
            attributes,
            &slice
        ) == errSecSuccess,
            let slice,
            SecStaticCodeCheckValidity(slice, SecCSFlags(rawValue: rawFlags), nil) == errSecSuccess
        else { continue }
        var sliceInfo: CFDictionary?
        guard SecCodeCopySigningInformation(slice, informationFlags, &sliceInfo) == errSecSuccess,
              let sliceDictionary = sliceInfo as? [CFString: Any]
        else { continue }
        identifiers += (sliceDictionary[kSecCodeInfoCdHashes] as? [Data])
            ?? [sliceDictionary[kSecCodeInfoUnique] as? Data].compactMap(\.self)
    }
    guard !identifiers.isEmpty else { throw LauncherBundleVerificationError.invalidBundle }
    let signatureFlags = (dictionary[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
    let entitlementDictionary = dictionary[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
    let enabledEntitlements = entitlementDictionary.compactMap { key, value in
        (value as? NSNumber)?.boolValue == true ? key : nil
    }
    return LauncherBundleCodeEvidence(
        identifier: identifier,
        teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier] as? String,
        designatedRequirement: requirementText,
        codeIdentifiers: identifiers,
        isAdHoc: signatureFlags & SecCodeSignatureFlags.adhoc.rawValue != 0,
        runtimeProtection: launcherRuntimeProtection(signingInformation: dictionary),
        enabledEntitlements: enabledEntitlements
    )
}

public struct LauncherBundlePayloadSnapshot: Equatable, Sendable {
    public let sourcePath: String
    public let sourceSHA256: String
    public let byteCount: Int64
}

public enum LauncherBundlePayloadError: Error, Equatable, LocalizedError {
    case cannotOpen
    case cannotReadMetadata
    case notRegularMachO
    case notExecutable
    case tooLarge
    case changedDuringCopy
    case cannotWrite

    public var errorDescription: String? {
        switch self {
        case .cannotOpen: "CLI executable could not be opened securely"
        case .cannotReadMetadata: "CLI executable metadata could not be read"
        case .notRegularMachO: "Choose one regular Mach-O executable"
        case .notExecutable: "The selected Mach-O is not executable"
        case .tooLarge: "The selected Mach-O exceeds 512 MiB"
        case .changedDuringCopy: "The selected executable changed while it was copied"
        case .cannotWrite: "The Launcher Bundle payload could not be written"
        }
    }
}

public func copyLauncherBundlePayload(
    from sourceURL: URL,
    to destinationURL: URL
) throws -> LauncherBundlePayloadSnapshot {
    let source = sourceURL.resolvingSymlinksInPath().standardizedFileURL
    let sourceDescriptor = open(source.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard sourceDescriptor >= 0 else { throw LauncherBundlePayloadError.cannotOpen }
    defer { close(sourceDescriptor) }
    var before = stat()
    guard fstat(sourceDescriptor, &before) == 0 else {
        throw LauncherBundlePayloadError.cannotReadMetadata
    }
    guard before.st_mode & S_IFMT == S_IFREG else {
        throw LauncherBundlePayloadError.notRegularMachO
    }
    guard before.st_mode & 0o111 != 0 else { throw LauncherBundlePayloadError.notExecutable }
    guard before.st_size <= launcherBundleMaximumPayloadBytes else {
        throw LauncherBundlePayloadError.tooLarge
    }
    let destinationDescriptor = open(
        destinationURL.path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        mode_t(0o700)
    )
    guard destinationDescriptor >= 0 else { throw LauncherBundlePayloadError.cannotWrite }
    var succeeded = false
    defer {
        close(destinationDescriptor)
        if !succeeded { unlink(destinationURL.path) }
    }

    var hasher = SHA256()
    var header = [UInt8]()
    var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
    var total: Int64 = 0
    while true {
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(sourceDescriptor, $0.baseAddress, $0.count)
        }
        if count == 0 { break }
        if count < 0 {
            if errno == EINTR { continue }
            throw LauncherBundlePayloadError.cannotOpen
        }
        total += Int64(count)
        guard total <= launcherBundleMaximumPayloadBytes else {
            throw LauncherBundlePayloadError.tooLarge
        }
        let chunk = Data(buffer.prefix(count))
        if header.count < 4 { header.append(contentsOf: chunk.prefix(4 - header.count)) }
        hasher.update(data: chunk)
        try writeLauncherBundleBytes(chunk, to: destinationDescriptor)
    }
    guard launcherBundleMachOMagic(header) else {
        throw LauncherBundlePayloadError.notRegularMachO
    }
    var after = stat()
    guard fstat(sourceDescriptor, &after) == 0 else {
        throw LauncherBundlePayloadError.cannotReadMetadata
    }
    guard before.st_dev == after.st_dev,
          before.st_ino == after.st_ino,
          before.st_size == after.st_size,
          before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
          before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
          total == before.st_size
    else { throw LauncherBundlePayloadError.changedDuringCopy }
    guard fsync(destinationDescriptor) == 0 else { throw LauncherBundlePayloadError.cannotWrite }
    succeeded = true
    return LauncherBundlePayloadSnapshot(
        sourcePath: source.path,
        sourceSHA256: hasher.finalize().hexString,
        byteCount: total
    )
}

public func sha256OfRegularFile(at url: URL) throws -> String {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw LauncherBundlePayloadError.cannotOpen }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0 else {
        throw LauncherBundlePayloadError.cannotReadMetadata
    }
    guard info.st_mode & S_IFMT == S_IFREG else {
        throw LauncherBundlePayloadError.notRegularMachO
    }
    var hasher = SHA256()
    var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
    while true {
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(descriptor, $0.baseAddress, $0.count)
        }
        if count == 0 { return hasher.finalize().hexString }
        if count < 0 {
            if errno == EINTR { continue }
            throw LauncherBundlePayloadError.cannotOpen
        }
        hasher.update(data: Data(buffer.prefix(count)))
    }
}

public func launcherBundleTreeSHA256(at root: URL) throws -> String {
    var hasher = SHA256()
    try hashLauncherBundleTreeEntry(root, relativePath: "", hasher: &hasher)
    return hasher.finalize().hexString
}

private func hashLauncherBundleTreeEntry(
    _ url: URL,
    relativePath: String,
    hasher: inout SHA256
) throws {
    var metadata = stat()
    guard lstat(url.path, &metadata) == 0,
          metadata.st_mode & S_IFMT != S_IFLNK
    else { throw LauncherBundleVerificationError.invalidBundle }
    let isDirectory = metadata.st_mode & S_IFMT == S_IFDIR
    guard isDirectory || metadata.st_mode & S_IFMT == S_IFREG else {
        throw LauncherBundleVerificationError.invalidBundle
    }
    let pathData = Data(relativePath.utf8)
    hasher.update(data: Data([isDirectory ? 0x44 : 0x46]))
    hasher.update(data: launcherBundleTreeLength(pathData.count))
    hasher.update(data: pathData)
    if isDirectory {
        let children = try FileManager.default.contentsOfDirectory(
            at: url,
            includingPropertiesForKeys: nil
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        for child in children {
            let childPath = relativePath.isEmpty
                ? child.lastPathComponent
                : relativePath + "/" + child.lastPathComponent
            try hashLauncherBundleTreeEntry(child, relativePath: childPath, hasher: &hasher)
        }
        return
    }

    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw LauncherBundleVerificationError.invalidBundle }
    defer { close(descriptor) }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
          opened.st_mode & S_IFMT == S_IFREG,
          opened.st_dev == metadata.st_dev,
          opened.st_ino == metadata.st_ino
    else { throw LauncherBundleVerificationError.invalidBundle }
    hasher.update(data: launcherBundleTreeLength(Int(opened.st_size)))
    var remaining = opened.st_size
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while remaining > 0 {
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(descriptor, $0.baseAddress, min($0.count, Int(remaining)))
        }
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw LauncherBundleVerificationError.invalidBundle }
        hasher.update(data: Data(buffer.prefix(count)))
        remaining -= off_t(count)
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0,
          after.st_size == opened.st_size,
          after.st_mtimespec.tv_sec == opened.st_mtimespec.tv_sec,
          after.st_mtimespec.tv_nsec == opened.st_mtimespec.tv_nsec
    else { throw LauncherBundleVerificationError.invalidBundle }
}

private func launcherBundleTreeLength(_ value: Int) -> Data {
    var encoded = UInt64(value).bigEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}

public func launcherBundleDisplayName(from value: String) -> String? {
    let name = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !name.isEmpty, name.utf8.count <= 80,
          !name.contains("/"), name != ".", name != "..",
          name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
    else { return nil }
    return name
}

public func launcherBundleCommandName(from value: String) -> String? {
    let name = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !name.isEmpty, name.utf8.count <= 80, name != ".", name != "..",
          name.first != "-",
          name.unicodeScalars.allSatisfy({ scalar in
              scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar)
                  || "._+-".unicodeScalars.contains(scalar))
          })
    else { return nil }
    return name
}

public func launcherBundleManagedDirectory() -> URL {
    URL(fileURLWithPath: "/Applications/Automic Vault", isDirectory: true)
}

public func launcherBundleCommandURL(named commandName: String) -> URL {
    URL(fileURLWithPath: "/usr/local/bin", isDirectory: true)
        .appendingPathComponent(commandName)
}

private func launcherBundleTreeIsSystemProtected(at url: URL) -> Bool {
    var metadata = stat()
    guard lstat(url.path, &metadata) == 0,
          metadata.st_mode & S_IFMT != S_IFLNK,
          metadata.st_uid == 0,
          metadata.st_mode & 0o022 == 0
    else { return false }
    guard metadata.st_mode & S_IFMT == S_IFDIR else {
        return metadata.st_mode & S_IFMT == S_IFREG
    }
    guard let children = try? FileManager.default.contentsOfDirectory(
        at: url,
        includingPropertiesForKeys: nil
    ) else { return false }
    return children.allSatisfy(launcherBundleTreeIsSystemProtected)
}

public func launcherBundleAppURL(
    containing executablePath: String,
    managedDirectory: URL = launcherBundleManagedDirectory()
) -> URL? {
    let managedPath = managedDirectory.standardizedFileURL.path + "/"
    var candidate = URL(fileURLWithPath: executablePath).standardizedFileURL
    while candidate.path != "/" {
        if candidate.pathExtension.caseInsensitiveCompare("app") == .orderedSame,
           candidate.path.hasPrefix(managedPath) {
            return candidate
        }
        candidate.deleteLastPathComponent()
    }
    return nil
}

public func launcherBundleClaimsReservedIdentity(at appURL: URL) -> Bool {
    let infoURL = appURL.appendingPathComponent("Contents/Info.plist")
    guard let data = try? Data(contentsOf: infoURL),
          let dictionary = try? PropertyListSerialization.propertyList(
              from: data,
              format: nil
          ) as? [String: Any],
          let identifier = dictionary[kCFBundleIdentifierKey as String] as? String
    else { return false }
    return identifier.hasPrefix(launcherBundleIdentifierPrefix)
}

private struct LauncherBundleInfo {
    let generation: UUID
    let bundleIdentifier: String
    let executable: String
    let payloadSHA256: String
    let commandName: String?
}

private func launcherBundleInfo(at appURL: URL) throws -> LauncherBundleInfo {
    let infoURL = appURL.appendingPathComponent("Contents/Info.plist")
    guard let data = try? Data(contentsOf: infoURL),
          let dictionary = try? PropertyListSerialization.propertyList(
              from: data,
              format: nil
          ) as? [String: Any],
          let generationText = dictionary[launcherBundleGenerationInfoKey] as? String,
          let generation = UUID(uuidString: generationText),
          let bundleIdentifier = dictionary[kCFBundleIdentifierKey as String] as? String,
          let executable = dictionary[kCFBundleExecutableKey as String] as? String,
          let payloadSHA256 = dictionary[launcherBundlePayloadSHA256InfoKey] as? String
    else { throw LauncherBundleVerificationError.invalidBundle }
    return LauncherBundleInfo(
        generation: generation,
        bundleIdentifier: bundleIdentifier,
        executable: executable,
        payloadSHA256: payloadSHA256,
        commandName: dictionary[launcherBundleCommandNameInfoKey] as? String
    )
}

private func launcherBundleRequirementString(_ requirement: SecRequirement) -> String? {
    var text: CFString?
    guard SecRequirementCopyString(requirement, [], &text) == errSecSuccess,
          let text
    else { return nil }
    return text as String
}

func launcherBundleDesignatedRequirement(from dictionary: [CFString: Any]) -> String? {
    guard let value = dictionary[kSecCodeInfoDesignatedRequirement] as CFTypeRef?,
          CFGetTypeID(value) == SecRequirementGetTypeID()
    else { return nil }
    let requirement = unsafeDowncast(value, to: SecRequirement.self)
    return launcherBundleRequirementString(requirement)
}

private func launcherBundleEnrollmentPrecedes(
    _ lhs: LauncherBundleEnrollment,
    _ rhs: LauncherBundleEnrollment
) -> Bool {
    let comparison = lhs.displayName.localizedStandardCompare(rhs.displayName)
    return comparison == .orderedAscending
        || (comparison == .orderedSame && lhs.createdAt < rhs.createdAt)
}

private func normalizedCodeIdentifiers(_ identifiers: [Data]) -> [Data] {
    Array(Set(identifiers)).sorted { $0.hexString < $1.hexString }
}

private func launcherBundleMachOMagic(_ bytes: [UInt8]) -> Bool {
    guard bytes.count == 4 else { return false }
    let big = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    return [
        UInt32(0xfeedface), 0xcefaedfe, 0xfeedfacf, 0xcffaedfe,
        0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
    ].contains(big)
}

private func writeLauncherBundleBytes(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { bytes in
        var written = 0
        while written < bytes.count {
            let count = Darwin.write(
                descriptor,
                bytes.baseAddress?.advanced(by: written),
                bytes.count - written
            )
            if count < 0 {
                if errno == EINTR { continue }
                throw LauncherBundlePayloadError.cannotWrite
            }
            written += count
        }
    }
}

private extension Sequence where Element == UInt8 {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
