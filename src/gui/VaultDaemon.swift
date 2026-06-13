import AppKit
import CryptoKit
import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

private let localPeerTokenSocketOptionLevel = Int32(0)
private let localPeerTokenSocketOptionName = Int32(0x006)

private struct VaultClientApprovalRequest: Codable {
    let id: String
    let intent: VaultExecutionIntent
}

private struct VaultClientContainmentSession: Codable {
    let id: String
    let pid: UInt32
    let agentID: String
    let command: String
    let args: [String]
    let cwd: String
    let initialExecutablePath: String
    let toolchainRoot: String
    let binDir: String
    let sandboxProfilePath: String
    let socketPath: String

    enum CodingKeys: String, CodingKey {
        case id
        case pid
        case agentID = "agent_id"
        case command
        case args
        case cwd
        case initialExecutablePath = "initial_executable_path"
        case toolchainRoot = "toolchain_root"
        case binDir = "bin_dir"
        case sandboxProfilePath = "sandbox_profile_path"
        case socketPath = "socket_path"
    }
}

private struct KeyTransferImportRequest: Codable {
    let id: String
    let source: KeyTransferApprovalSource
    let replace: Bool
    let items: [KeyTransferImportItem]
}

private enum KeyTransferImportItem: Codable {
    case dotenvPrivateKey(
        envFilePath: String,
        publicKeyName: String,
        publicKey: String,
        publicKeyFingerprint: String,
        privateKey: String
    )
    case isotopeSecret(key: String, value: String)

    enum CodingKeys: String, CodingKey {
        case kind
        case envFilePath = "env_file_path"
        case publicKeyName = "public_key_name"
        case publicKey = "public_key"
        case publicKeyFingerprint = "public_key_fingerprint"
        case privateKey = "private_key"
        case key
        case value
    }

    enum Kind: String, Codable {
        case dotenvPrivateKey = "dotenv_private_key"
        case isotopeSecret = "isotope_secret"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .dotenvPrivateKey:
            self = .dotenvPrivateKey(
                envFilePath: try container.decode(String.self, forKey: .envFilePath),
                publicKeyName: try container.decode(String.self, forKey: .publicKeyName),
                publicKey: try container.decode(String.self, forKey: .publicKey),
                publicKeyFingerprint: try container.decode(String.self, forKey: .publicKeyFingerprint),
                privateKey: try container.decode(String.self, forKey: .privateKey)
            )
        case .isotopeSecret:
            self = .isotopeSecret(
                key: try container.decode(String.self, forKey: .key),
                value: try container.decode(String.self, forKey: .value)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .dotenvPrivateKey(let envFilePath, let publicKeyName, let publicKey, let publicKeyFingerprint, let privateKey):
            try container.encode(Kind.dotenvPrivateKey, forKey: .kind)
            try container.encode(envFilePath, forKey: .envFilePath)
            try container.encode(publicKeyName, forKey: .publicKeyName)
            try container.encode(publicKey, forKey: .publicKey)
            try container.encode(publicKeyFingerprint, forKey: .publicKeyFingerprint)
            try container.encode(privateKey, forKey: .privateKey)
        case .isotopeSecret(let key, let value):
            try container.encode(Kind.isotopeSecret, forKey: .kind)
            try container.encode(key, forKey: .key)
            try container.encode(value, forKey: .value)
        }
    }
}

private struct DotenvKeychainLoadRequest: Codable {
    let id: String
    let account: String
}

private struct DotenvKeychainStoreRequest: Codable {
    let id: String
    let account: String
    let privateKey: String

    enum CodingKeys: String, CodingKey {
        case id
        case account
        case privateKey = "private_key"
    }
}

private struct DotenvKeychainDeleteRequest: Codable {
    let id: String
    let account: String
}

private struct KeyTransferImportPlan {
    let approval: KeyTransferApprovalRequestSnapshot
    let actions: [KeyTransferImportAction]
    let alreadyPresent: Int
}

private enum KeyTransferImportAction {
    case storeDotenvPrivateKey(publicKeyFingerprint: String, privateKey: String)
    case storeIsotopeSecret(key: String, value: String)
}

private enum VaultClientRequest: Codable {
    case containmentStarted(VaultClientContainmentSession)
    case approvalRequest(VaultClientApprovalRequest)
    case keyTransferApprovalRequest(KeyTransferApprovalRequestSnapshot)
    case keyTransferImportRequest(KeyTransferImportRequest)
    case dotenvKeychainLoadRequest(DotenvKeychainLoadRequest)
    case dotenvKeychainStoreRequest(DotenvKeychainStoreRequest)
    case dotenvKeychainDeleteRequest(DotenvKeychainDeleteRequest)

    enum CodingKeys: String, CodingKey {
        case type
        case session
        case id
        case intent
        case request
    }

    enum RequestType: String, Codable {
        case containmentStarted = "containment_started"
        case approvalRequest = "approval_request"
        case keyTransferApprovalRequest = "key_transfer_approval_request"
        case keyTransferImportRequest = "key_transfer_import_request"
        case dotenvKeychainLoadRequest = "dotenv_keychain_load_request"
        case dotenvKeychainStoreRequest = "dotenv_keychain_store_request"
        case dotenvKeychainDeleteRequest = "dotenv_keychain_delete_request"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(RequestType.self, forKey: .type)
        switch type {
        case .containmentStarted:
            self = .containmentStarted(
                try container.decode(VaultClientContainmentSession.self, forKey: .session)
            )
        case .approvalRequest:
            self = .approvalRequest(
                VaultClientApprovalRequest(
                    id: try container.decode(String.self, forKey: .id),
                    intent: try container.decode(VaultExecutionIntent.self, forKey: .intent)
                )
            )
        case .keyTransferApprovalRequest:
            self = .keyTransferApprovalRequest(
                try container.decode(KeyTransferApprovalRequestSnapshot.self, forKey: .request)
            )
        case .keyTransferImportRequest:
            self = .keyTransferImportRequest(
                try container.decode(KeyTransferImportRequest.self, forKey: .request)
            )
        case .dotenvKeychainLoadRequest:
            self = .dotenvKeychainLoadRequest(
                try container.decode(DotenvKeychainLoadRequest.self, forKey: .request)
            )
        case .dotenvKeychainStoreRequest:
            self = .dotenvKeychainStoreRequest(
                try container.decode(DotenvKeychainStoreRequest.self, forKey: .request)
            )
        case .dotenvKeychainDeleteRequest:
            self = .dotenvKeychainDeleteRequest(
                try container.decode(DotenvKeychainDeleteRequest.self, forKey: .request)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        switch self {
        case .containmentStarted(let session):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.containmentStarted, forKey: .type)
            try container.encode(session, forKey: .session)
        case .approvalRequest(let request):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.approvalRequest, forKey: .type)
            try container.encode(request.id, forKey: .id)
            try container.encode(request.intent, forKey: .intent)
        case .keyTransferApprovalRequest(let request):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.keyTransferApprovalRequest, forKey: .type)
            try container.encode(request, forKey: .request)
        case .keyTransferImportRequest(let request):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.keyTransferImportRequest, forKey: .type)
            try container.encode(request, forKey: .request)
        case .dotenvKeychainLoadRequest(let request):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.dotenvKeychainLoadRequest, forKey: .type)
            try container.encode(request, forKey: .request)
        case .dotenvKeychainStoreRequest(let request):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.dotenvKeychainStoreRequest, forKey: .type)
            try container.encode(request, forKey: .request)
        case .dotenvKeychainDeleteRequest(let request):
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(RequestType.dotenvKeychainDeleteRequest, forKey: .type)
            try container.encode(request, forKey: .request)
        }
    }
}

private enum VaultDaemonEvent: Encodable {
    case approvalResponse(id: String, approved: Bool, reason: String?)
    case execChunk(id: String, stream: String, data: String)
    case execComplete(id: String, exitCode: Int32)
    case keyTransferImportResponse(id: String, imported: Int, alreadyPresent: Int)
    case dotenvKeychainLoadResponse(id: String, privateKey: String?)
    case dotenvKeychainStoreResponse(id: String, stored: Bool)
    case dotenvKeychainDeleteResponse(id: String, deleted: Bool)
    case error(id: String?, code: Int, message: String)

    enum CodingKeys: String, CodingKey {
        case type
        case id
        case approved
        case reason
        case stream
        case data
        case exitCode = "exit_code"
        case imported
        case alreadyPresent = "already_present"
        case privateKey = "private_key"
        case stored
        case deleted
        case code
        case message
    }

    enum EventType: String, Codable {
        case approvalResponse = "approval_response"
        case execChunk = "exec_chunk"
        case execComplete = "exec_complete"
        case keyTransferImportResponse = "key_transfer_import_response"
        case dotenvKeychainLoadResponse = "dotenv_keychain_load_response"
        case dotenvKeychainStoreResponse = "dotenv_keychain_store_response"
        case dotenvKeychainDeleteResponse = "dotenv_keychain_delete_response"
        case error
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .approvalResponse(let id, let approved, let reason):
            try container.encode(EventType.approvalResponse, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(approved, forKey: .approved)
            try container.encodeIfPresent(reason, forKey: .reason)
        case .execChunk(let id, let stream, let data):
            try container.encode(EventType.execChunk, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(stream, forKey: .stream)
            try container.encode(data, forKey: .data)
        case .execComplete(let id, let exitCode):
            try container.encode(EventType.execComplete, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(exitCode, forKey: .exitCode)
        case .keyTransferImportResponse(let id, let imported, let alreadyPresent):
            try container.encode(EventType.keyTransferImportResponse, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(imported, forKey: .imported)
            try container.encode(alreadyPresent, forKey: .alreadyPresent)
        case .dotenvKeychainLoadResponse(let id, let privateKey):
            try container.encode(EventType.dotenvKeychainLoadResponse, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encodeIfPresent(privateKey, forKey: .privateKey)
        case .dotenvKeychainStoreResponse(let id, let stored):
            try container.encode(EventType.dotenvKeychainStoreResponse, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(stored, forKey: .stored)
        case .dotenvKeychainDeleteResponse(let id, let deleted):
            try container.encode(EventType.dotenvKeychainDeleteResponse, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(deleted, forKey: .deleted)
        case .error(let id, let code, let message):
            try container.encode(EventType.error, forKey: .type)
            try container.encodeIfPresent(id, forKey: .id)
            try container.encode(code, forKey: .code)
            try container.encode(message, forKey: .message)
        }
    }
}

final class VaultDaemon {
    private static let dotenvKeychainService = "com.automicvault.dotenv"
    private static let defaultDotenvKeychainAccessGroup = "ZU76A67LGU.com.automicvault.dotenv"
    private static let dotenvPrivateKeyAccountPrefix = "DOTENV_PRIVATE_KEY:"
    private static let dotenvBrokerAuthorizedClientsInfoKey = "AVDotenvKeychainBrokerAuthorizedClients"
    private static let defaultDotenvBrokerAuthorizedClientIdentifiers = [
        "com.automicvault.av",
        "com.automicvault.menu-helper.av"
    ]

    struct Configuration {
        let socketURL: URL
    }

    private let configuration: Configuration
    private let approvalStore = VaultApprovalStore()
    private let keyTransferApprovalStore = KeyTransferApprovalStore()
    private let containmentLogStore = ContainmentLogStore()
    private let statusStore = NucleusStatusStore()
    private let queue = DispatchQueue(label: "com.automicvault.vault.daemon", qos: .userInitiated)
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let dotenvKeychainAccessGroup: String
    private let activeRequestLock = NSLock()
    private let stateLock = NSLock()
    private var activeRequestID: String?
    private var listeningSocket: Int32 = -1
    private var shouldRun = false
    private let openMainWindow: () -> Void
    private let notifyUser: () -> Void

    init(
        configuration: Configuration = .default,
        openMainWindow: @escaping () -> Void,
        notifyUser: @escaping () -> Void
    ) {
        self.configuration = configuration
        self.openMainWindow = openMainWindow
        self.notifyUser = notifyUser
        self.dotenvKeychainAccessGroup =
            Bundle.main.object(forInfoDictionaryKey: "AVDotenvKeychainAccessGroup") as? String
            ?? Self.defaultDotenvKeychainAccessGroup
    }

    func start() {
        guard beginRunning() else { return }
        queue.async {
            do {
                try self.startServer()
            } catch {
                NSLog("vaultd failed to start: %@", error.localizedDescription)
                self.endRunning()
            }
        }
    }

    func stop() {
        let socket = stopRunning()
        if socket >= 0 {
            Darwin.close(socket)
        }
        try? FileManager.default.removeItem(at: configuration.socketURL)
    }

    private func startServer() throws {
        try FileManager.default.createDirectory(
            at: configuration.socketURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: configuration.socketURL.deletingLastPathComponent().path
        )
        try? FileManager.default.removeItem(at: configuration.socketURL)

        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(configuration.socketURL.path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            Darwin.close(socketFD)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ENAMETOOLONG))
        }
        #if os(macOS)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        #endif
        withUnsafeMutablePointer(to: &address.sun_path) { pathPointer in
            pathPointer.withMemoryRebound(to: CChar.self, capacity: pathBytes.count + 1) { buffer in
                _ = strncpy(buffer, configuration.socketURL.path, pathBytes.count)
                buffer[pathBytes.count] = 0
            }
        }

        var bindAddress = address
        let bindResult = withUnsafePointer(to: &bindAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                bind(
                    socketFD,
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_un>.stride)
                )
            }
        }
        guard bindResult == 0 else {
            let code = errno
            Darwin.close(socketFD)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(code))
        }
        chmod(configuration.socketURL.path, 0o600)

        guard listen(socketFD, 8) == 0 else {
            let code = errno
            Darwin.close(socketFD)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(code))
        }

        setListeningSocket(socketFD)
        defer {
            clearListeningSocket(socketFD)
            Darwin.close(socketFD)
            try? FileManager.default.removeItem(at: configuration.socketURL)
            endRunning()
        }

        while isRunning {
            let clientFD = accept(socketFD, nil, nil)
            if clientFD < 0 {
                if errno == EINTR || isRunning == false {
                    continue
                }
                NSLog("vaultd accept failed: %d", errno)
                continue
            }
            handleClient(clientFD)
        }
    }

    private func handleClient(_ clientFD: Int32) {
        defer { Darwin.close(clientFD) }
        guard let line = readLine(from: clientFD) else {
            return
        }
        let data = Data(line.utf8)
        let request: VaultClientRequest
        do {
            request = try decoder.decode(VaultClientRequest.self, from: data)
        } catch {
            send(.error(id: nil, code: 400, message: "invalid request"), to: clientFD)
            return
        }

        switch request {
        case .containmentStarted(let session):
            processContainmentStarted(session)
        case .approvalRequest(let request):
            processApprovalRequest(request, clientFD: clientFD)
        case .keyTransferApprovalRequest(let request):
            processKeyTransferApprovalRequest(request, clientFD: clientFD)
        case .keyTransferImportRequest(let request):
            processKeyTransferImportRequest(request, clientFD: clientFD)
        case .dotenvKeychainLoadRequest(let request):
            processDotenvKeychainLoadRequest(request, clientFD: clientFD)
        case .dotenvKeychainStoreRequest(let request):
            processDotenvKeychainStoreRequest(request, clientFD: clientFD)
        case .dotenvKeychainDeleteRequest(let request):
            processDotenvKeychainDeleteRequest(request, clientFD: clientFD)
        }
    }

    private func processContainmentStarted(_ session: VaultClientContainmentSession) {
        let snapshot = VaultContainmentSessionSnapshot(
            id: session.id,
            pid: session.pid,
            agentID: session.agentID,
            command: session.command,
            args: session.args,
            cwd: session.cwd,
            initialExecutablePath: session.initialExecutablePath,
            toolchainRoot: session.toolchainRoot,
            binDir: session.binDir,
            sandboxProfilePath: session.sandboxProfilePath,
            socketPath: session.socketPath,
            startedAt: Date()
        )
        try? containmentLogStore.startSession(snapshot)
    }

    private func processApprovalRequest(
        _ request: VaultClientApprovalRequest,
        clientFD: Int32
    ) {
        guard beginRequest(id: request.id) else {
            send(.error(id: request.id, code: 409, message: "vaultd is already processing a request"), to: clientFD)
            return
        }
        defer { endRequest(id: request.id) }

        do {
            try approvalStore.savePendingApproval(
                VaultApprovalRequestSnapshot(id: request.id, intent: request.intent)
            )
            appendCommandLog(for: request)
            appendApprovalPendingLog(for: request)
            routeApprovalPresentation()
            let decision = waitForDecision(id: request.id)
                ?? VaultApprovalDecision(id: request.id, approved: false, reason: "approval unavailable")
            appendApprovalLog(for: request, decision: decision)
            send(
                .approvalResponse(
                    id: decision.id,
                    approved: decision.approved,
                    reason: decision.reason
                ),
                to: clientFD
            )
            guard decision.approved else {
                approvalStore.clearPendingApproval(id: request.id)
                return
            }
            execute(intent: request.intent, id: request.id, clientFD: clientFD)
            approvalStore.clearPendingApproval(id: request.id)
        } catch {
            approvalStore.clearPendingApproval(id: request.id)
            send(
                .error(
                    id: request.id,
                    code: 500,
                    message: error.localizedDescription
                ),
                to: clientFD
            )
        }
    }

    private func processKeyTransferApprovalRequest(
        _ request: KeyTransferApprovalRequestSnapshot,
        clientFD: Int32
    ) {
        guard beginRequest(id: request.id) else {
            send(.error(id: request.id, code: 409, message: "vaultd is already processing a request"), to: clientFD)
            return
        }
        defer { endRequest(id: request.id) }

        do {
            try keyTransferApprovalStore.savePendingApproval(request)
            routeApprovalPresentation()
            let decision = waitForKeyTransferDecision(id: request.id)
                ?? KeyTransferApprovalDecision(
                    id: request.id,
                    approved: false,
                    reason: "approval unavailable"
                )
            send(
                .approvalResponse(
                    id: decision.id,
                    approved: decision.approved,
                    reason: decision.reason
                ),
                to: clientFD
            )
            keyTransferApprovalStore.clearPendingApproval(id: request.id)
        } catch {
            keyTransferApprovalStore.clearPendingApproval(id: request.id)
            send(
                .error(
                    id: request.id,
                    code: 500,
                    message: error.localizedDescription
                ),
                to: clientFD
            )
        }
    }

    private func processKeyTransferImportRequest(
        _ request: KeyTransferImportRequest,
        clientFD: Int32
    ) {
        guard beginRequest(id: request.id) else {
            send(.error(id: request.id, code: 409, message: "vaultd is already processing a request"), to: clientFD)
            return
        }
        defer { endRequest(id: request.id) }

        do {
            let plan = try keyTransferImportPlan(for: request)
            try keyTransferApprovalStore.savePendingApproval(plan.approval)
            routeApprovalPresentation()
            let decision = waitForKeyTransferDecision(id: request.id)
                ?? KeyTransferApprovalDecision(
                    id: request.id,
                    approved: false,
                    reason: "approval unavailable"
                )
            guard decision.approved else {
                keyTransferApprovalStore.clearPendingApproval(id: request.id)
                send(
                    .error(
                        id: request.id,
                        code: 1,
                        message: decision.reason ?? "key transfer denied"
                    ),
                    to: clientFD
                )
                return
            }
            let imported = try applyKeyTransferImport(plan.actions)
            send(
                .keyTransferImportResponse(
                    id: request.id,
                    imported: imported,
                    alreadyPresent: plan.alreadyPresent
                ),
                to: clientFD
            )
            keyTransferApprovalStore.clearPendingApproval(id: request.id)
        } catch {
            keyTransferApprovalStore.clearPendingApproval(id: request.id)
            send(
                .error(
                    id: request.id,
                    code: 500,
                    message: error.localizedDescription
                ),
                to: clientFD
            )
        }
    }

    private func processDotenvKeychainLoadRequest(
        _ request: DotenvKeychainLoadRequest,
        clientFD: Int32
    ) {
        guard requireAuthorizedDotenvKeychainClient(clientFD: clientFD, id: request.id) else {
            return
        }

        do {
            try validateDotenvPrivateKeyAccount(request.account)
            let privateKey = try dotenvPrivateKeyRead(account: request.account)
            send(
                .dotenvKeychainLoadResponse(
                    id: request.id,
                    privateKey: privateKey
                ),
                to: clientFD
            )
        } catch {
            send(
                .error(id: request.id, code: 500, message: error.localizedDescription),
                to: clientFD
            )
        }
    }

    private func processDotenvKeychainStoreRequest(
        _ request: DotenvKeychainStoreRequest,
        clientFD: Int32
    ) {
        guard requireAuthorizedDotenvKeychainClient(clientFD: clientFD, id: request.id) else {
            return
        }

        do {
            try validateDotenvPrivateKeyAccount(request.account)
            try validateDotenvPrivateKey(request.privateKey)
            try dotenvPrivateKeyWrite(account: request.account, value: request.privateKey)
            send(
                .dotenvKeychainStoreResponse(id: request.id, stored: true),
                to: clientFD
            )
        } catch {
            send(
                .error(id: request.id, code: 500, message: error.localizedDescription),
                to: clientFD
            )
        }
    }

    private func processDotenvKeychainDeleteRequest(
        _ request: DotenvKeychainDeleteRequest,
        clientFD: Int32
    ) {
        guard requireAuthorizedDotenvKeychainClient(clientFD: clientFD, id: request.id) else {
            return
        }

        do {
            try validateDotenvPrivateKeyAccount(request.account)
            let deleted = try dotenvPrivateKeyDelete(account: request.account)
            send(
                .dotenvKeychainDeleteResponse(id: request.id, deleted: deleted),
                to: clientFD
            )
        } catch {
            send(
                .error(id: request.id, code: 500, message: error.localizedDescription),
                to: clientFD
            )
        }
    }

    private func keyTransferImportPlan(
        for request: KeyTransferImportRequest
    ) throws -> KeyTransferImportPlan {
        guard request.items.isEmpty == false else {
            throw daemonError("transfer bundle contains no keys")
        }

        var approvalItems: [KeyTransferApprovalItem] = []
        var actions: [KeyTransferImportAction] = []
        var alreadyPresent = 0
        var conflicts: [String] = []
        var seen: Set<String> = []

        for item in request.items {
            switch item {
            case .dotenvPrivateKey(
                let envFilePath,
                let publicKeyName,
                let publicKey,
                let publicKeyFingerprint,
                let privateKey
            ):
                try validateDotenvPublicKeyName(publicKeyName)
                try validateHex(publicKey, bytes: 33, label: "dotenv public key")
                try validateHex(publicKeyFingerprint, bytes: 32, label: "dotenv public key fingerprint")
                guard sha256Hex(publicKey) == publicKeyFingerprint else {
                    throw daemonError("dotenv public key fingerprint mismatch")
                }
                try validateDotenvPrivateKey(privateKey)
                guard seen.insert("dotenv:\(publicKeyFingerprint)").inserted else {
                    throw daemonError("duplicate dotenv private key \(fingerprintPrefix(publicKeyFingerprint))")
                }

                let existing = try dotenvPrivateKeyRead(
                    account: dotenvPrivateKeyAccount(publicKeyFingerprint: publicKeyFingerprint)
                )
                let replacingExisting = existing.map { $0 != privateKey } ?? false
                approvalItems.append(
                    KeyTransferApprovalItem(
                        kind: "dotenv",
                        name: publicKeyName,
                        detail: "\(envFilePath) (\(fingerprintPrefix(publicKeyFingerprint)))",
                        replacingExisting: replacingExisting
                    )
                )
                if let existing {
                    if existing == privateKey {
                        alreadyPresent += 1
                    } else if request.replace {
                        actions.append(
                            .storeDotenvPrivateKey(
                                publicKeyFingerprint: publicKeyFingerprint,
                                privateKey: privateKey
                            )
                        )
                    } else {
                        conflicts.append("dotenv private key \(fingerprintPrefix(publicKeyFingerprint))")
                    }
                } else {
                    actions.append(
                        .storeDotenvPrivateKey(
                            publicKeyFingerprint: publicKeyFingerprint,
                            privateKey: privateKey
                        )
                    )
                }
            case .isotopeSecret(let key, let value):
                try validateIsotopeKeyName(key)
                guard seen.insert("isotope:\(key)").inserted else {
                    throw daemonError("duplicate isotope key \(key)")
                }
                let existing = try keychainRead(
                    service: "com.automicvault.isotope",
                    account: key
                )
                let replacingExisting = existing.map { $0 != value } ?? false
                approvalItems.append(
                    KeyTransferApprovalItem(
                        kind: "isotope",
                        name: key,
                        detail: nil,
                        replacingExisting: replacingExisting
                    )
                )
                if let existing {
                    if existing == value {
                        alreadyPresent += 1
                    } else if request.replace {
                        actions.append(.storeIsotopeSecret(key: key, value: value))
                    } else {
                        conflicts.append("isotope key \(key)")
                    }
                } else {
                    actions.append(.storeIsotopeSecret(key: key, value: value))
                }
            }
        }

        if conflicts.isEmpty == false {
            throw daemonError(
                "destination already has different values for \(conflicts.joined(separator: ", ")); rerun with --replace to overwrite"
            )
        }

        return KeyTransferImportPlan(
            approval: KeyTransferApprovalRequestSnapshot(
                id: request.id,
                source: request.source,
                itemCount: request.items.count,
                replace: request.replace,
                items: approvalItems
            ),
            actions: actions,
            alreadyPresent: alreadyPresent
        )
    }

    private func applyKeyTransferImport(_ actions: [KeyTransferImportAction]) throws -> Int {
        for action in actions {
            switch action {
            case .storeDotenvPrivateKey(let publicKeyFingerprint, let privateKey):
                try dotenvPrivateKeyWrite(
                    account: dotenvPrivateKeyAccount(publicKeyFingerprint: publicKeyFingerprint),
                    value: privateKey
                )
            case .storeIsotopeSecret(let key, let value):
                try keychainWrite(
                    service: "com.automicvault.isotope",
                    account: key,
                    value: value
                )
            }
        }
        return actions.count
    }

    private func dotenvPrivateKeyAccount(publicKeyFingerprint: String) -> String {
        "\(Self.dotenvPrivateKeyAccountPrefix)\(publicKeyFingerprint)"
    }

    private func validateDotenvPublicKeyName(_ name: String) throws {
        guard name == "DOTENV_PUBLIC_KEY"
            || (name.hasPrefix("DOTENV_PUBLIC_KEY_") && name.count > "DOTENV_PUBLIC_KEY_".count)
        else {
            throw daemonError("invalid dotenv public key name: \(name)")
        }
    }

    private func validateDotenvPrivateKeyAccount(_ account: String) throws {
        guard account.hasPrefix(Self.dotenvPrivateKeyAccountPrefix) else {
            throw daemonError("invalid dotenv private key account")
        }
        let fingerprint = String(account.dropFirst(Self.dotenvPrivateKeyAccountPrefix.count))
        try validateHex(fingerprint, bytes: 32, label: "dotenv public key fingerprint")
    }

    private func validateDotenvPrivateKey(_ value: String) throws {
        for part in value.split(separator: ",") where part.isEmpty == false {
            try validateHex(String(part), bytes: 32, label: "dotenv private key")
        }
    }

    private func validateIsotopeKeyName(_ key: String) throws {
        guard let first = key.unicodeScalars.first else {
            throw daemonError("empty isotope key name")
        }
        guard first == "_" || CharacterSet.letters.contains(first) else {
            throw daemonError("invalid isotope key name: \(key)")
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_"))
        guard key.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw daemonError("invalid isotope key name: \(key)")
        }
    }

    private func validateHex(_ value: String, bytes: Int, label: String) throws {
        guard value.count == bytes * 2 else {
            throw daemonError("\(label) must be \(bytes) bytes")
        }
        let hex = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        guard value.unicodeScalars.allSatisfy({ hex.contains($0) }) else {
            throw daemonError("\(label) must be hex")
        }
    }

    private func sha256Hex(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private func fingerprintPrefix(_ value: String) -> String {
        String(value.prefix(12))
    }

    private func dotenvPrivateKeyRead(account: String) throws -> String? {
        let query = dotenvPrivateKeyQuery(account: account).merging([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]) { _, new in new }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return try keychainRead(service: Self.dotenvKeychainService, account: account)
        }
        guard status == errSecSuccess else {
            throw dotenvKeychainError(action: "load", account: account, status: status)
        }
        guard let data = result as? Data,
              let value = String(data: data, encoding: .utf8)
        else {
            throw daemonError("dotenv keychain lookup did not return UTF-8 data")
        }
        return value
    }

    private func dotenvPrivateKeyWrite(account: String, value: String) throws {
        let data = Data(value.utf8)
        let query = dotenvPrivateKeyQuery(account: account)
        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var createQuery = query
            createQuery[kSecValueData as String] = data
            status = SecItemAdd(createQuery as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw dotenvKeychainError(action: "store", account: account, status: status)
        }
    }

    private func dotenvPrivateKeyDelete(account: String) throws -> Bool {
        let query = dotenvPrivateKeyQuery(account: account)
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            return false
        }
        guard status == errSecSuccess else {
            throw dotenvKeychainError(action: "delete", account: account, status: status)
        }
        return true
    }

    private func dotenvPrivateKeyQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.dotenvKeychainService,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: dotenvKeychainAccessGroup
        ]
    }

    private func dotenvKeychainError(action: String, account: String, status: OSStatus) -> Error {
        let securityMessage = securityErrorMessage(status)
        var message = "failed to \(action) dotenv private key \(account) in Data Protection keychain access group \(dotenvKeychainAccessGroup): \(securityMessage)"
        if status == -34018 || securityMessage.localizedCaseInsensitiveContains("entitlement") {
            message += "; ensure this binary is signed with keychain-access-groups containing \(dotenvKeychainAccessGroup); verify with `codesign -d --entitlements - <path>`"
        }
        return daemonError(message)
    }

    private func keychainRead(service: String, account: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw daemonError("failed to load keychain item \(account): \(securityErrorMessage(status))")
        }
        guard let data = result as? Data,
              let value = String(data: data, encoding: .utf8)
        else {
            throw daemonError("keychain lookup did not return UTF-8 data")
        }
        return value
    }

    private func keychainWrite(service: String, account: String, value: String) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var createQuery = query
            createQuery[kSecValueData as String] = data
            createQuery[kSecAttrAccess as String] = try passwordAccess(service: service)
            status = SecItemAdd(createQuery as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw daemonError("failed to store keychain item \(account): \(securityErrorMessage(status))")
        }
    }

    private func passwordAccess(service: String) throws -> SecAccess {
        var trustedApplications: [SecTrustedApplication] = []
        var currentApplication: SecTrustedApplication?
        var status = SecTrustedApplicationCreateFromPath(nil, &currentApplication)
        guard status == errSecSuccess, let currentApplication else {
            throw daemonError("trusted application failed: \(securityErrorMessage(status))")
        }
        trustedApplications.append(currentApplication)

        let avPath = "/usr/local/bin/av"
        if FileManager.default.isExecutableFile(atPath: avPath) {
            var avApplication: SecTrustedApplication?
            status = avPath.withCString { path in
                SecTrustedApplicationCreateFromPath(path, &avApplication)
            }
            guard status == errSecSuccess, let avApplication else {
                throw daemonError("trusted application failed for \(avPath): \(securityErrorMessage(status))")
            }
            trustedApplications.append(avApplication)
        }

        var access: SecAccess?
        status = SecAccessCreate(service as CFString, trustedApplications as CFArray, &access)
        guard status == errSecSuccess, let access else {
            throw daemonError("keychain access failed: \(securityErrorMessage(status))")
        }
        return access
    }

    private func requireAuthorizedDotenvKeychainClient(clientFD: Int32, id: String) -> Bool {
        guard let auditToken = peerAuditToken(for: clientFD),
              authorizedDotenvBrokerRequirements.contains(where: { requirement in
                  process(auditToken: auditToken, satisfies: requirement)
              })
        else {
            send(
                .error(
                    id: id,
                    code: 403,
                    message: "dotenv keychain broker request rejected: unauthorized client"
                ),
                to: clientFD
            )
            return false
        }
        return true
    }

    private var authorizedDotenvBrokerRequirements: [String] {
        if let configured = Bundle.main.object(
            forInfoDictionaryKey: Self.dotenvBrokerAuthorizedClientsInfoKey
        ) as? [String] {
            let requirements = configured.filter { $0.isEmpty == false }
            if requirements.isEmpty == false {
                return requirements
            }
        }

        let configuredTeamIdentifier = dotenvKeychainAccessGroup
            .components(separatedBy: ".")
            .first ?? ""
        let teamIdentifier = configuredTeamIdentifier.isEmpty
            ? "ZU76A67LGU"
            : configuredTeamIdentifier
        return Self.defaultDotenvBrokerAuthorizedClientIdentifiers.map { identifier in
            "identifier \"\(identifier)\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
        }
    }

    private func peerAuditToken(for clientFD: Int32) -> Data? {
        var auditToken = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        let result = withUnsafeMutablePointer(to: &auditToken) { pointer in
            getsockopt(
                clientFD,
                localPeerTokenSocketOptionLevel,
                localPeerTokenSocketOptionName,
                pointer,
                &length
            )
        }
        guard result == 0, length == socklen_t(MemoryLayout<audit_token_t>.size) else {
            return nil
        }
        return withUnsafeBytes(of: auditToken) { Data($0) }
    }

    private func process(auditToken: Data, satisfies requirementString: String) -> Bool {
        let attributes: [String: Any] = [
            kSecGuestAttributeAudit as String: auditToken
        ]
        var guest: SecCode?
        let codeStatus = SecCodeCopyGuestWithAttributes(
            nil,
            attributes as CFDictionary,
            SecCSFlags(),
            &guest
        )
        guard codeStatus == errSecSuccess, let guest else {
            return false
        }

        var requirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(
            requirementString as CFString,
            SecCSFlags(),
            &requirement
        )
        guard requirementStatus == errSecSuccess, let requirement else {
            return false
        }

        return SecCodeCheckValidity(guest, SecCSFlags(), requirement) == errSecSuccess
    }

    private func securityErrorMessage(_ status: OSStatus) -> String {
        if let message = SecCopyErrorMessageString(status, nil) as String? {
            return message
        }
        return "Security error \(status)"
    }

    private func daemonError(_ message: String) -> NSError {
        NSError(domain: "com.automicvault.vaultd", code: 1, userInfo: [
            NSLocalizedDescriptionKey: message
        ])
    }

    private func routeApprovalPresentation() {
        if NSRunningApplication.runningApplications(withBundleIdentifier: "com.automicvault").isEmpty {
            notifyUser()
        }
    }

    private func waitForDecision(id: String) -> VaultApprovalDecision? {
        while isRunning {
            if let decision = approvalStore.loadDecision(id: id) {
                return decision
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return nil
    }

    private func waitForKeyTransferDecision(id: String) -> KeyTransferApprovalDecision? {
        while isRunning {
            if let decision = keyTransferApprovalStore.loadDecision(id: id) {
                return decision
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return nil
    }

    private var isRunning: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return shouldRun
    }

    private func beginRunning() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard shouldRun == false else { return false }
        shouldRun = true
        return true
    }

    private func endRunning() {
        stateLock.lock()
        shouldRun = false
        stateLock.unlock()
    }

    private func stopRunning() -> Int32 {
        stateLock.lock()
        defer { stateLock.unlock() }
        shouldRun = false
        let socket = listeningSocket
        listeningSocket = -1
        return socket
    }

    private func setListeningSocket(_ socket: Int32) {
        stateLock.lock()
        listeningSocket = socket
        stateLock.unlock()
    }

    private func clearListeningSocket(_ socket: Int32) {
        stateLock.lock()
        if listeningSocket == socket {
            listeningSocket = -1
        }
        stateLock.unlock()
    }

    private func execute(intent: VaultExecutionIntent, id: String, clientFD: Int32) {
        let process = Process()
        guard let executableURL = resolveExecutableURL(for: intent.tool) else {
            appendLog(
                sessionID: intent.agentID,
                kind: .error,
                title: "Could not resolve command",
                detail: intent.tool
            )
            send(.error(id: id, code: 404, message: "unable to resolve \(intent.tool)"), to: clientFD)
            return
        }

        process.executableURL = executableURL
        process.arguments = intent.args
        process.currentDirectoryURL = URL(fileURLWithPath: intent.cwd, isDirectory: true)
        process.environment = hostEnvironment(from: intent.env)

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        stdoutPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            guard data.isEmpty == false else { return }
            self.sendChunk(data, stream: "stdout", id: id, clientFD: clientFD)
        }

        stderrPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            guard data.isEmpty == false else { return }
            self.sendChunk(data, stream: "stderr", id: id, clientFD: clientFD)
        }

        do {
            try process.run()
        } catch {
            stdoutPipe.fileHandleForReading.readabilityHandler = nil
            stderrPipe.fileHandleForReading.readabilityHandler = nil
            appendLog(
                sessionID: intent.agentID,
                kind: .error,
                title: "Could not launch command",
                detail: error.localizedDescription
            )
            send(.error(id: id, code: 500, message: error.localizedDescription), to: clientFD)
            return
        }

        process.waitUntilExit()
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil

        let remainingStdout = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        if remainingStdout.isEmpty == false {
            sendChunk(remainingStdout, stream: "stdout", id: id, clientFD: clientFD)
        }
        let remainingStderr = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        if remainingStderr.isEmpty == false {
            sendChunk(remainingStderr, stream: "stderr", id: id, clientFD: clientFD)
        }

        send(.execComplete(id: id, exitCode: process.terminationStatus), to: clientFD)
    }

    private func appendCommandLog(for request: VaultClientApprovalRequest) {
        appendLog(
            sessionID: request.intent.agentID,
            kind: .command,
            title: commandLine(for: request.intent),
            detail: "cwd: \(request.intent.cwd)"
        )
    }

    private func appendApprovalLog(
        for request: VaultClientApprovalRequest,
        decision: VaultApprovalDecision
    ) {
        let title = decision.approved ? "Approved" : "Denied"
        appendLog(
            sessionID: request.intent.agentID,
            kind: .approval,
            title: title,
            detail: commandLine(for: request.intent)
        )
    }

    private func appendApprovalPendingLog(for request: VaultClientApprovalRequest) {
        appendLog(
            sessionID: request.intent.agentID,
            kind: .approval,
            title: "Approval requested",
            detail: commandLine(for: request.intent)
        )
    }

    private func appendLog(
        sessionID: String?,
        kind: VaultContainmentLogEntry.Kind,
        title: String,
        detail: String
    ) {
        guard let sessionID, sessionID.isEmpty == false else {
            return
        }
        try? containmentLogStore.append(
            sessionID: sessionID,
            kind: kind,
            title: title,
            detail: detail
        )
    }

    private func commandLine(for intent: VaultExecutionIntent) -> String {
        ([intent.tool] + intent.args).joined(separator: " ")
    }

    private func sendChunk(_ data: Data, stream: String, id: String, clientFD: Int32) {
        guard let chunk = String(data: data, encoding: .utf8), chunk.isEmpty == false else {
            return
        }
        send(.execChunk(id: id, stream: stream, data: chunk), to: clientFD)
    }

    private func send(_ event: VaultDaemonEvent, to clientFD: Int32) {
        guard let data = try? encoder.encode(event) else {
            return
        }
        _ = data.withUnsafeBytes { bytes in
            Darwin.write(clientFD, bytes.baseAddress, bytes.count)
        }
        _ = "\n".utf8CString.withUnsafeBytes { bytes in
            Darwin.write(clientFD, bytes.baseAddress, bytes.count - 1)
        }
    }

    private func readLine(from clientFD: Int32) -> String? {
        var data = Data()
        var byte: UInt8 = 0
        while true {
            let count = Darwin.read(clientFD, &byte, 1)
            if count <= 0 {
                break
            }
            if byte == 0x0A {
                break
            }
            data.append(byte)
        }
        guard data.isEmpty == false else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func beginRequest(id: String) -> Bool {
        activeRequestLock.lock()
        defer { activeRequestLock.unlock() }
        guard activeRequestID == nil else { return false }
        activeRequestID = id
        return true
    }

    private func endRequest(id: String) {
        activeRequestLock.lock()
        defer { activeRequestLock.unlock() }
        if activeRequestID == id {
            activeRequestID = nil
        }
    }

    private func resolveExecutableURL(for tool: String) -> URL? {
        let searchRoots = [
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin"
        ]
        for root in searchRoots {
            let candidate = URL(fileURLWithPath: root, isDirectory: true)
                .appendingPathComponent(tool, isDirectory: false)
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    private func hostEnvironment(from captured: [String: String]) -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        for (key, value) in captured {
            environment[key] = value
        }
        environment["PATH"] = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        environment.removeValue(forKey: "VAULT_SOCKET_PATH")
        environment.removeValue(forKey: "VAULT_TOOLCHAIN_ROOT")
        return environment
    }
}

private extension VaultDaemon.Configuration {
    static var `default`: Self {
        Self(
            socketURL: FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(
                    "Library/Application Support/Automic Vault",
                    isDirectory: true
                )
                .appendingPathComponent("vault.sock", isDirectory: false)
        )
    }
}
