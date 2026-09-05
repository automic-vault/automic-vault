@preconcurrency import Foundation
import CProcessInfo
import Darwin
import MenubarHelperCore
import Security

struct ProxyTargetIdentity: Sendable {
    let pid: pid_t
    let pidVersion: Int32
    let startUsec: UInt64
    let effectiveUserID: uid_t
    let auditSessionID: UInt32
}

struct ProxySessionLaunch: Sendable {
    let keys: [String]
    let target: String
    let arguments: [String]
    let cwd: String
    let selectedSecretValues: SelectedSecretValues
    let targetCodeIdentity: Data?
    let identity: ProxyTargetIdentity
}

struct ProxySessionMaterial: Sendable {
    let sessionID: UUID
    let proxyURL: String
    let caCertificatePath: String
    let references: [String: String]
}

struct ProxyDestinationRequest: Sendable {
    let sessionID: UUID
    let target: String
    let cwd: String
    let method: String
    let origin: String
    let path: String
    let queryNames: [String]
    let secretNames: [String]
    let selectedSecretValues: SelectedSecretValues
}

enum ProxyDestinationDecision: Sendable {
    case deny
    case allowOnce
    case allowForSession
}

struct ProxySessionSummary: Identifiable, Equatable, Sendable {
    let id: UUID
    let startedAt: Date
    let target: String
    let pid: Int32
    let secretNames: [String]
    let authorizedRequestCount: Int
    let authorizedOrigins: [String]
}

@MainActor
final class ProxySessionViewModel: ObservableObject {
    static let shared = ProxySessionViewModel()

    @Published private(set) var sessions: [ProxySessionSummary] = []

    func update(_ sessions: [ProxySessionSummary]) {
        self.sessions = sessions
    }

    func terminate(_ id: UUID) {
        Task { await SecretProxyCoordinator.shared.terminate(id: id) }
    }
}

actor SecretProxyCoordinator {
    static let shared = SecretProxyCoordinator()

    typealias DestinationApproval = @MainActor @Sendable (
        ProxyDestinationRequest,
        ApprovalCancellation
    ) -> ProxyDestinationDecision

    private struct DestinationRule: Hashable {
        let origin: String
        let secretNames: [String]
    }

    private struct PendingAuthorizationID: Hashable {
        let sessionID: UUID
        let requestID: UInt64
    }

    private struct Session {
        let id: UUID
        let startedAt: Date
        let launch: ProxySessionLaunch
        let references: [String: String]
        let caDirectory: URL
        let process: Process
        let input: FileHandle
        let output: FileHandle
        let secretValueCustody: SecretValueCustody
        let approveDestination: DestinationApproval
        var identity: ProxyTargetIdentity
        var codeIdentity: Data?
        var awaitsTargetExec: Bool
        var rules: Set<DestinationRule>
        var authorizedRequestCount: Int
        var authorizedOrigins: Set<String>
    }

    private var sessions: [UUID: Session] = [:]
    private var pendingAuthorizations: [PendingAuthorizationID: ApprovalCancellation] = [:]
    private var destinationPromptActive = false
    private var destinationPromptWaiters: [CheckedContinuation<Void, Never>] = []
    private let maximumControlFrame = 4 * 1024 * 1024

    func start(
        launch: ProxySessionLaunch,
        secretValueCustody: SecretValueCustody,
        approveDestination: @escaping DestinationApproval
    ) async throws -> ProxySessionMaterial {
        guard targetIsLive(launch.identity),
              proxyExecutableCodeIdentity(path: launch.target) == launch.targetCodeIdentity
        else {
            throw SecretProxyError("Target identity changed before the Proxy Session started")
        }
        let helper = try verifiedHelperURL()
        let id = UUID()
        let credential = try randomToken(prefix: "avproxy_", byteCount: 32)
        var references: [String: String] = [:]
        for key in launch.keys {
            references[key] = try randomToken(prefix: "avref_", byteCount: 32)
        }

        let process = Process()
        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process.executableURL = helper
        process.arguments = []
        process.environment = ["AV_PROXY_CONTROL": "1"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/", isDirectory: true)
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        inputPipe.fileHandleForReading.closeFile()
        outputPipe.fileHandleForWriting.closeFile()
        guard runningHelperHasExpectedSignature(pid: process.processIdentifier) else {
            process.terminate()
            throw SecretProxyError("Running proxy helper failed code-signing verification")
        }

        do {
            try writeFrame([
                "type": "bootstrap",
                "session_id": id.uuidString.lowercased(),
                "proxy_credential": credential,
                "target": [
                    "pid": Int(launch.identity.pid),
                    "pid_version": Int(launch.identity.pidVersion),
                    "start_usec": launch.identity.startUsec,
                ],
                "references": references,
            ], to: inputPipe.fileHandleForWriting)
            let ready = try await readFrame(
                from: outputPipe.fileHandleForReading,
                timeout: .seconds(5)
            )
            guard ready["type"] as? String == "ready",
                  ready["session_id"] as? String == id.uuidString.lowercased(),
                  let port = ready["port"] as? Int,
                  (1...65_535).contains(port),
                  let caPEM = ready["ca_pem"] as? String,
                  caPEM.hasPrefix("-----BEGIN CERTIFICATE-----")
            else {
                throw SecretProxyError("Proxy helper returned an invalid ready message")
            }
            guard targetIsLive(launch.identity) else {
                throw SecretProxyError("Target identity changed while the Proxy Session started")
            }
            let (caDirectory, caURL) = try writeSessionCertificate(caPEM, sessionID: id)
            process.terminationHandler = { _ in
                Task { await SecretProxyCoordinator.shared.helperTerminated(id: id) }
            }
            sessions[id] = Session(
                id: id,
                startedAt: Date(),
                launch: launch,
                references: references,
                caDirectory: caDirectory,
                process: process,
                input: inputPipe.fileHandleForWriting,
                output: outputPipe.fileHandleForReading,
                secretValueCustody: secretValueCustody,
                approveDestination: approveDestination,
                identity: launch.identity,
                codeIdentity: liveCodeIdentity(pid: launch.identity.pid),
                awaitsTargetExec: true,
                rules: [],
                authorizedRequestCount: 0,
                authorizedOrigins: []
            )
            publishSessions()
            startControlReader(id: id, output: outputPipe.fileHandleForReading)
            startTargetMonitor(id: id)
            return ProxySessionMaterial(
                sessionID: id,
                proxyURL: "http://av:\(credential)@127.0.0.1:\(port)",
                caCertificatePath: caURL.path,
                references: references
            )
        } catch {
            inputPipe.fileHandleForWriting.closeFile()
            outputPipe.fileHandleForReading.closeFile()
            if process.isRunning { process.terminate() }
            throw error
        }
    }

    func terminate(id: UUID) {
        guard let session = sessions.removeValue(forKey: id) else { return }
        let pendingIDs = pendingAuthorizations.keys.filter { $0.sessionID == id }
        let cancellations = pendingIDs.compactMap { pendingAuthorizations.removeValue(forKey: $0) }
        cancellations.forEach { $0.cancel() }
        try? writeFrame(["type": "shutdown"], to: session.input)
        session.input.closeFile()
        session.output.closeFile()
        if session.process.isRunning { session.process.terminate() }
        try? FileManager.default.removeItem(at: session.caDirectory)
        publishSessions()
    }

    private func helperTerminated(id: UUID) {
        terminate(id: id)
    }

    private func startControlReader(id: UUID, output: FileHandle) {
        Task.detached { [weak self] in
            do {
                while let payload = try Self.readFramePayloadSynchronously(
                    from: output,
                    maximumLength: 4 * 1024 * 1024,
                    timeoutMilliseconds: nil
                ) {
                    await self?.receive(payload, sessionID: id)
                }
            } catch {}
            await self?.terminate(id: id)
        }
    }

    private func startTargetMonitor(id: UUID) {
        Task { [weak self] in
            while let self, await self.refreshTargetIdentity(id: id) {
                let interval = await self.sessions[id]?.awaitsTargetExec == true ? 25 : 250
                try? await Task.sleep(for: .milliseconds(interval))
            }
            await self?.terminate(id: id)
        }
    }

    private func refreshTargetIdentity(id: UUID) -> Bool {
        guard var session = sessions[id] else { return false }
        var current = AVProcessIdentity()
        guard av_process_identity(session.identity.pid, &current),
              current.start_usec == session.identity.startUsec,
              current.euid == session.identity.effectiveUserID,
              current.audit_session_id == session.identity.auditSessionID
        else { return false }
        if current.pidversion == session.identity.pidVersion {
            return session.codeIdentity.map { liveCodeIdentity(pid: current.pid) == $0 } ?? true
        }
        guard session.awaitsTargetExec,
              current.pidversion > 0,
              processPath(current) == session.launch.target,
              liveCodeIdentity(pid: current.pid) == session.launch.targetCodeIdentity
        else { return false }
        session.identity = ProxyTargetIdentity(
            pid: current.pid,
            pidVersion: current.pidversion,
            startUsec: current.start_usec,
            effectiveUserID: current.euid,
            auditSessionID: current.audit_session_id
        )
        session.codeIdentity = liveCodeIdentity(pid: current.pid)
        session.awaitsTargetExec = false
        sessions[id] = session
        return true
    }

    private func receive(_ payload: Data, sessionID: UUID) {
        guard let frame = try? decodeFrame(payload) else {
            terminate(id: sessionID)
            return
        }
        guard let type = frame["type"] as? String,
              let wireSessionID = frame["session_id"] as? String,
              wireSessionID == sessionID.uuidString.lowercased(),
              let requestID = frame["request_id"] as? UInt64 ?? (frame["request_id"] as? NSNumber)?.uint64Value,
              requestID > 0
        else {
            terminate(id: sessionID)
            return
        }
        let pendingID = PendingAuthorizationID(sessionID: sessionID, requestID: requestID)
        if type == "cancel" {
            pendingAuthorizations.removeValue(forKey: pendingID)?.cancel()
            return
        }
        guard type == "authorize",
              let method = frame["method"] as? String,
              let origin = frame["origin"] as? String,
              let path = frame["path"] as? String,
              let queryNames = frame["query_names"] as? [String],
              let secretNames = frame["secret_names"] as? [String],
              pendingAuthorizations[pendingID] == nil
        else {
            terminate(id: sessionID)
            return
        }
        let cancellation = ApprovalCancellation()
        pendingAuthorizations[pendingID] = cancellation
        Task {
            await authorize(
                sessionID: sessionID,
                requestID: requestID,
                method: method,
                origin: origin,
                path: path,
                queryNames: queryNames,
                secretNames: secretNames,
                cancellation: cancellation
            )
        }
    }

    private func authorize(
        sessionID: UUID,
        requestID: UInt64,
        method: String,
        origin: String,
        path: String,
        queryNames: [String],
        secretNames: [String],
        cancellation: ApprovalCancellation
    ) async {
        let pendingID = PendingAuthorizationID(sessionID: sessionID, requestID: requestID)
        defer {
            if pendingAuthorizations[pendingID] === cancellation {
                pendingAuthorizations.removeValue(forKey: pendingID)
            }
        }
        guard !cancellation.isCanceled else { return }
        guard refreshTargetIdentity(id: sessionID),
              var session = sessions[sessionID],
              validOrigin(origin),
              method.range(of: #"^[A-Z]{1,16}$"#, options: .regularExpression) != nil,
              path.hasPrefix("/"), path.count <= 2048,
              queryNames.count <= 128,
              queryNames.allSatisfy({ !$0.isEmpty && $0.count <= 256 }),
              !secretNames.isEmpty,
              Set(secretNames).count == secretNames.count,
              secretNames.allSatisfy({
                  session.references[$0] != nil
                      && session.launch.selectedSecretValues.contains($0)
              })
        else {
            deny(sessionID: sessionID, requestID: requestID, reason: "invalid or expired Proxy Session request")
            return
        }
        let sortedNames = secretNames.sorted()
        let rule = DestinationRule(origin: origin, secretNames: sortedNames)
        let decision: ProxyDestinationDecision
        let approvalSource: String
        if session.rules.contains(rule) {
            decision = .allowForSession
            approvalSource = "Session"
        } else {
            await acquireDestinationPrompt()
            defer { releaseDestinationPrompt() }
            if !cancellation.isCanceled,
               refreshTargetIdentity(id: sessionID),
               let current = sessions[sessionID] {
                session = current
                if current.rules.contains(rule) {
                    decision = .allowForSession
                    approvalSource = "Session"
                } else {
                    decision = await current.approveDestination(
                        ProxyDestinationRequest(
                            sessionID: sessionID,
                            target: current.launch.target,
                            cwd: current.launch.cwd,
                            method: method,
                            origin: origin,
                            path: path,
                            queryNames: queryNames,
                            secretNames: sortedNames,
                            selectedSecretValues: current.launch.selectedSecretValues.selecting(
                                names: sortedNames
                            )
                        ),
                        cancellation
                    )
                    approvalSource = "Manual"
                }
            } else {
                decision = .deny
                approvalSource = "Expired"
            }
        }
        guard !cancellation.isCanceled else { return }
        guard decision != .deny else {
            _ = appendAccessRequestRecord(proxyRecord(
                session: session,
                method: method,
                origin: origin,
                path: path,
                queryNames: queryNames,
                secretNames: sortedNames,
                decision: "Denied",
                approvalSource: approvalSource,
                reason: "Destination denied"
            ))
            deny(sessionID: sessionID, requestID: requestID, reason: "destination denied")
            return
        }
        guard refreshTargetIdentity(id: sessionID),
              let current = sessions[sessionID],
              !cancellation.isCanceled
        else {
            deny(sessionID: sessionID, requestID: requestID, reason: "Proxy Session expired during approval")
            return
        }
        session = current
        guard !cancellation.isCanceled else { return }
        let secrets: [String: String]
        do {
            secrets = try session.secretValueCustody.load(
                session.launch.selectedSecretValues,
                names: sortedNames
            )
        } catch {
            _ = appendAccessRequestRecord(proxyRecord(
                session: session,
                method: method,
                origin: origin,
                path: path,
                queryNames: queryNames,
                secretNames: sortedNames,
                decision: "Failed",
                approvalSource: approvalSource,
                reason: error.localizedDescription
            ))
            deny(sessionID: sessionID, requestID: requestID, reason: error.localizedDescription)
            return
        }
        guard refreshTargetIdentity(id: sessionID),
              var liveSession = sessions[sessionID],
              !cancellation.isCanceled
        else {
            deny(sessionID: sessionID, requestID: requestID, reason: "Proxy Session expired before release")
            return
        }
        let record = proxyRecord(
            session: liveSession,
            method: method,
            origin: origin,
            path: path,
            queryNames: queryNames,
            secretNames: sortedNames,
            decision: "Approved",
            approvalSource: approvalSource,
            reason: decision == .allowForSession ? "Allowed for Proxy Session" : "Allowed once"
        )
        guard appendAccessRequestRecord(record) else {
            deny(sessionID: sessionID, requestID: requestID, reason: "Authorization History is unavailable")
            return
        }
        guard !cancellation.isCanceled else { return }
        if decision == .allowForSession { liveSession.rules.insert(rule) }
        liveSession.authorizedRequestCount += 1
        liveSession.authorizedOrigins.insert(origin)
        sessions[sessionID] = liveSession
        publishSessions()
        do {
            try writeFrame([
                "type": "authorization",
                "request_id": requestID,
                "allowed": true,
                "secrets": secrets,
            ], to: liveSession.input)
        } catch {
            terminate(id: sessionID)
        }
    }

    private func deny(sessionID: UUID, requestID: UInt64, reason: String) {
        guard let session = sessions[sessionID] else { return }
        do {
            try writeFrame([
                "type": "authorization",
                "request_id": requestID,
                "allowed": false,
                "reason": reason,
            ], to: session.input)
        } catch {
            terminate(id: sessionID)
        }
    }

    private func acquireDestinationPrompt() async {
        if !destinationPromptActive {
            destinationPromptActive = true
            return
        }
        await withCheckedContinuation { continuation in
            destinationPromptWaiters.append(continuation)
        }
    }

    private func releaseDestinationPrompt() {
        if destinationPromptWaiters.isEmpty {
            destinationPromptActive = false
        } else {
            destinationPromptWaiters.removeFirst().resume()
        }
    }

    private func proxyRecord(
        session: Session,
        method: String,
        origin: String,
        path: String,
        queryNames: [String],
        secretNames: [String],
        decision: String,
        approvalSource: String,
        reason: String
    ) -> AccessRequestRecord {
        let query = queryNames.isEmpty ? "" : "?" + queryNames.sorted().map { "\($0)=…" }.joined(separator: "&")
        return AccessRequestRecord(
            date: Date(),
            tool: "Secret Proxy",
            command: "\(method) \(origin)\(path)\(query)",
            displayCommand: "\(method) \(origin)\(path)\(query)",
            decision: decision,
            approvalSource: approvalSource,
            reason: reason,
            launcher: URL(fileURLWithPath: session.launch.target).lastPathComponent,
            callerPath: session.launch.target,
            target: origin,
            cwd: session.launch.cwd,
            keys: secretNames,
            detail: "Proxy Session \(session.id.uuidString.lowercased())",
            secretValueSources: session.launch.selectedSecretValues
                .selecting(names: secretNames)
                .sourceDisplayNames
        )
    }

    private func publishSessions() {
        let summaries = sessions.values.map {
            ProxySessionSummary(
                id: $0.id,
                startedAt: $0.startedAt,
                target: $0.launch.target,
                pid: $0.launch.identity.pid,
                secretNames: $0.launch.keys,
                authorizedRequestCount: $0.authorizedRequestCount,
                authorizedOrigins: $0.authorizedOrigins.sorted()
            )
        }.sorted { $0.startedAt > $1.startedAt }
        Task { @MainActor in ProxySessionViewModel.shared.update(summaries) }
    }

    private func validOrigin(_ origin: String) -> Bool {
        guard let components = URLComponents(string: origin),
              components.scheme == "http" || components.scheme == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.path.isEmpty, components.query == nil, components.fragment == nil
        else { return false }
        return origin == components.string
    }

    private func targetIsLive(_ expected: ProxyTargetIdentity) -> Bool {
        var current = AVProcessIdentity()
        return av_process_identity(expected.pid, &current)
            && current.pidversion == expected.pidVersion
            && current.start_usec == expected.startUsec
            && current.euid == expected.effectiveUserID
            && current.audit_session_id == expected.auditSessionID
    }

    private func processPath(_ identity: AVProcessIdentity) -> String {
        withUnsafeBytes(of: identity.path) { bytes in
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
    }

    private func liveCodeIdentity(pid: pid_t) -> Data? {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess
        else { return nil }
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
              let dictionary = info as? [CFString: Any]
        else { return nil }
        return dictionary[kSecCodeInfoUnique] as? Data
    }

    private func verifiedHelperURL() throws -> URL {
        guard let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() else {
            throw SecretProxyError("Automic Vault bundle path is unavailable")
        }
        let helper = executableDirectory.appendingPathComponent("av-proxy-helper", isDirectory: false)
        guard FileManager.default.isExecutableFile(atPath: helper.path),
              helper.deletingLastPathComponent().standardizedFileURL == executableDirectory.standardizedFileURL,
              helperHasExpectedSignature(helper)
        else {
            throw SecretProxyError("Proxy helper failed code-signing verification")
        }
        return helper
    }

    private func helperHasExpectedSignature(_ url: URL) -> Bool {
        guard let teamID = selfTeamID() else { return false }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code
        else { return false }
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"com.automicvault.av-proxy-helper\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement
        else { return false }
        guard SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess,
              helperHasRequiredRuntime(code)
        else { return false }
        return true
    }

    private func runningHelperHasExpectedSignature(pid: pid_t) -> Bool {
        guard let teamID = selfTeamID() else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code
        else { return false }
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"com.automicvault.av-proxy-helper\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement
        else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    private func helperHasRequiredRuntime(_ code: SecStaticCode) -> Bool {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        ) == errSecSuccess,
        let dictionary = info as? [CFString: Any],
        let flags = dictionary[kSecCodeInfoFlags] as? NSNumber,
        flags.uint32Value & 0x0001_0000 != 0,
        let entitlements = dictionary[kSecCodeInfoEntitlementsDict] as? [String: Any],
        entitlements["com.apple.security.app-sandbox"] as? Bool == true,
        entitlements["com.apple.security.network.client"] as? Bool == true,
        entitlements["com.apple.security.network.server"] as? Bool == true
        else { return false }
        let prohibited = [
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.debugger",
        ]
        return entitlements["keychain-access-groups"] == nil
            && prohibited.allSatisfy { entitlements[$0] as? Bool != true }
    }

    private func selfTeamID() -> String? {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &info
              ) == errSecSuccess,
              let dictionary = info as? [CFString: Any]
        else { return nil }
        return dictionary[kSecCodeInfoTeamIdentifier] as? String
    }

    private func randomToken(prefix: String, byteCount: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SecretProxyError("Secure random generation failed")
        }
        return prefix + Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func writeSessionCertificate(_ pem: String, sessionID: UUID) throws -> (URL, URL) {
        let prefix = FileManager.default.temporaryDirectory
            .appendingPathComponent("com.automicvault.proxy.\(sessionID.uuidString.lowercased()).XXXXXX")
            .path
        var template = Array(prefix.utf8CString)
        guard mkdtemp(&template) != nil else {
            throw SecretProxyError("Could not create a private Proxy Session directory")
        }
        let end = template.firstIndex(of: 0) ?? template.endIndex
        let directoryPath = String(
            decoding: template[..<end].map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
        let directory = URL(fileURLWithPath: directoryPath, isDirectory: true)
        let certificate = directory.appendingPathComponent("ca.pem", isDirectory: false)
        try Data(pem.utf8).write(to: certificate, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: certificate.path)
        return (directory, certificate)
    }

    private func writeFrame(_ object: [String: Any], to handle: FileHandle) throws {
        let payload = try JSONSerialization.data(withJSONObject: object)
        guard !payload.isEmpty, payload.count <= maximumControlFrame else {
            throw SecretProxyError("Control frame is too large")
        }
        var length = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        frame.append(payload)
        try handle.write(contentsOf: frame)
    }

    private func readFrame(from handle: FileHandle, timeout: Duration) async throws -> [String: Any] {
        let timeoutMilliseconds = Int32(clamping: timeout.components.seconds * 1_000)
        let payload = try await Task.detached {
            guard let payload = try Self.readFramePayloadSynchronously(
                    from: handle,
                    maximumLength: 4 * 1024 * 1024,
                    timeoutMilliseconds: timeoutMilliseconds
            ) else { throw SecretProxyError("Proxy helper closed its control channel") }
            return payload
        }.value
        return try decodeFrame(payload)
    }

    private func decodeFrame(_ payload: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            throw SecretProxyError("Control frame is not a JSON object")
        }
        return object
    }

    nonisolated private static func readFramePayloadSynchronously(
        from handle: FileHandle,
        maximumLength: Int,
        timeoutMilliseconds: Int32?
    ) throws -> Data? {
        let deadline = timeoutMilliseconds.map {
            DispatchTime.now().uptimeNanoseconds + UInt64(max(0, $0)) * 1_000_000
        }
        guard let lengthData = try readExact(4, from: handle, deadline: deadline) else { return nil }
        let length = lengthData.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= maximumLength else {
            throw SecretProxyError("Control frame has an invalid length")
        }
        guard let payload = try readExact(Int(length), from: handle, deadline: deadline) else {
            throw SecretProxyError("Control frame ended unexpectedly")
        }
        return payload
    }

    nonisolated private static func readExact(
        _ count: Int,
        from handle: FileHandle,
        deadline: UInt64?
    ) throws -> Data? {
        var data = Data()
        while data.count < count {
            if let deadline {
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else { throw SecretProxyError("Proxy helper timed out") }
                let remaining = min((deadline - now) / 1_000_000, UInt64(Int32.max))
                var descriptor = pollfd(
                    fd: handle.fileDescriptor,
                    events: Int16(POLLIN | POLLHUP),
                    revents: 0
                )
                let result = Darwin.poll(&descriptor, 1, Int32(max(1, remaining)))
                if result == 0 { throw SecretProxyError("Proxy helper timed out") }
                if result < 0 {
                    if errno == EINTR { continue }
                    throw SecretProxyError("Proxy helper control channel failed")
                }
            }
            guard let chunk = try handle.read(upToCount: count - data.count), !chunk.isEmpty else {
                return data.isEmpty ? nil : data
            }
            data.append(chunk)
        }
        return data
    }
}

func proxyExecutableCodeIdentity(path: String) -> Data? {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
          let code,
          SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess
    else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
          let dictionary = info as? [CFString: Any]
    else { return nil }
    return dictionary[kSecCodeInfoUnique] as? Data
}

private struct SecretProxyError: LocalizedError {
    let message: String

    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
