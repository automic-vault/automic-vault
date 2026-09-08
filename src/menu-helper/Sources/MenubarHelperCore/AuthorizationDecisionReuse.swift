import CryptoKit
import Foundation

public struct AuthorizationClientExecution: Hashable, Sendable {
    public let pid: Int32
    public let pidVersion: Int32
    public let startUsec: UInt64
    public let effectiveUserID: UInt32
    public let auditSessionID: UInt32

    public init(
        pid: Int32,
        pidVersion: Int32,
        startUsec: UInt64,
        effectiveUserID: UInt32,
        auditSessionID: UInt32
    ) {
        self.pid = pid
        self.pidVersion = pidVersion
        self.startUsec = startUsec
        self.effectiveUserID = effectiveUserID
        self.auditSessionID = auditSessionID
    }
}

public struct AuthorizationCredentialHelperParent: Hashable, Sendable {
    public let pid: Int32
    public let startUsec: UInt64
    public let effectiveUserID: UInt32
    public let target: String
    public let arguments: [String]

    public init(
        pid: Int32,
        startUsec: UInt64,
        effectiveUserID: UInt32,
        target: String,
        arguments: [String]
    ) {
        self.pid = pid
        self.startUsec = startUsec
        self.effectiveUserID = effectiveUserID
        self.target = target
        self.arguments = arguments
    }
}

public enum AuthorizationDecisionReusePolicy: Hashable, Sendable {
    case reusable
    case freshApprovalRequired
    case disabled
}

public enum AuthorizationDecisionReuseOutcome: Equatable, Sendable {
    case canceled
    case interrupted
    case denied
    case approved
    case alwaysApproved
    case temporaryAccessGrant
}

public struct AuthorizationDecisionReuseRequest: Hashable, Sendable {
    fileprivate let client: AuthorizationClientExecution
    fileprivate let policy: AuthorizationDecisionReusePolicy

    private let callerPath: String
    private let signingIdentifier: String
    private let signingTeamIdentifier: String
    private let operation: String
    private let secretNames: [String]
    private let target: String
    private let arguments: [String]
    private let workingDirectory: String
    private let replaceExistingEnvironment: Bool
    private let allowMissingSecrets: Bool
    private let environmentConflicts: [String]
    private let shebangScript: String?
    private let scriptDataSHA256: Data?
    private let snapshotIncompatibleInterpreter: String?
    private let tool: String?
    private let title: String?
    private let detail: String?
    private let credentialScope: String?
    private let credentialParent: AuthorizationCredentialHelperParent?
    private let selectedValueSources: [SelectedSecretValueSourceIdentity]

    public init(
        client: AuthorizationClientExecution,
        callerPath: String,
        signingIdentifier: String,
        signingTeamIdentifier: String,
        operation: String,
        secretNames: [String],
        target: String,
        arguments: [String],
        workingDirectory: String,
        replaceExistingEnvironment: Bool,
        allowMissingSecrets: Bool,
        environmentConflicts: [String],
        shebangScript: String?,
        scriptData: Data?,
        snapshotIncompatibleInterpreter: String?,
        tool: String?,
        title: String?,
        detail: String?,
        credentialScope: String?,
        credentialParent: AuthorizationCredentialHelperParent?,
        selectedSecretValues: SelectedSecretValues,
        policy: AuthorizationDecisionReusePolicy
    ) {
        self.client = client
        self.callerPath = callerPath
        self.signingIdentifier = signingIdentifier
        self.signingTeamIdentifier = signingTeamIdentifier
        self.operation = operation
        self.secretNames = Array(Set(secretNames)).sorted()
        self.target = target
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.replaceExistingEnvironment = replaceExistingEnvironment
        self.allowMissingSecrets = allowMissingSecrets
        self.environmentConflicts = Array(Set(environmentConflicts)).sorted()
        self.shebangScript = shebangScript
        self.scriptDataSHA256 = scriptData.map { Data(SHA256.hash(data: $0)) }
        self.snapshotIncompatibleInterpreter = snapshotIncompatibleInterpreter
        self.tool = tool
        self.title = title
        self.detail = detail
        self.credentialScope = credentialScope
        self.credentialParent = credentialParent
        self.selectedValueSources = selectedSecretValues.authorizationIdentity()
        self.policy = policy
    }
}

public struct AuthorizationDecisionReuseCache: Sendable {
    private enum Key: Hashable, Sendable {
        case approval(AuthorizationDecisionReuseRequest)
        case denial(AuthorizationClientExecution)
    }

    private let ttl: TimeInterval
    private var expirations: [Key: Date] = [:]

    public init(ttl: TimeInterval = 5 * 60) {
        precondition(ttl > 0)
        self.ttl = ttl
    }

    public mutating func decision(
        for request: AuthorizationDecisionReuseRequest,
        now: Date = Date()
    ) -> AuthorizationDecisionReuseOutcome? {
        prune(now: now)
        guard request.policy != .disabled else { return nil }
        if expirations[.denial(request.client)] != nil { return .denied }
        guard request.policy == .reusable else { return nil }
        return expirations[.approval(request)] == nil ? nil : .approved
    }

    public mutating func remember(
        _ outcome: AuthorizationDecisionReuseOutcome,
        for request: AuthorizationDecisionReuseRequest,
        now: Date = Date()
    ) {
        prune(now: now)
        guard request.policy != .disabled else { return }
        let key: Key
        switch outcome {
        case .canceled, .interrupted, .temporaryAccessGrant:
            return
        case .denied:
            key = .denial(request.client)
        case .approved, .alwaysApproved:
            guard request.policy == .reusable else { return }
            key = .approval(request)
        }
        expirations[key] = now.addingTimeInterval(ttl)
    }

    private mutating func prune(now: Date) {
        expirations = expirations.filter { $0.value > now }
    }
}
