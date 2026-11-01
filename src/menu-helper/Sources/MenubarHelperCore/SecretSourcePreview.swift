import Foundation

/// Metadata only: this type cannot hold Secret bytes or Keychain account identifiers.
public struct SecretSourcePreview: Encodable, Equatable, Sendable {
    public let name: String
    public let source: String
    public let projectDirectory: String?
}

public func secretSourcePreview(secrets: [StoredSecret], cwd: String) throws -> [SecretSourcePreview] {
    let selected = try resolveStoredSecretValues(names: secrets.map(\.account), cwd: cwd, secrets: secrets)
    return secrets.sorted { $0.account < $1.account }.map { secret in
        switch selected[secret.account]?.source {
        case .global:
            SecretSourcePreview(name: secret.account, source: "global", projectDirectory: nil)
        case .projectDirectory(let path):
            SecretSourcePreview(name: secret.account, source: "project", projectDirectory: path)
        case nil:
            SecretSourcePreview(name: secret.account, source: "missing", projectDirectory: nil)
        }
    }
}
