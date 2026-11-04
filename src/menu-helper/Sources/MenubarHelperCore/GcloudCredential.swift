import Foundation

public func isGcloudCredentialKey(_ key: String) -> Bool {
    let prefix = "GCLOUD_AUTH_"
    guard key.hasPrefix(prefix), key.utf8.count <= 492 else { return false }
    let encoded = Array(key.dropFirst(prefix.count).utf8)
    guard !encoded.isEmpty, encoded.count.isMultiple(of: 2),
          encoded.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) }) else { return false }
    let bytes = stride(from: 0, to: encoded.count, by: 2).map {
        UInt8(String(decoding: encoded[$0...($0 + 1)], as: UTF8.self), radix: 16)!
    }
    guard let account = String(bytes: bytes, encoding: .utf8) else { return false }
    return !account.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
}

public func gcloudCredentialSelectionIsSupported(_ selected: SelectedSecretValues) -> Bool {
    selected.names.allSatisfy { isGcloudCredentialKey($0) && selected.source(for: $0) == .global }
}

public func gcloudCredentialIsSupported(_ value: String) -> Bool {
    guard value.utf8.count <= 1024 * 1024,
          let object = try? JSONSerialization.jsonObject(with: Data(value.utf8)),
          let fields = object as? [String: Any], fields["type"] as? String == "authorized_user",
          fields["universe_domain"] as? String == "googleapis.com",
          let tokenURI = fields["token_uri"] as? String,
          ["https://oauth2.googleapis.com/token", "https://accounts.google.com/o/oauth2/token"].contains(tokenURI),
          fields["revoke_uri"] as? String == "https://oauth2.googleapis.com/revoke",
          Set(fields.keys).isSubset(of: ["type", "client_id", "client_secret", "refresh_token", "revoke_uri", "scopes", "token_uri", "rapt_token", "universe_domain"])
    else { return false }
    return ["client_id", "client_secret", "refresh_token"].allSatisfy {
        guard let text = fields[$0] as? String else { return false }
        return !text.isEmpty && !text.contains("\0")
    }
}

/// A stale login/refresh/logout cannot replace a newer credential.
public func gcloudCredentialMatchesExpected(current: String?, expected: String?) -> Bool {
    current == expected
}
