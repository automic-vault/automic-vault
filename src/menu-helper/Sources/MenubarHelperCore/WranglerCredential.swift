/// Wrangler profile names are encoded without case or punctuation collisions.
public func isWranglerCredentialKey(_ key: String) -> Bool {
    let prefix = "WRANGLER_AUTH_"
    guard key.hasPrefix(prefix), key.utf8.count <= 512 else { return false }
    let encoded = key.dropFirst(prefix.count)
    return !encoded.isEmpty && encoded.utf8.count.isMultiple(of: 2)
        && encoded.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) }
}
