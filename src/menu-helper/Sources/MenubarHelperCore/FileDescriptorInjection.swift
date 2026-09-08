/// Canonical mapping text is bound into the request, phone Approval digest,
/// decision-reuse identity, and persisted Authorization Record detail.
public func fileDescriptorInjectionDetail(keys: [String], mappings: [String]) -> String? {
    guard !keys.isEmpty, Set(keys).count == keys.count, mappings.count == keys.count else { return nil }
    var names = Set<String>()
    var descriptors = Set<Int32>()
    var pairs: [String: Int32] = [:]
    for mapping in mappings {
        let parts = mapping.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let first = parts[0].utf8.first,
              first == 95 || (65...90).contains(first) || (97...122).contains(first),
              parts[0].utf8.allSatisfy({
                  $0 == 95 || (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
              }),
              let fd = Int32(parts[1]), fd >= 3, fd < Int32.max,
              String(fd) == parts[1],
              names.insert(String(parts[0])).inserted,
              descriptors.insert(fd).inserted
        else { return nil }
        pairs[String(parts[0])] = fd
    }
    guard names == Set(keys) else { return nil }
    return "Anonymous pipes: " + pairs.sorted { $0.key < $1.key }.map { "\($0.key) → FD \($0.value)" }.joined(separator: ", ")
        + ". Exact stored bytes, then EOF. Requested Secret Names are removed from the Target's environment."
}
