import Foundation
import XPC

private let approvalService = "com.automicvault.av2.approval"
private let maximumSecretNames = 64
private let varlockProtocolVersion: UInt64 = 1
private let menuHelperRequirement = """
anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and \
identifier "com.automicvault"
"""

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("Automic Vault Varlock plugin: \(message)\n".utf8))
    exit(1)
}

private func canonicalWorkingDirectory() -> String? {
    var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard realpath(FileManager.default.currentDirectoryPath, &resolved) != nil else { return nil }
    return resolved.withUnsafeBytes { bytes in
        String(bytes: bytes.prefix { $0 != 0 }, encoding: .utf8)
    }
}

if CommandLine.arguments.dropFirst().elementsEqual(["--protocol-version"]) {
    print(varlockProtocolVersion)
    exit(0)
}

#if DEBUG
if CommandLine.arguments.dropFirst().elementsEqual(["--test-canonical-working-directory"]) {
    guard let cwd = canonicalWorkingDirectory() else { fail("working directory is unavailable") }
    print(cwd)
    exit(0)
}
#endif

guard 4...(maximumSecretNames + 3) ~= CommandLine.arguments.count else {
    fail("expected a protocol version, schema digest, and between 1 and \(maximumSecretNames) Secret Names")
}
guard UInt64(CommandLine.arguments[1]) == varlockProtocolVersion else {
    fail("unsupported Varlock protocol version")
}
let schemaDigest = CommandLine.arguments[2]
guard schemaDigest.utf8.count == 64,
      schemaDigest.utf8.allSatisfy({ 48...57 ~= $0 || 97...102 ~= $0 })
else { fail("invalid Varlock schema digest") }

let secretNames = Array(CommandLine.arguments.dropFirst(3)).sorted()
guard Set(secretNames).count == secretNames.count,
      secretNames.allSatisfy({ name in
          let bytes = Array(name.utf8)
          guard let first = bytes.first,
                first == 95 || 65...90 ~= first || 97...122 ~= first
          else { return false }
          return bytes.dropFirst().allSatisfy({
              $0 == 95 || 48...57 ~= $0 || 65...90 ~= $0 || 97...122 ~= $0
          })
      })
else {
    fail("invalid Secret Name")
}
guard let cwd = canonicalWorkingDirectory() else { fail("working directory is unavailable") }

let connection = xpc_connection_create_mach_service(approvalService, nil, 0)
guard xpc_connection_set_peer_code_signing_requirement(
    connection, menuHelperRequirement
) == 0 else {
    fail("could not verify Automic Vault")
}
xpc_connection_set_event_handler(connection) { _ in }
xpc_connection_activate(connection)
defer { xpc_connection_cancel(connection) }

let request = xpc_dictionary_create_empty()
xpc_dictionary_set_string(request, "op", "varlock")
xpc_dictionary_set_uint64(request, "protocol_version", varlockProtocolVersion)
xpc_dictionary_set_string(request, "schema_sha256", schemaDigest)
let keys = xpc_array_create_empty()
for name in secretNames {
    name.withCString { xpc_array_set_string(keys, XPC_ARRAY_APPEND, $0) }
}
xpc_dictionary_set_value(request, "keys", keys)
xpc_dictionary_set_string(request, "cwd", cwd)

let reply = xpc_connection_send_message_with_reply_sync(connection, request)
if xpc_get_type(reply) == XPC_TYPE_ERROR {
    let error = xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION)
        .map(String.init(cString:)) ?? "XPC connection failed"
    fail(error)
}
guard xpc_dictionary_get_bool(reply, "ok") else {
    let error = xpc_dictionary_get_string(reply, "error")
        .map(String.init(cString:)) ?? "request denied"
    fail(error)
}
guard xpc_dictionary_get_uint64(reply, "protocol_version") == varlockProtocolVersion else {
    fail("Automic Vault returned an incompatible Varlock protocol response")
}
guard let values = xpc_dictionary_get_value(reply, "secrets"),
      xpc_get_type(values) == XPC_TYPE_DICTIONARY
else {
    fail("Automic Vault returned no Secret Values")
}
var secrets: [String: String] = [:]
for name in secretNames {
    guard let value = xpc_dictionary_get_string(values, name) else {
        fail("Automic Vault returned no value for \(name)")
    }
    secrets[name] = String(cString: value)
}
guard let output = try? JSONSerialization.data(withJSONObject: secrets, options: [.sortedKeys]) else {
    fail("could not encode Secret Values")
}
FileHandle.standardOutput.write(output)
