import Foundation
import Security

/// Validates a fresh live process and binds its signed identity to the selected file.
/// The caller must bind the process execution across this call and subsequent use.
public func liveExecutableCodeIdentity(pid: pid_t, executableURL: URL) -> Data? {
    var live: SecCode?
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &live) == errSecSuccess,
          let live,
          SecCodeCheckValidity(live, [], nil) == errSecSuccess
    else { return nil }

    var liveStatic: SecStaticCode?
    var liveInfo: CFDictionary?
    guard SecCodeCopyStaticCode(live, [], &liveStatic) == errSecSuccess,
          let liveStatic,
          SecCodeCopySigningInformation(liveStatic, [], &liveInfo) == errSecSuccess,
          let liveHash = (liveInfo as? [CFString: Any])?[kSecCodeInfoUnique] as? Data
    else { return nil }

    var disk: SecStaticCode?
    var diskInfo: CFDictionary?
    guard SecStaticCodeCreateWithPath(executableURL as CFURL, [], &disk) == errSecSuccess,
          let disk,
          SecCodeCopySigningInformation(disk, [], &diskInfo) == errSecSuccess,
          let diskHash = (diskInfo as? [CFString: Any])?[kSecCodeInfoUnique] as? Data,
          diskHash == liveHash
    else { return nil }
    // Disk metadata grants no authority: its hash must match the validated live code.
    // macOS enforces mapped-page integrity; this does not verify every byte on disk.
    return liveHash
}
