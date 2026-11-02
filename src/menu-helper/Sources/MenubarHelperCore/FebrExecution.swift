import Darwin
import Foundation

/// Root enrollment authenticates one local build; it is not Launcher authority.
public struct FebrEnrollment: Codable, Equatable, Sendable {
    public static let executable = "/opt/febr/libexec/febr"
    public static let identifier = "dev.mxcl.febr"
    public let protocolVersion: Int
    public let cdhash: String
    public let uid: UInt32
    public let gid: UInt32

    public var isValid: Bool {
        protocolVersion == 1 && uid >= 200 && gid >= 200 && cdhash.count == 40
            && cdhash.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public var requirement: String { "identifier \"\(Self.identifier)\" and cdhash H\"\(cdhash)\"" }

    public static func load() -> Self? {
        for path in ["/opt", "/opt/febr", "/opt/febr/libexec"] {
            var status = stat()
            guard lstat(path, &status) == 0, status.st_mode & S_IFMT == S_IFDIR,
                  status.st_uid == 0, status.st_mode & 0o022 == 0, access(path, W_OK) != 0 else { return nil }
        }
        let fd = open("/opt/febr/libexec/av-client.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var status = stat()
        guard fstat(fd, &status) == 0, status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == 0, status.st_mode & 0o022 == 0,
              status.st_size > 0, status.st_size <= 4096,
              access("/opt/febr/libexec/av-client.json", W_OK) != 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(status.st_size))
        guard read(fd, &bytes, bytes.count) == bytes.count,
              let enrollment = try? JSONDecoder().decode(Self.self, from: Data(bytes)), enrollment.isValid else { return nil }
        var user = passwd()
        var userResult: UnsafeMutablePointer<passwd>?
        var userBuffer = [CChar](repeating: 0, count: 16384)
        var group = Darwin.group()
        var groupResult: UnsafeMutablePointer<Darwin.group>?
        var groupBuffer = [CChar](repeating: 0, count: 16384)
        guard getpwnam_r("irnbru", &user, &userBuffer, userBuffer.count, &userResult) == 0,
              userResult != nil, user.pw_uid == enrollment.uid, user.pw_gid == enrollment.gid,
              getgrnam_r("irnbru", &group, &groupBuffer, groupBuffer.count, &groupResult) == 0,
              groupResult != nil, group.gr_gid == enrollment.gid else { return nil }
        var binary = stat()
        guard lstat(executable, &binary) == 0, binary.st_mode & S_IFMT == S_IFREG,
              binary.st_uid == enrollment.uid, binary.st_gid == enrollment.gid,
              binary.st_mode & 0o7777 == 0o6555, access(executable, W_OK) != 0 else { return nil }
        return enrollment
    }
}

public enum FebrOperation: String, Sendable {
    case systemWrite, localWrite
    public var detail: String {
        switch self {
        case .systemWrite: "This operation changes protected packages shared by this Mac's users."
        case .localWrite: "This operation changes services running under your user account."
        }
    }
}

/// Exact positive command catalog. Unknown syntax never reaches Approval.
public func febrOperation(_ args: [String]) -> FebrOperation? {
    guard let command = args.first, args.count <= 2048,
          args.allSatisfy({ $0.utf8.count <= 1024 }) else { return nil }
    func name(_ value: String) -> Bool {
        guard let first = value.utf8.first,
              (97...122).contains(first) || (48...57).contains(first), !value.contains("..") else { return false }
        return value.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || [43,45,46,64,95].contains($0) }
    }
    switch command {
    case "install", "uninstall": return args.count > 1 && args.dropFirst().allSatisfy(name) ? .systemWrite : nil
    case "upgrade": return args.dropFirst().allSatisfy(name) ? .systemWrite : nil
    case "services":
        if args == ["services", "cleanup"] { return .localWrite }
        guard args.count == 3 else { return nil }
        if args[1] == "upgrade" { return name(args[2]) ? .systemWrite : nil }
        return ["start", "stop", "restart", "run"].contains(args[1]) && (name(args[2]) || args[2] == "--all") ? .localWrite : nil
    default: return nil
    }
}
