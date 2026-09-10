import Foundation
import Darwin

public func gitTransportPathHasNoACL(_ path: String) -> Bool {
    // On Darwin, ENOENT also means an existing file has no extended ACL.
    // Callers separately require the path's protected lstat metadata.
    guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return errno == ENOENT }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    return acl_valid(acl) == 0 && acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1 && errno == EINVAL
}

public let gitTransportRoot = "/opt/av/git"
public let gitTransportBinary = "/opt/av/git/bin/git"
public let gitTransportHTTPS = "/opt/av/git/bin/git-remote-https"
public let gitTransportGH = "/opt/av/git/bin/gh"
public let gitTransportRepository = "/opt/av/git/repository"
public let gitTransportConfig = "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"

/// Positive command surface shared with src/git_transport.rs. No user Git flags.
public struct GitTransportOperation: Sendable, Equatable {
    public let command: String
    public let url: String
    public let remotePlan: GitRemotePlan?

    public init?(_ arguments: [String]) {
        if arguments.first == "remote-helper" {
            guard let plan = GitRemotePlan(arguments) else { return nil }
            self.remotePlan = plan
            self.url = plan.url
            self.command = plan.phase == "push" || plan.phase == "list for-push" ? "push" : "fetch"
            return
        }
        self.remotePlan = nil
        guard arguments.count >= 2 else { return nil }
        let command = arguments[0], url = arguments[1]
        guard ["clone", "fetch", "pull", "push"].contains(command),
              arguments.count == (command == "clone" ? 3 : 2),
              arguments.allSatisfy({ !$0.isEmpty && !$0.contains("\0") }),
              url.hasPrefix("https://github.com/"), url.hasSuffix(".git") else { return nil }
        let parts = url.dropFirst("https://github.com/".count).dropLast(4).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, parts.allSatisfy({ part in
            !part.isEmpty && part != "." && part != ".." && part.utf8.allSatisfy {
                (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 95, 46].contains($0)
            }
        }) else { return nil }
        self.command = command
        self.url = url
    }

    public var classification: SecretGateRequestClassification { command == "push" ? .mutating : .localWrite }

    public func arguments(phase: String, oid: String) -> [String]? {
        if let plan = remotePlan {
            guard phase == "remote-helper", oid.isEmpty else { return nil }
            return Self.configuration + ["-c", "protocol.version=0", "remote-https", plan.url, plan.url]
        }
        let tail: [String]
        switch phase {
        case "advertise" where command != "push" && oid.isEmpty:
            tail = ["ls-remote", "--exit-code", "--refs", "--", url, "refs/heads/main"]
        case "fetch" where command != "push" && Self.validOID(oid):
            tail = ["fetch", "--no-auto-maintenance", "--no-write-fetch-head", "--no-write-commit-graph",
                    "--no-tags", "--no-recurse-submodules", "--", url, oid]
        case "push" where command == "push" && Self.validOID(oid):
            tail = ["push", "--no-verify", "--", url, "\(oid):refs/heads/main"]
        default: return nil
        }
        return Self.configuration + tail
    }

    private static var configuration: [String] {
        let config = [
            "credential.helper=", "credential.helper=!exec /opt/av/git/bin/gh auth git-credential",
            "credential.useHttpPath=true", "core.hooksPath=/dev/null", "core.fsmonitor=false",
            "http.sslBackend=openssl", "http.sslVerify=true", "http.sslCAInfo=/private/etc/ssl/cert.pem",
            "http.sslCAPath=/opt/av/git/empty", "http.followRedirects=false", "http.proxy=",
            "protocol.allow=never", "protocol.https.allow=always",
        ]
        return ["--no-replace-objects"] + config.flatMap { ["-c", $0] }
    }

    public static func validOID(_ value: String) -> Bool {
        value.utf8.count == 40 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

public func gitTransportEnvironment(objects: String, nonce: String) -> [String: String] {
    ["PATH": "/opt/av/git/bin:/usr/bin:/bin", "HOME": "/opt/av/git/empty",
     "XDG_CONFIG_HOME": "/opt/av/git/empty", "GH_CONFIG_DIR": "/opt/av/git/empty",
     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
     "GIT_EXEC_PATH": "/opt/av/git/bin", "GIT_DIR": gitTransportRepository,
     "GIT_OBJECT_DIRECTORY": objects, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat",
     "LC_ALL": "C", "AV_GIT_NONCE": nonce]
}

/// Wire schema mirrors RemotePlan in src/git_transport.rs. Every accepted field
/// determines the sole request supplied to a fresh credential-bearing process.
public struct GitRemotePlan: Sendable, Equatable {
    public let wire: [String]
    public let url: String
    public let phase: String

    public init?(_ args: [String]) {
        guard args.count >= 5, args.count <= 4106, args[0] == "remote-helper",
              args.reduce(0, { $0 + $1.utf8.count }) <= 1024 * 1024 + 16_384,
              args.allSatisfy({ $0.utf8.count <= 8192 && !$0.contains("\n") && !$0.contains("\r") && !$0.contains("\0") }),
              GitTransportOperation(["fetch", args[1]]) != nil,
              let separator = args[3...].firstIndex(of: "") else { return nil }
        var previous = ""
        for option in args[3..<separator] {
            let parts = option.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 3, parts[0] == "option", parts[1] > previous,
                  Self.validOption(parts[1], parts[2]) else { return nil }
            previous = parts[1]
        }
        let commands = Array(args.dropFirst(separator + 1))
        guard !commands.isEmpty, commands.count <= 4096,
              commands.reduce(0, { $0 + $1.utf8.count }) <= 1024 * 1024 else { return nil }
        switch args[2] {
        case "list", "list for-push":
            guard commands == [args[2]] else { return nil }
        case "fetch":
            guard commands.allSatisfy({ line in
                let p = line.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
                return p.count == 3 && p[0] == "fetch" && GitTransportOperation.validOID(p[1]) && (p[2] == "HEAD" || Self.validBranch(p[2]))
            }) else { return nil }
        case "push":
            guard commands.allSatisfy({ line in
                guard line.hasPrefix("push ") else { return false }
                let p = line.dropFirst(5).split(separator: ":", omittingEmptySubsequences: false).map(String.init)
                return p.count == 2 && GitTransportOperation.validOID(p[0]) && Self.validBranch(p[1])
            }) else { return nil }
        default: return nil
        }
        wire = args; url = args[1]; phase = args[2]
    }

    public static func validOption(_ key: String, _ value: String) -> Bool {
        switch key {
        case "progress", "cloning", "followtags", "check-connectivity", "dry-run": return ["true", "false"].contains(value)
        case "verbosity": return ["0", "1", "2", "3"].contains(value)
        default: return false
        }
    }

    public static func validBranch(_ value: String) -> Bool {
        value.hasPrefix("refs/heads/") && value.utf8.count <= 4096 && !value.contains("..")
            && value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [95,46,47,45].contains($0) }
            && value.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
                !$0.isEmpty && !$0.hasPrefix(".") && !$0.hasSuffix(".") && !$0.hasSuffix(".lock")
            }
    }
}
