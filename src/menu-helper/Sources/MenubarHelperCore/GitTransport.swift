import Foundation

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

    public init?(_ arguments: [String]) {
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
        let config = [
            "credential.helper=", "credential.helper=!exec /opt/av/git/bin/gh auth git-credential",
            "credential.useHttpPath=true", "core.hooksPath=/dev/null", "core.fsmonitor=false",
            "http.sslBackend=openssl", "http.sslVerify=true", "http.sslCAInfo=/private/etc/ssl/cert.pem",
            "http.sslCAPath=/opt/av/git/empty", "http.followRedirects=false", "http.proxy=",
            "protocol.allow=never", "protocol.https.allow=always",
        ]
        return ["--no-replace-objects"] + config.flatMap { ["-c", $0] } + tail
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
