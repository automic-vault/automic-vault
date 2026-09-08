import Foundation
import Testing
@testable import MenubarHelperCore

struct SSHAgentTests {
    @Test func signingRequestRequiresTwoDigestsAndKnownFlags() {
        let args = ["payload-sha256=" + String(repeating: "a", count: 64),
                    "public-key-sha256=" + String(repeating: "0", count: 64), "signature-flags=0"]
        #expect(validSSHSigningArguments(args))
        #expect(!validSSHSigningArguments(Array(args.dropLast())))
        #expect(!validSSHSigningArguments(args + ["extra"]))
        #expect(!validSSHSigningArguments([args[0], args[1], "signature-flags=1"]))
        #expect(!validSSHSigningArguments([args[0] + "f", args[1], args[2]]))
        #expect(!validSSHSigningArguments([args[0].uppercased(), args[1], args[2]]))
    }

    @Test func agentPolicyStartsWithApprovalAndHasNoReadOnlyAuthority() {
        let gate = SecretGate(id: "ssh-agent", keyPatterns: [sshCredentialSecretName],
                              routes: [], defaultProtection: .noAccess, appPolicies: [])
        #expect(gate.initialProtection == .noAccess)
        #expect(gate.availableProtections == [.noAccess, .fullExceptSecretDumps])
        #expect(gate.normalizedProtection(.readOnly) == .noAccess)
        #expect(gate.normalizedProtection(.readOnlyAndLocalWrites) == .noAccess)
        #expect(gate.protectionTitle(.fullExceptSecretDumps) == "Allow Authentication")
        #expect(SSHAgentConfiguration().enabled == false)
    }

    @Test func agentSelectsTheGlobalCredentialEvenWithARootProjectValue() throws {
        let global = StoredSecretValue(source: .global, keychainAccount: sshCredentialSecretName, accessibility: .whenUnlocked, keychainProperties: [])
        let project = StoredSecretValue(source: .projectDirectory("/"), keychainAccount: "project", accessibility: .whenUnlocked, keychainProperties: [])
        let secret = StoredSecret(account: sshCredentialSecretName, values: [global, project])
        let selected = try resolveStoredSecretValues(names: [sshCredentialSecretName], cwd: "/",
                                                    secrets: [secret], globalOnly: true)
        #expect(selected[sshCredentialSecretName]?.source == .global)
        let ordinary = try resolveStoredSecretValues(names: [sshCredentialSecretName], cwd: "/", secrets: [secret])
        #expect(ordinary[sshCredentialSecretName]?.source == .projectDirectory("/"))
    }

    @Test func configurationIsReversibleAndRejectsAmbiguousBlocks() throws {
        let original = "Host work\n  HostName work.example\n  User alice\n"
        let home = URL(fileURLWithPath: "/Users/alice")
        let socketPath = sshAgentSocketURL(home: home, xdgDataHome: nil).path
        #expect(socketPath == "/Users/alice/.local/share/automic-vault/ssh-agent.sock")
        #expect(sshAgentSocketURL(home: home, xdgDataHome: "").path == socketPath)
        #expect(sshAgentSocketURL(home: home, xdgDataHome: "relative/path").path == socketPath)
        #expect(sshAgentSocketURL(home: home, xdgDataHome: "/custom/data").path == "/custom/data/automic-vault/ssh-agent.sock")
        let configured = try sshAgentConfig(original, socketPath: socketPath)
        #expect(configured.hasPrefix("# BEGIN Automic Vault SSH Agent\nHost *\n"))
        #expect(configured.contains("  IdentityAgent \"\(socketPath)\"\n"))
        #expect(configured.contains("  IdentityFile none\n"))
        #expect(configured.contains("  UseKeychain no\n"))
        #expect(try sshAgentConfig(configured, socketPath: nil) == original)
        #expect(try sshAgentConfig(configured, socketPath: socketPath) == configured)
        #expect(throws: SSHAgentError.self) { try sshAgentConfig(original + configured, socketPath: nil) }
        #expect(throws: SSHAgentError.self) { try sshAgentConfig(original, socketPath: "/tmp/a\nProxyCommand bad") }
        #expect(throws: SSHAgentError.self) { try sshAgentConfig(original, socketPath: "/tmp/%h") }
    }
}
