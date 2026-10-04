import Foundation
import Testing
import Security
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

    private func key(_ name: String, byte: UInt8) -> SSHAgentCredential {
        SSHAgentCredential(name: name, publicKey: "ssh-ed25519 " + Data(repeating: byte, count: 51).base64EncodedString())
    }

    @Test func legacyConfigurationPreservesItsExactIdentityAndGeneration() throws {
        let generation = UUID()
        let publicKey = key("fixture", byte: 1).publicKey
        let data = try JSONSerialization.data(withJSONObject: ["generation": generation.uuidString,
            "enabled": true, "publicKey": publicKey])
        let config = try JSONDecoder().decode(SSHAgentConfiguration.self, from: data)
        #expect(config.enabled)
        #expect(config.generation == generation)
        #expect(config.credentials.count == 1)
        #expect(config.credentials[0].secretName == sshCredentialSecretName)
        #expect(config.credentials[0].gateID == "ssh-agent")
        #expect(config.credentials[0].publicKey == publicKey)
        #expect(try JSONDecoder().decode(SSHAgentConfiguration.self, from: JSONEncoder().encode(config)) == config)
    }

    @Test func exactKeySelectionFailsClosedOnDuplicateDisabledAndRemovedKeys() throws {
        let github = key("GitHub", byte: 1)
        let homelab = key("Homelab", byte: 2)
        var config = SSHAgentConfiguration(enabled: true, credentials: [github, homelab])
        #expect(config.credential(publicKeyDigest: try #require(github.publicKeyDigest)) == github)
        #expect(config.credential(publicKeyDigest: String(repeating: "0", count: 64)) == nil)
        let original = config
        config.credentials[0].name = "Renamed"
        #expect(config.credentials[0].gateID == github.gateID)
        #expect(config.credentials[0].secretName == github.secretName)
        #expect(config != original) // The retained configuration cannot authorize after a change.
        config.credentials.removeFirst()
        #expect(config.credential(publicKeyDigest: try #require(github.publicKeyDigest)) == nil)
        config.enabled = false
        #expect(config.credential(publicKeyDigest: try #require(homelab.publicKeyDigest)) == nil)
        config = SSHAgentConfiguration(enabled: true, credentials: [github, github])
        #expect(!config.isValid)
        #expect(config.credential(publicKeyDigest: try #require(github.publicKeyDigest)) == nil)
        #expect(throws: (any Error).self) { try JSONEncoder().encode(config) }
        let duplicateMaterial = SSHAgentCredential(name: "Other purpose", publicKey: github.publicKey)
        #expect(!SSHAgentConfiguration(enabled: true, credentials: [github, duplicateMaterial]).isValid)
    }

    @Test func malformedNewCatalogCannotFallBackToLegacy() throws {
        let fixture = ["generation": UUID().uuidString, "enabled": true, "publicKey": key("fixture", byte: 1).publicKey,
                       "version": 2, "credentials": "broken"] as [String: Any]
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(SSHAgentConfiguration.self, from: JSONSerialization.data(withJSONObject: fixture))
        }
        var config = SSHAgentConfiguration(enabled: true, credentials: [key("bad\nname", byte: 1)])
        #expect(!config.isValid)
        config.credentials = (0..<33).map { key("Key \($0)", byte: UInt8($0)) }
        #expect(!config.isValid)
    }

    @Test func credentialGatesKeepIndependentPoliciesAndDenials() throws {
        let github = key("GitHub", byte: 1)
        let homelab = key("Homelab", byte: 2)
        let config = SSHAgentConfiguration(enabled: true, credentials: [github, homelab])
        let prototype = SecretGateDescriptor(id: "ssh-agent", keyPatterns: [sshCredentialSecretName],
            routes: [SecretGateRoute(operation: "ssh-sign", scriptPath: nil, targetPath: "/signed/av",
                callerIdentifiers: ["com.automicvault.av"], keyPatterns: [sshCredentialSecretName],
                replaceExistingEnv: false, allowMissingKeys: false)])
        let descriptors = sshAgentGateDescriptors([prototype], configuration: config)
        #expect(descriptors.map(\.id) == [github.gateID, homelab.gateID])
        #expect(descriptors.map(\.keyPatterns) == [[github.secretName], [homelab.secretName]])
        #expect(descriptors[1].routes[0].keyPatterns == [homelab.secretName])
        #expect(descriptors[1].routes[0].targetPath == "/signed/av")
        let githubGate = loadedSecretGate(from: descriptors[0], policyRecords: .success([]))
        let homelabGate = loadedSecretGate(from: descriptors[1], policyRecords: .success([]))
        #expect(githubGate.initialProtection == .noAccess)
        #expect(homelabGate.availableProtections == [.noAccess, .fullExceptSecretDumps])
        #expect(!homelabGate.supportsUnknownDenial)
        let records = [SecretGatePolicyRecord(gateID: github.gateID, requirement: "identifier claude",
            protection: .fullExceptSecretDumps, runtimeRequirement: .hardened),
            SecretGatePolicyRecord(gateID: "ssh-agent", requirement: nil, protection: .fullExceptSecretDumps)]
        #expect(loadedSecretGate(from: descriptors[0], policyRecords: .success(records)).appPolicies.first?.protection == .fullExceptSecretDumps)
        #expect(loadedSecretGate(from: descriptors[1], policyRecords: .success(records)).appPolicies.isEmpty)
        #expect(loadedSecretGate(from: descriptors[1], policyRecords: .success(records)).defaultProtection == .noAccess)
        #expect(loadedSecretGate(from: descriptors[0], policyRecords: .failure(errSecDecode)).defaultProtection == .noAccess)
        let denials = TemporaryLauncherDenials()
        let scope = try #require(TemporaryLauncherDenialScope(gate: githubGate, classification: .mutating))
        denials.deny("claude", launcherName: "Claude", scope: scope, now: 0)
        #expect(denials.isDenied("claude", gate: githubGate, classification: .mutating, now: 1))
        #expect(!denials.isDenied("claude", gate: homelabGate, classification: .mutating, now: 1))
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
        #expect(configured.contains("# END Automic Vault SSH Agent\n\n" + original))
        #expect(try sshAgentConfig(configured, socketPath: nil) == original)
        #expect(try sshAgentConfig(configured, socketPath: socketPath) == configured)
        let empty = try sshAgentConfig("", socketPath: socketPath)
        #expect(empty.hasSuffix("# END Automic Vault SSH Agent\n"))
        #expect(try sshAgentConfig(empty, socketPath: nil) == "")
        let leadingBlank = try sshAgentConfig("\n" + original, socketPath: socketPath)
        #expect(try sshAgentConfig(leadingBlank, socketPath: nil) == "\n" + original)
        let legacy = configured.replacingOccurrences(of: "# END Automic Vault SSH Agent\n\n", with: "# END Automic Vault SSH Agent\n")
        #expect(try sshAgentConfig(legacy, socketPath: socketPath) == configured)
        #expect(throws: SSHAgentError.self) { try sshAgentConfig(original + configured, socketPath: nil) }
        #expect(throws: SSHAgentError.self) { try sshAgentConfig(original, socketPath: "/tmp/a\nProxyCommand bad") }
        #expect(throws: SSHAgentError.self) { try sshAgentConfig(original, socketPath: "/tmp/%h") }
    }
}
