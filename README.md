# Automic Vault

[English](README.md) · [简体中文](README.zh-Hans.md)

**CLI security is broken. The packaging layer is where we fix it.**

I created Homebrew. Now I’m fixing what happens when agents use it.

— [Max Howell](https://mxcl.dev/)

You install tools to do a job. Their credentials often sit in files or helpers
that other code running as you can read. Agents inherit that access.

Automic Vault hardens supported CLI tools on macOS. We move exposed credentials
into the Keychain and change how the tools request them. You keep your commands;
AV checks the complete operation before applying a protected credential.

## Start with a tool you use

Download the [latest release], or install with Homebrew:

```sh
$ brew install --cask automic-vault/isotopes/automic-vault
$ open /Applications/Automic\ Vault.app
$ av scan
$ av harden gh
$ av doctor gh
```

For GitHub, hardening installs our signed, patched `gh` and migrates its existing
credentials into Automic Vault custody. Authenticated operations then reach the
GitHub Authorization Gate. `av doctor gh` verifies the installed protection.

Hardeners use the integration each tool supports: a patched build, wrapper,
credential helper, or configuration change. See [supported tools][hardeners] for
coverage and installation tradeoffs. A clean Scan covers only supported checks.

> [!NOTE]
> Hardening is per supported Tool. AV does not sandbox your agent or intercept
> every command. A Tool that receives a Secret can still leak it.

## Your secrets manager should know what the secrets *do*

With a Verified Launcher on GitHub **Read Only** policy, the same token produces
three decisions:

```text
gh issue list     → automically authorized
gh issue create   → Approval required
gh auth token     → Secret Disclosure; Approval required
```

Set a policy for each terminal, IDE, or agent that qualifies as a Verified
Launcher. AV verifies the live software identity and checks the Tool, Target,
command, arguments, working directory, Secret Names, and selected Value sources.
The Mac enforces the decision.

**Write Access** permits recognized reads and writes. Disclosure and elevated
credential use still require Approval. Unknown operations require Approval at
every Access Level.

<img src="./docs/img/authorization-gate-v4.jpg" alt="Automic Vault Authorization Gate" style="width: 589px; height: auto" />

[Access Levels and Approval](docs/authorization.md) ·
[Launcher eligibility](docs/signed-cli-launchers.md)

## Homebrew installs need authority too

Homebrew hardening gates package-management operations and protects
`/opt/homebrew` against modification by other code running as you. At
**Read & Update**, recognized inspection commands and `brew update` can run;
installs and upgrades need Approval.

This is separate from authorizing credential use. Installing a package does not
make its code trustworthy or put its execution in a sandbox.

> [!IMPORTANT]
> Homebrew hardening targets Apple Silicon installations at `/opt/homebrew`.
> Homebrew services and shell completions are incompatible while hardened.
> Review the [Homebrew hardener][brew hardener] before enabling it.

## Approve the work that needs more authority

For an eligible Codex task or Claude Code session, you can grant ten active
minutes of **Write Access** at one Tool-specific gate. The visible controls let
you extend, suspend, or end the grant. It excludes direct Secret access, Secret
mutation, elevated credential use, disclosure, and unknown operations.

The task identifier is a forgeable narrowing label. The Verified Launcher
remains the identity boundary.

For repeated work, review a script and its declared capabilities, then bless it:

```sh
$ av bless ./release.sh
```

A Blessed Script binds your review to its exact contents and declaration.
Editing either invalidates the Blessing. Validate agent input before using it;
a Blessing does not make the code trustworthy. A script's capability ceiling
constrains attributable gated operations, not ordinary command execution.

[Temporary Access Grants](docs/authorization.md#temporary-access-grants) ·
[Blessed Scripts](docs/direct-secret-access.md#blessed-script-lifecycle) ·
[Reviewed release example](docs/examples/reentrant-release.sh)

## Put Approval beyond an agent’s clicks

Enable **Touch ID Approval** for biometric-only allow actions on the Mac, or
use **iPhone Approval** across your enrolled Macs. Each Mac retains its own
Secrets, policy, enforcement, and Authorization History.

> [!WARNING]
> With iPhone Approval, disable iPhone Mirroring and **Show on Mac** wherever
> an agent can control the Mac, or require Face ID or Touch ID on every eligible
> iPhone. Otherwise those features can put Approval controls back on a Mac.

[Touch ID and iPhone setup](docs/authorization.md) ·
[iPhone beta](https://testflight.apple.com/join/cfnDU5kM)

## For tools and workflows beyond hardening

- [Project Values](docs/project-secrets.md) select a credential value by working
  directory. Directories select Values; they grant no authority.
- [Secret Proxy](docs/secret-proxy.md) applies credentials to approved HTTP
  destinations for compatible clients. Its session references are bearer values.
- [GPG signing](docs/securing-git.md#gate-gpg-commit-signing) and the
  [SSH Agent Gate](docs/domain-language.md#ssh-agent-gate) authorize signatures
  without giving Git or SSH clients the private key. SSH authority does not
  restrict destinations.
- [Launcher Bundles](docs/signed-cli-launchers.md#create-a-launcher-bundle)
  establish a verified identity for supported unsigned CLIs, not publisher trust.

[Choosing a Mechanism](docs/choosing-a-mechanism.md) covers these options,
Direct Secret Access, and their tradeoffs. The [user manual] has the full CLI
reference, setup instructions, and troubleshooting.

## Where this stops

AV protects against untrusted or compromised code running with your normal
user privileges. It builds on macOS code signing, the Data Protection Keychain,
TCC, Hardened Runtime, and live process identity. Code signing establishes
identity and integrity, not intent.

Root or kernel compromise, arbitrary local destruction, and a Target's behavior
after receiving a Secret remain outside the product boundary. Wrappers cannot
intercept every process execution. Keep your terminal and agent harness's
[macOS permissions minimal](docs/tool-hardening.md#rescind-unneeded-terminal-permissions).

[Authorization History](docs/authorization.md#authorization-history) records
allowed and denied requests locally. AV persists and verifies an allowed Secret
Use's record before releasing the Secret. History is bounded, not tamper-proof
or a complete forensic log.

## Companion Apps

Network filtering and general-purpose agent sandboxing are outside Automic
Vault's scope and roadmap. These apps cover those needs:

- [Tiny Shield](https://tinyshield.proxyman.com) monitors your Mac's network
  connections and lets you block apps or domains. Automic Vault controls whether
  an operation may use a protected credential; Tiny Shield adds control over
  where apps can connect, including traffic that uses no credential.
- [agentsh](https://www.agentsh.org) applies file, network, and process policies
  to agents run through it. Use it to restrict workspace access and command
  execution alongside Automic Vault's Secret Custody and Authorization Gates.
  Those restrictions address local actions, such as deleting files, that need
  no protected Secret and may never reach an Automic Vault gate.

&nbsp;


## Documentation

- [User manual][user manual]
- [Documentation index](docs/index.md)
- [Choosing a Mechanism](docs/choosing-a-mechanism.md)
- [Domain language](docs/domain-language.md), [architecture](docs/architecture.md), and [positioning](docs/positioning.md)
- [Architecture decisions](docs/adr/)
- [Homebrew tap](https://github.com/automic-vault/homebrew-isotopes)
- [![Chat w/Maintainer](https://knock-knock.mxcl.dev/badge.svg)](https://knock-knock.mxcl.dev/automic-vault/automic-vault)

&nbsp;


> [!IMPORTANT]
> Automic Vault is not associated or affiliated with any cryptocurrency or
> “token”.

[latest release]: https://github.com/automic-vault/automic-vault/releases/latest
[user manual]: https://www.automicvault.com/docs/

[hardeners]: https://www.automicvault.com/docs/hardeners/
[brew hardener]: src/isotopes/hardeners/homebrew.md
