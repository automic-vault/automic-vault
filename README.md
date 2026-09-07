# Automic Vault [![Knock Knock](https://outclaw.dev/badge.svg)](https://outclaw.dev/automic-vault/automic-vault)

> Your secrets manager should know what the secrets *do*.

Automic Vault is a macOS secrets manager for developer tools and agents. It
moves supported credentials out of plaintext files and checks the complete
operation before applying a credential.

Your terminals, IDEs, agents, and projects keep their normal commands. Agents
need no Automic Vault plugin, and repositories need no policy file.

## Quickstart

Download the [latest release], or install with Homebrew:

```sh
$ brew install --cask automic-vault/isotopes/automic-vault
$ open /Applications/Automic\ Vault.app
```

Scan for exposed credentials, harden a supported Tool, then verify the result:

```sh
$ av scan
$ av harden gh
$ av doctor gh
```

Automic Vault has several other mechanisms (Blessed Scripts, Launcher
Bundles, the Secret Proxy, Direct Secret Access) for situations a Hardener
doesn't cover. See [Choosing a Mechanism](docs/choosing-a-mechanism.md) for
which one fits your situation.

For the rest: [user manual] or `av help`.

## Detectors

Automic Vault continuously checks over 100 developer-tool configurations for
Exposures and Hazards, including plaintext credentials, permissive Keychain
items, and ambient credential helpers. Each Finding includes a mitigation.

Detectors inspect without changing your environment or requesting Secrets. A
clean Scan means no supported Detector found an issue; it cannot certify that
your machine is secure.

[Detection coverage and interpreting Findings](docs/tool-hardening.md)

## Hardeners

Hardeners move supported credentials into Secret Custody in the macOS Data
Protection Keychain and configure the Tool's Authorization Gate. Depending on
the Tool, this can mean a credential helper, wrapper, or Isotope: an Automic
Vault-compatible build of the Tool.

`av doctor` verifies the protection Automic Vault installed. AWS hardening gives
normal commands short-lived credentials; Docker hardening removes ambient
registry-helper access. Homebrew's Execution Gate controls supported operations
even when no Secret is involved.

[Hardening, verification, and AWS/Docker handoffs](docs/tool-hardening.md)

## Authorization Gates

Most secrets managers check who may retrieve a named secret. Automic Vault
checks the Verified Launcher, Tool, Target, command, arguments, working
directory, Secret Names, and selected Value sources before allowing the
complete operation on the Mac where it will run.

With **Read Only** access, one GitHub token produces three decisions:

```text
gh issue list     → automically authorized
gh issue create   → Approval required
gh auth token     → Secret Disclosure; Approval required
```

Each gate applies a default Access Level or a rule for the Verified Launcher.
**Write Access** permits recognized reads and writes; disclosure and elevated
credential use still need Approval. Unknown operations need Approval at every
Access Level.

<img src="./docs/img/authorization-gate-v4.jpg" alt="Automic Vault Authorization Gate" style="width: 589px; height: auto" />

Automic Vault controls the handoff. The Target controls the Secret after
receiving it.

[Access Levels, Approval, and locked-device behavior](docs/authorization.md)

### Temporary Access Grants

An eligible Codex task or Claude Code session can request **Allow Write Access
for 10 Minutes…**. The in-memory grant covers one Verified Launcher, Tool-specific gate,
and agent task. A visible strip lets you add ten minutes, suspend access and its
countdown, or end the grant.

<img src="./docs/img/temporary-write-access.png" alt="Automic Vault temporary write access controls" style="width: 589px; height: auto" />

The task identifier is a forgeable narrowing label; the Verified Launcher
remains the identity boundary. Grants exclude direct Secret access, Secret
mutations, elevated credential use, disclosure, and unknown operations.

[Grant scope, expiry, and controls](docs/authorization.md#temporary-access-grants)

### Touch ID Approval

Require Touch ID on your Mac for an allow action. Each Approval uses a fresh
biometric result for that exact request, without a password, Apple Watch, or
pointer-driven fallback. Touch ID requires an active Mac session and awake
displays, and can coexist with iPhone Approval.

[Enable Touch ID Approval](docs/authorization.md#touch-id-approval)

### iPhone Approval

Approve operations across your enrolled Macs from eligible iPhones on the same
iCloud Keychain account. Each Mac keeps its Secrets, policy, enforcement, and
Authorization History local; the iPhone never receives Secret Values.

Enabling iPhone Approval removes pointer- and keyboard-driven allow actions
from that Mac. Separately enabled Touch ID Approval can still carry an Approval.
An iPhone needs an active iPhone Approval subscription to send an allow response.

> [!WARNING]
> iPhone Mirroring and **Show on Mac** can put Approval controls back onto a Mac
> when phone biometrics are off. Disable those features wherever an agent can
> control the Mac, or require Face ID or Touch ID on every eligible iPhone.

[Enrollment, notifications, and account-wide recovery](docs/authorization.md#iphone-approval)

### GPG Signing

Sign Git commits and tags without giving Git the private key or passphrase.
The GPG Signing Gate authorizes private-key use while your normal Git commands
keep working. You can select a separate signing credential for exact Verified
Launchers so agents use a distinct signing identity.

The gate offers **Approval Required** and **Allow Signing**. The signing
Target handles the private key while creating the signature.

[Configure Git signing](docs/securing-git.md#gate-gpg-commit-signing)

### Authorization History

Inspect allowed and denied requests, the operations and software involved, and
the decision source. Automic Vault persists and verifies an allowed Secret
Use's record before releasing the Secret; recording failure denies release.

History is bounded and local. It provides neither tamper resistance nor a
complete forensic log.

[Authorization History and its limits](docs/authorization.md#authorization-history)

## Verified Launchers

Choose which terminals, IDEs, agents, or eligible standalone CLIs receive
authority. Automic Vault checks the live Launcher's code identity and runtime
protections on each request. Launcher-specific policy names that exact identity.

Code signing proves identity and integrity, not intent. A failed identity or
runtime check blocks automic authorization. Prefer vendor-signed distributions
when available; signing an interpreter does not authenticate the scripts,
dependencies, or plug-ins it loads.

[Launcher eligibility and vendor-signed Tools](docs/signed-cli-launchers.md)

### Launcher Bundles

For an unsigned single-file Mach-O CLI, Automic Vault can snapshot the executable
into a signed Launcher Bundle with Hardened Runtime and a root-owned command
link. Each authorization revalidates its enrolled generation, payload, signatures,
and runtime posture. Changes or re-signing hard-deny its requests.

A Launcher Bundle establishes identity for that packaged code. It cannot
establish publisher trust or make the CLI safe. Scripts and directory-shaped
Tools are unsupported.

[Create and update a Launcher Bundle](docs/signed-cli-launchers.md#create-a-launcher-bundle)

## Blessed Scripts

Review a script once and bind its canonical path, exact contents, declaration,
and capabilities to a Blessing:

```sh
$ av bless --endorse-launcher ./scripts/deploy
```

The script declares the Secrets and Tool capabilities it needs:

```sh
#!/usr/local/bin/av inject +DEPLOY_TOKEN -- /bin/bash
# --- automic-vault
# capabilities:
#   gh: read-only
#   aws: write
# ---
```

Editing the script or declaration invalidates the Blessing. A Launcher
Endorsement lets one Verified Launcher automically authorize that exact
Blessing. Use Blessed Scripts for reviewed work that exits, and Tool
Authorization Gates for long-running processes.

<img src="./docs/img/blessed-script.png" alt="Automic Vault Blessed Script review" style="width: 589px; height: auto" />

[Blessings and execution guarantees](docs/domain-language.md#blessed-script) ·
[Running scripts across app restarts](docs/direct-secret-access.md#blessed-script-lifecycle)

### Reentrant Blessed Scripts

A reentrant Blessed Script does deterministic work until it needs agent input,
then prints a prompt and exits. The prompt names the required output, fixed
subcommands that expose reviewed capabilities, and the command to continue.

Automic Vault authorizes every invocation separately. Keep Secret Values within
the script's execution and validate agent output before using it.

[Release example with GitHub, S3, and CloudFront](docs/examples/reentrant-release.sh)
includes input validation, digest checks, conditional writes, and idempotent
retries.

## Project Secrets

Keep the same Secret Name across projects, with one Global Value and separate
Project Values:

```sh
$ av save API_TOKEN
$ av save --project-directory=. API_TOKEN
```

Automic Vault selects the nearest Project Value at or above the physical working
directory, falling back to the Global Value when none matches. A read failure for
the selected Value ends the request without trying another value.

The directory selects a Value and grants no authority. The same name-based
policy covers all Values of that Secret.

[Project Values, dotenvx, and mise](docs/project-secrets.md)

## Credential Proxies

AV's Secret Proxy gives your application a random, session-specific Secret
Reference in place of each Secret Value:

```sh
$ av save API_TOKEN
$ av proxy +API_TOKEN -- node --use-env-proxy app.js
```

The proxy applies the real Secret when that reference appears in an approved
outbound HTTP/S request. Starting a Proxy Session and adding a destination
require Approval. **Allow for Session** remembers that origin and Secret Name
only for the session.

The application must support the supplied proxy and scoped CA settings. Secret
References and the Proxy Credential are bearer values: code that obtains them
can use destinations already allowed for that session.

[Application example, `.env`, and compatibility](docs/secret-proxy.md)

The [Varlock integration](docs/varlock.md) resolves Secrets through `ENV` and
can compose with Varlock's own credential proxy. It requires one Approval per
run and does not support Automic Authorization or Blessings. Varlock's proxy
and `av proxy` are separate sessions; don't nest them.

## Security Boundaries

Automic Vault protects against untrusted or compromised code running with your
normal user privileges. It builds on macOS code signing, the Data Protection
Keychain, TCC, Hardened Runtime, and live process identity.

Root or kernel compromise, arbitrary local destruction, and a Target's behavior
after receiving a Secret remain outside the product boundary. Wrappers cannot
intercept every process execution. Keep your terminal and agent harness's
[macOS permissions minimal](docs/tool-hardening.md#rescind-unneeded-terminal-permissions).

## Documentation

- [User manual][user manual]
- [Documentation index](docs/index.md)
- [Domain language](docs/domain-language.md), [architecture](docs/architecture.md), and [positioning](docs/positioning.md)
- [Architecture decisions](docs/adr/)
- [Homebrew tap](https://github.com/automic-vault/homebrew-isotopes)
- [Ephemeral chat](https://outclaw.dev/automic-vault/automic-vault)

Automic Vault is free and open source under Apache-2.0. iPhone Approval requires
a subscription to send allow responses.

> [!IMPORTANT]
> Automic Vault is not associated or affiliated with any cryptocurrency or
> “token”.

[latest release]: https://github.com/automic-vault/automic-vault/releases/latest
[user manual]: https://www.automicvault.com/docs/
