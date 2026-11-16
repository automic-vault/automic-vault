# GitHub CLI

## How Automic Vault Hardens `gh`

The official macOS `gh` executable is Developer ID signed. Upstream still
delegates Keychain reads to `/usr/bin/security` and provides `gh auth token`,
which prints the credential to standard output. Code signing establishes the
executable's identity and integrity; it does not authorize credential use.

We provide a [patched version] of `gh`. `av harden gh` installs it from our
[tap] when Homebrew is available, or installs the same signed release directly
at `/usr/local/bin/gh`. The Isotope:

1. Is Automic Vault-signed so the gate can bind the Gate Client and Target.
2. Keeps the credential in Automic Vault custody instead of an upstream
   `gh:<host>` Keychain item accessible through `/usr/bin/security`.
3. Routes authenticated operations through the `gh` Secret Gate.

[patched version]: https://github.com/automic-vault/gh-cli
[tap]: https://github.com/automic-vault/homebrew-isotopes

## Credential Migration

Use `av harden gh` to install the Isotope and migrate existing `gh` credentials
into Automic Vault. For directly managed installations, Hardened Tools reports new releases and
provides Update and Update All. Hardening keeps an existing valid release.

## Git HTTPS transport (deprecated)

Automic Vault's protected Git HTTPS transport is deprecated. This applies to
`av git` and the `git-remote-av` adapter, not the GitHub CLI Isotope or its
Secret Gate. Use [SSH with the Automic Vault SSH agent](../../../docs/securing-git.md)
for Git authentication.

`av harden gh` installs the Isotope and migrates credentials without installing
or refreshing the Git runtime, installing an adapter, or changing Git
configuration. The legacy `--without-git-configuration` flag remains accepted
as a no-op. Existing routing and old manual-configuration preferences stay
untouched. Doctor no longer asks you to install the transport or enable routing;
it reports existing `av::` URL rewrites as deprecated.

Existing transport use prints a warning on stderr and retains its runtime,
process-chain, operation, policy, and Authorization Record checks. The private
runtime installer refuses installation. An unavailable or invalid runtime still
fails closed; there is no fallback to an ordinary credential helper.

To move away from the transport, configure SSH first and review your routing:

```sh
git config --includes --show-origin --get-regexp '^url\.av::.*\.(insteadof|pushinsteadof)$'
```

Remove only the reviewed value from the reported configuration file. For the
exact global rule previously installed by this hardener:

```sh
git config --global --fixed-value --unset-all url."av::https://github.com/".insteadOf https://github.com/
```

Review included files, repository-local rules, `pushInsteadOf`, and direct
`av::` remote URLs separately. Removing a rewrite restores previous transport
selection, which may include an ordinary credential helper. It does not migrate
a remote to SSH or grant authority to retrieve a token. Ordinary helper token
retrieval remains Secret Disclosure; do not broaden policy to silence failures.

## Secret Gate

The menu bar app creates a `gh` Secret Gate as soon as the hardened CLI is
installed. Configure its default and per-Launcher Access Levels there. Read
Only automically authorizes known read-only commands and `gh api` GET requests.
Local Write also authorizes `repo clone`, `pr checkout`, `gist clone`, and
download commands, which can change local files but do not mutate GitHub.
Write Access authorizes recognized remote writes, but Secret Disclosure through
`gh auth token` or `gh auth status --show-token` still requires Approval. The gate
also classifies the entire `gh auth git-credential` command family as Secret
Disclosure, including `get`, `store`, `erase`, and future protocol operations.
Full Access includes recognized Secret Disclosure.
In-process aliases, unrecognized commands, and argument forms the gate cannot
classify require Approval at every Access Level because they may disclose the
token. Ordinary recognized read and write commands retain their Access Levels.

## Details

- The migration covers standard `hosts.yml` token entries and legacy macOS
  Keychain items named `gh:<host>`.
- Existing Git configuration can still delegate GitHub credentials to `gh auth
  git-credential`; the hardened `gh` helper path requests the token through
  Automic Vault.
- `av harden gh-cli` remains accepted as a compatibility alias.

## Using GitHub while the Mac is locked

iPhone Approval cannot unlock a Secret configured as When Unlocked. For a remote
agent, enable **Available While Locked** on the relevant GitHub Secrets while
the Mac is unlocked. The Secret Gate still authorizes each operation.

If `gh auth status` reports an invalid token only while locked, or login fails
with Keychain error `-25308`, follow the
[locked-Mac setup and troubleshooting guide](../../../docs/authorization.md#remote-work-from-a-locked-mac).
Login and credential changes can still require an unlocked Mac.
