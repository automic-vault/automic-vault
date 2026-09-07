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
into Automic Vault. Direct installs are updated by running the same command when
`av doctor gh` reports a new release.

## Secret Gate

The menu bar app creates a `gh` Secret Gate as soon as the hardened CLI is
installed. Configure its default and per-Launcher Access Levels there. Read
Only automically authorizes known read-only commands and `gh api` GET requests.
Local Write also authorizes `repo clone`, `pr checkout`, `gist clone`, and
download commands, which can change local files but do not mutate GitHub.
Write Access authorizes recognized remote writes, but Secret Disclosure through
`gh auth token` or `gh auth status --show-token` still requires approval.

## Details

- The migration covers standard `hosts.yml` token entries and legacy macOS
  Keychain items named `gh:<host>`.
- Existing Git configuration can still delegate GitHub credentials to `gh auth
  git-credential`; the hardened `gh` helper path requests the token through
  Automic Vault.
- `av harden gh-cli` remains accepted as a compatibility alias.
