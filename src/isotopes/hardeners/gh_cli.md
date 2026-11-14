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

## GitHub HTTPS operations

After completing Isotope installation and credential migration, `av harden gh`
also attempts to configure Git globally to use Automic Vault's protected
transport for `https://github.com/` URLs, including fresh clones. It verifies
the installed signed CLI, installs or refreshes the protected runtime, checks
adapter discovery, and then adds the routing rule. Saved remote URLs and SSH
operations stay unchanged. `av doctor gh` checks this setup; rerun
`av harden gh` to repair it.

If Git setup fails, including because the available Git build has not been
reviewed, `gh` hardening still completes and reports a warning. Migrated legacy
credentials are removed and their cleanup verified before Git setup begins.
Doctor continues to report incomplete Git setup. No unverified transport is
published and no fallback credential helper is configured; protected Git
operations retain their runtime verification requirements.

If you manage Git configuration yourself, use:

```sh
av harden gh --without-git-configuration
```

This installs the `gh` Isotope and migrates credentials while leaving Git
configuration and the protected Git runtime untouched. Automic Vault records
the manual choice in `av-git-configuration` beside `hosts.yml`, so Doctor does
not request automatic Git setup. A later `av harden gh` configures Git and
resumes those checks. The option does not remove an existing routing rule or
grant ordinary Git permission to retrieve the token.

Automatic setup stops on overlapping URL rewrites, conditional configuration,
or Git environment overrides and offers the same option. It inspects the
system, global, included, and current repository configuration; it cannot
inspect every other repository or predict later configuration changes.

The protected transport supports the reviewed Git build and command surface in
the [Git workflow guide](../../../docs/git-workflow-testing.md#current-limits).
Unsupported requests fail explicitly without falling back to a credential
helper. Authorization still uses the existing `gh` Secret Gate.

To remove only the global routing value installed by this hardener:

```sh
git config --global --fixed-value --unset-all url."av::https://github.com/".insteadOf https://github.com/
av harden gh --without-git-configuration
```

Remove any separately configured repository-local rule separately. Rollback
restores previous transport selection; ordinary credential-helper requests
still require Secret Disclosure authority.

## Git cannot find `remote-av`

A `url."av::https://github.com/".insteadOf` rule makes Git look for
`git-remote-av`. Adding that rule by hand does not install the adapter or its
protected runtime. The adapter alone is also insufficient: the transport
requires a reviewed Git build, the matching signed Automic Vault CLI, and the
verified runtime.

Inspect the setup without fetching credentials:

```sh
command -v git
command -v git-remote-av
git config --show-origin --get-all 'url.av::https://github.com/.insteadOf'
av doctor gh
```

`command -v` only shows shell resolution; it does not verify the adapter or
Git's own helper search path. Homebrew Git is not supported by this transport.
For that setup, use SSH with Automic Vault's SSH agent rather than adding an
HTTPS rewrite. Review the origin reported above and remove only the manually
added routing value from that configuration file. The global rollback command
above applies only to a global rule; included and repository-local files need
separate review. Preserve unrelated rewrites and remote URLs.

If Doctor reports an unsupported build, rerunning setup cannot make that build
reviewed. `--without-git-configuration` suppresses automatic Git setup checks
but does not remove existing rewrites or repair a missing adapter. Do not copy
an arbitrary `git-remote-av` executable into PATH or enable an ordinary token
helper as a workaround. Ordinary helper token retrieval is Secret Disclosure.

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
