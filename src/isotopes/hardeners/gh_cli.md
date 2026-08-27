# GitHub CLI

## How Automic Vault Hardens `gh`

We provide a [patched version] of `gh`. `av harden gh` installs it from our
[tap] when Homebrew is available, or installs the same signed release directly
at `/usr/local/bin/gh`. The supported hardened path is designed so that only
the verified `gh` Isotope submits authenticated operations through the `gh`
Secret Gate; Automic Vault applies the GitHub Secret only to the authorized
Target.

The statements below describe the intended hardened-state contract. They do
not establish that this checkout, or a particular installed `gh`, is already
in Hardened State. That state is established only after the Hardener has
verified and activated the supported release.

[patched version]: https://github.com/automic-vault/gh-cli
[tap]: https://github.com/automic-vault/homebrew-isotopes

## Credential Migration

Use `av harden gh` to install the Isotope and migrate existing `gh` credentials
into Automic Vault. Direct installs are updated by running the same command when
`av doctor gh` reports a new release.

## Credential-resolution failure contract

Authenticated operations use the error-aware Automic Vault credential path.
If the Secret Application required for credential resolution is denied or
unavailable, including a timeout or approval-service/XPC unavailability, `gh`
returns a local Automic Vault credential-resolution error before it makes a
GitHub request. A credential-resolution failure never falls back to a legacy
credential, sends an anonymous request, or turns into a misleading HTTP 401.

An account-specific lookup may use the legacy host-wide credential only when
the account-specific lookup returns the exact `ErrNotFound` condition. If both
credential locations are genuinely absent, an endpoint that explicitly allows
anonymous access may remain anonymous. Absence and operational unavailability
are different outcomes.

`gh auth status` reports a credential-resolution failure caused by a denied or
unavailable Secret Application separately from an invalid GitHub credential.
Its operational diagnostic is `Vault retrieval unavailable.` It must not
describe that failure as logged out or invalid, or direct the user to log in or
authenticate again.

At the tested request boundaries, API transport and watchers re-resolve
through the error-aware path before each request. Refresh uses the
authenticated-flow token directly for credential setup and performs no
post-login Vault reread. A fresh invocation may recover after a transient
local Vault failure.

## Release and installation boundary

Only a verified official signed Automic Vault `gh` Isotope release installed by
`av harden gh` is permitted to operate against real credentials. A local source
build or checkout-local executable is not release evidence and must never
receive real credentials. Environment tokens, plaintext credential files, and
direct-binary Git workarounds are not equivalent hardened routes.

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

## Upstream context

On 2026-08-27, the official public GitHub REST state listed [GitHub CLI issue
#13317] as open. The official [pull request #13318] was open and non-draft.
These separate upstream records track misleading authentication behavior when
credential resolution fails. The Automic Vault Isotope extends the
error-aware contract across the remaining authentication-sensitive callers,
including API transport, Git credential resolution, token and refresh flows,
logout, status, and long-running operations.

[GitHub CLI issue #13317]: https://github.com/cli/cli/issues/13317
[pull request #13318]: https://github.com/cli/cli/pull/13318
