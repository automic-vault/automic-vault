# uv Detector

## Trigger Conditions

- uv credentials store contains plaintext credentials.

## Sensitive Files

- `$UV_CREDENTIALS_DIR/credentials.toml`
- `$XDG_DATA_HOME/uv/credentials/credentials.toml`
- `~/.local/share/uv/credentials/credentials.toml`

## Native Keychain Does Not Close the Exposure

The official macOS arm64 `uv 0.12.12` release has a valid Developer ID signature
and Hardened Runtime. Its native authentication backend calls Keychain Services
directly rather than delegating reads to `/usr/bin/security`.

However, any process running as the user can invoke the signed executable's
Secret Disclosure command:

```sh
UV_PREVIEW_FEATURES=native-auth uv auth token <service>
```

This prints the stored token to standard output. For password credentials, add
`--username <username>`. The Keychain authenticates `uv`; it does not authorize
the Launcher or the complete operation. Code signing therefore does not close
this Unprotected Credential Access path.

Native Keychain storage can reduce plaintext storage exposure, but configuring
it is not a Hardened State under the [Automic Vault security model](../../../../docs/domain-language.md).
The Detector checks the selected plaintext store;
absence of that file does not establish that native credentials are protected.
Scans must not invoke `uv auth token` or read credential bytes to test access.

### Verification: 2026-09-09

Tested the official `uv-aarch64-apple-darwin.tar.gz` from
[release 0.12.12](https://github.com/astral-sh/uv/releases/tag/0.12.12) on macOS
26.6.2 with a fresh dummy credential for a unique `.invalid` host:

- Archive SHA-256 matched the published checksum:
  `46740540b63fdee9a6cb2e19baf3f1f475b850c440a33e63455087a6871263f1`.
- `codesign --verify --strict` passed. The signer was
  `OpenAI OpCo, LLC (2DC432GLL2)`, with Hardened Runtime and no entitlements.
- Native login created a generic password with service `uv:<host>` and account
  `__token__`. Its secret-read ACL trusted the tested `uv` executable and did
  not include `/usr/bin/security`.
- `uv auth token` returned the exact dummy credential without a prompt.
- `/usr/bin/security find-generic-password -s uv:<host> -a __token__ -w`
  returned no credential before a five-second timeout; no approval was given.
  The timeout alone is inconclusive, but the ACL and upstream implementation
  do not show the `gh` delegation problem for this fresh item.
- All dummy credentials were removed. Existing credentials and ACLs were not
  changed. Older or manually modified items may have different access controls.

The locally installed Homebrew `uv 0.12.9` was only ad-hoc signed and lacked
Hardened Runtime. Do not infer signing posture from the Tool name or version.

Reproduce the credential checks with the manual
[dummy-only probe](../../../../scripts/check-uv-keychain.py), passing a reviewed
executable path. It reports retrieval results without printing the dummy value.
Review the tagged upstream
[native Keychain implementation](https://github.com/astral-sh/uv/blob/0.12.12/crates/uv-keyring/src/macos.rs),
[service naming](https://github.com/astral-sh/uv/blob/0.12.12/crates/uv-auth/src/keyring.rs),
and [token command](https://github.com/astral-sh/uv/blob/0.12.12/crates/uv/src/commands/auth/token.rs)
when reassessing a newer release. The `native-auth` preview is distinct from the
external `--keyring-provider subprocess` integration.

## Hardening

`av harden uv` migrates supported plaintext HTTP Basic credentials into AV
custody and installs the official signed distributable with a registered
keyring helper. See the [uv Hardener](../../hardeners/uv_cli.md) for setup,
supported commands, and limitations. Native Keychain and other credential
sources require separate migration; an empty plaintext store does not certify
their absence.
