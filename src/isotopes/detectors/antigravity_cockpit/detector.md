# antigravity-cockpit Detector

## Trigger Conditions

- Antigravity Cockpit credentials contain plaintext tokens.
- Antigravity Cockpit credentials exist but cannot be read or parsed.

## Sensitive Files

- `~/.antigravity_cockpit/credentials.json`

## Why This Matters

Antigravity Cockpit stores per-account credentials in
`~/.antigravity_cockpit/credentials.json` with permissions mode `0644`
(world-readable). The file holds live refresh tokens that survive access token
expiry, creating a severe Exposure that allows any local user or unauthorized
process on the system to obtain fresh access tokens.

## Why This is not Yet Hardened

Antigravity Cockpit stores mutable account credential state on disk without a
native keychain-backed credential store or pluggable credential helper. A safe fix
requires upstream support for system keychain custody or a dedicated source isotope.

Antigravity Cockpit manages account credentials independently through
`~/.antigravity_cockpit/credentials.json`, writing unencrypted tokens with
world-readable permissions outside of the CLI's purview. It does not provide
pluggable credential storage or system keychain integration.

Environment-wrapper stubs cannot resolve this exposure because Cockpit is a
companion GUI application operating outside the terminal shell and its OAuth
sessions rely on live token refreshes that require bidirectional writeback to disk.

A complete Hardener requires upstream Antigravity Cockpit to add native macOS
Keychain custody or support for external credential helpers.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
