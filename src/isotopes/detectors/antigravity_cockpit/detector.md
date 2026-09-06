# antigravity-cockpit Detector

## Trigger Conditions

- Antigravity Cockpit credentials contain plaintext tokens.
- Antigravity Cockpit credentials exist but cannot be read or parsed.

## Sensitive Files

- `~/.antigravity_cockpit/credentials.json`

## Why This Matters

Older versions of Antigravity Cockpit (prior to v2.1.29) exported account
credentials to a shared file at `~/.antigravity_cockpit/credentials.json` with
permissions mode `0644` (world-readable). The file holds live refresh tokens
that survive access token expiry, creating a severe Exposure that allows any
local user or unauthorized process on the system to obtain fresh access tokens.

Cockpit disabled this shared unencrypted credential export in v2.1.29 in favor
of VS Code's native `SecretStorage` backed by the OS Keychain. However, leftover
credential files created by earlier versions are not automatically deleted upon
upgrading and remain exposed on disk.

## Mitigation

Upgrade Antigravity Cockpit to v2.1.29 or later and remove the leftover
`~/.antigravity_cockpit/credentials.json` credential file.

After deleting the unencrypted residue file, consider revoking any tokens
previously stored in plaintext to invalidate exposed refresh credentials.

## Why Automic Vault Does Not Provide a Hardener

Automic Vault does not provide a custom Hardener for Antigravity Cockpit because
upstream already adopted native OS keychain storage via VS Code `SecretStorage`
in v2.1.29. Remediation requires updating the extension and removing unencrypted
legacy residue rather than installing an Automic Vault proxy wrapper.

[Open an issue to discuss integration questions](https://github.com/automic-vault/automic-vault/issues).
