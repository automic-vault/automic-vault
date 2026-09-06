# gemini-cli Detector

## Trigger Conditions

- Gemini CLI OAuth credentials contain plaintext tokens.
- Gemini CLI OAuth credentials exist but cannot be read or parsed.

## Sensitive Files

- `~/.gemini/oauth_creds.json`

## Why This Matters

Gemini CLI caches OAuth credentials in `~/.gemini/oauth_creds.json` with
permissions mode `0600`. The file contains plaintext `access_token`,
`refresh_token`, and `id_token` values. Live refresh tokens survive access-token
expiry, allowing unauthorized processes running under the same user account to
mint new access tokens and call Gemini services without authentication prompts.

## Mitigation

Delete `~/.gemini/oauth_creds.json` and authenticate via short-lived environment
credentials, or configure Gemini CLI's encrypted file storage support with
`GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true`.

## Why This is not Yet Hardened

Gemini CLI defaults to storing OAuth credentials on disk in plaintext JSON rather
than using the macOS Keychain, and does not provide a pluggable credential-helper
interface. While an encrypted file backend can be forced through environment
variables, Automic Vault does not yet provide a verified wrapper or dedicated
secret gate for the tool.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
