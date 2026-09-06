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
credentials such as `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_CLOUD_ACCESS_TOKEN`.

While Gemini CLI supports token storage migration via the OS Keychain, it falls
back to an encrypted file (`~/.gemini/gemini-credentials.json`) when native
keychain storage is unavailable or when `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true`
is set. This fallback derives its AES key entirely from static metadata (the
application name, hostname, and username). Any process running under the user's
account can reconstruct the key and decrypt the credentials. Do not rely on
encrypted-file storage alone to resolve same-user credential exposure.

## Why This is not Yet Hardened

Gemini CLI defaults to storing OAuth credentials on disk in plaintext JSON rather
than enforcing native macOS Keychain custody, and does not provide a pluggable
credential-helper interface. Automic Vault does not yet provide a verified wrapper
or dedicated secret gate for Gemini CLI.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
