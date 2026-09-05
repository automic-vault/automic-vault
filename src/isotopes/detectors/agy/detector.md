# agy Detector

## Trigger Conditions

- agy OAuth credentials contain plaintext tokens.
- agy OAuth credentials exist but cannot be read or parsed.

## Sensitive Files

- `~/.gemini/oauth_creds.json`

## Why This Matters

agy caches OAuth credentials in `~/.gemini/oauth_creds.json` (mode `0600`) with
access, refresh, and ID tokens. The file holds live refresh tokens that survive access
token expiry, creating an Exposure that allows unauthorized processes running as
the user to obtain fresh access tokens.

## Why This is not Yet Hardened

agy stores mutable OAuth session state on disk without a native keychain-backed
credential store or pluggable credential helper. A safe fix requires upstream
support for system keychain custody or a dedicated source isotope.

agy's OAuth authentication flow hardcodes token storage to `~/.gemini/oauth_creds.json`
without a configuration option, environment variable, or command-line flag to
delegate session storage to the macOS Keychain or an external credential helper.
While agy includes internal keyring support for enterprise Google Cloud and
Workforce Identity Federation onboarding, standard developer OAuth sessions
cannot use this mechanism.

Environment-wrapper stubs cannot resolve this exposure because OAuth sessions
rely on live token refreshes that require bidirectional writeback to disk,
unlike static credentials passed via environment variables.

A complete Hardener requires upstream agy to add native macOS Keychain custody or
support for external credential helpers.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
