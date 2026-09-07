# ADR 0035: rclone Configuration Password Custody

## Decision

rclone's configuration wrapping password is a Global Value applied only through
the `rclone` Authorization Gate. The Target must be the Automic Vault Isotope,
signed by the Automic Vault team with Hardened Runtime and no entitlements. The
Isotope changes only rclone's default password command to
`/usr/local/bin/av rclone-password 1`.

The Hardener uses rclone's native configuration encryption rather than parsing,
extracting, or recreating individual remote credentials. Competing password
environment variables and inherited config-key files fail closed during
hardening.

## Context

rclone supports many backends and stores their credentials together in one
configuration. Its native encrypted-config boundary covers those formats without
temporary plaintext files, but the password command receives no remote or
operation context. Upstream's macOS release is not code signed, so the Gate
cannot accept it as a Target.

## Consequences

One approved Secret Application unlocks every remote in the configuration for
the lifetime of that verified rclone process. Automic Vault does not claim
per-remote access control. Doctor verifies the signed Target and native encrypted
configuration; unsupported encryption versions and plaintext state fail closed.
