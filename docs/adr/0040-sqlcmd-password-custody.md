# ADR 0040: sqlcmd password custody

- Status: Accepted
- Date: 2026-09-01

## Context

Microsoft's Go sqlcmd stores basic-auth passwords as reversible base64 data in
the default macOS sqlconfig. macOS release executables are unsigned or ad-hoc
signed, and upstream has no credential-provider boundary suitable for
process-bound Secret Application.

## Decision

Automic Vault publishes a Developer ID-signed, Hardened Runtime sqlcmd Isotope
with no entitlements. The Isotope replaces supported passwords with `@av`
markers and uses fixed `sqlcmd-credential` operations through the signed `av`
Gate Client. It structurally validates the default sqlconfig and atomically
rewrites it only after every plaintext password has been stored.

The Hardener accepts basic-auth users in `~/.sqlcmd/sqlconfig`. Custom
sqlconfig paths, unsupported authentication, unknown fields, unsafe or
oversized files, malformed markers, and missing Secret Values fail closed.

The menu helper verifies the Gate Client and its live sqlcmd parent, including
the configured Target path, identifier `sqlcmd`, Automic Vault team identity,
Developer ID signature, Hardened Runtime, and absence of entitlements. It binds
the Authorization Request to the complete Target arguments, working directory,
user profile, endpoint, and derived Secret Name, then revalidates those claims
immediately before Secret Application.

SQL text does not provide an independently authenticated operation intent
signal, so query execution classifies as Unknown. `config connection-strings`
and `config view --raw` classify as Secret Dumps. Credential stores and deletes
use separate approved mutation operations.

## Consequences

Supported passwords remain in Secret Custody without temporary plaintext
sqlconfig files. Password changes made through the Isotope store or delete the
corresponding Secret Value through explicit mutation approvals.

Legacy flags, `SQLCMD_PASSWORD`, `SQLCMDPASSWORD`, certificates, custom
sqlconfig files, and credentials supplied outside modern config remain outside
coverage. The verified sqlcmd Target necessarily receives an approved password
in memory; Automic Vault cannot control it after Secret Application.
