# 0079: Root-enrolled local ib Execution Gate

Signing admission superseded by [ADR 0080](0080-ib-signing-identity.md).

Status: accepted

## Context

ib manages protected Homebrew bottles through a dedicated non-root account.
Its local source installer cannot require an Automic Vault Developer ID signing
key. Accepting a path or an arbitrary ad-hoc signing name would let same-user
software impersonate a Gate Client.

## Decision

The root-run installer records the signed code hash, protocol version, UID and
GID in a protected enrollment file beside the protected executable. It signs
ib with Hardened Runtime, identifier `dev.mxcl.ib`, and no entitlements.
The binary remains owned by the package account with mode 6555; its containing
directory and enrollment are root-owned and not writable by the user.

At startup AV adds only that exact validated hash to its XPC admission
requirement. Existing Developer ID requirements remain unchanged. Installation
or an update requires restarting AV. Runtime validation independently reloads
the enrollment and validates the live peer through its XPC audit token, not a
PID supplied by the client. The real user must be AV's user and the effective
UID/GID must match the enrolled package account. The runtime must be hardened,
entitlement-free, and match the enrolled identifier and code hash.

A dedicated route accepts one request per connection: `authorize`, protocol 1,
fixed Target, `tool=ib`, no Secret Names, and a positive catalog of package and
service mutations. Unknown syntax denies the request before Approval. No client
in this route can enter Secret APIs or the generic client dispatch.

Each operation needs fresh human Approval through AV's existing configured
surface. The service checks identity and enrollment after Approval, persists and
verifies the Authorization Record, rechecks identity, then returns an explicit
protocol-1 acknowledgement. It supplies no Secret bytes. It does not reuse
Homebrew policies, Blessings, Temporary Access Grants, or cached decisions.

## Limits

Root is the enrollment authority and is outside the same-user adversary model.
Installing a local build is an administrator trust decision, not proof of the
build's source provenance. A damaged or replaced enrollment/build fails closed.
The integration adds no general-purpose execution containment. ib enforces
its package boundary and AV controls its submitted mutations.
