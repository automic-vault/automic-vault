# ADR 0064: Independent authority for each SSH credential

Status: accepted; amends [ADR 0044](0044-ssh-agent-gate.md) and [ADR 0048](0048-ssh-agent-blessed-scripts.md).

## Context

Issue #368 needs one Verified Launcher to authenticate with a GitHub key while
requiring Approval for a different homelab key. A key label or client-supplied
hostname cannot prove destination. Reusing a key at both services preserves
access to both, regardless of its name.

## Decision

Keep one agent and a bounded catalog of up to 32 named credentials. Enumerate
public keys without retrieving private material. Each credential owns an exact
Secret Name and independent Authorization Gate. Select by the SHA-256 digest
of the SSH protocol public-key blob, rejecting absent or duplicate keys.
The original credential retains its Secret Name, gate ID and policy. Decode the
legacy configuration into that single named credential without copying private
bytes or adding authority. New keys use fresh UUID identities and start at
Approval Required. Never reuse removed identities. Rename changes display only;
replacement requires adding a fresh key and reviewing fresh policy.

The request and Authorization Record bind the selected Secret and key digest.
The existing live socket, original ancestry, runtime, record-before-release and
configuration revalidation checks remain mandatory. No reuse, temporary grants,
retained provenance or fallback to another credential applies. Denial remains
scoped to the exact credential gate. Existing `ssh-agent: trusted` script authority
covers only the original credential, never newly added keys. Empty capability
ceilings and revoked Blessings continue to suppress inherited automatic policy.

Catalog mutations abort if the existing configuration cannot be read or decoded;
only a missing catalog can initialize an empty configuration.
Addition requires the existing human Approval surface. Store private material
before publishing it in configuration. Configuration publication failure leaves
no new usable identity. Removal unpublishes first, invalidating pending signatures,
then deletes private material; errors are surfaced without restoring authority.
Generating Ed25519 keys uses the existing RustCrypto dependency inside the signed
helper; usable private material is never written to disk or displayed.

## Consequences

Settings presents a key list with per-key policy, also available from Authorization
Gates. New keys require registration with their services. Public key ordering can
cause OpenSSH to try a key the user did not intend; rejecting or approving a
signature applies to that exact key only, never all keys for the connection.
Imports do not remove external private copies or another agent’s entries. Names
and fingerprints aid review but do not establish destinations or Launcher identity.
