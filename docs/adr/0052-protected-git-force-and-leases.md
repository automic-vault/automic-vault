# ADR 0052: Protected Git force pushes and per-branch leases

- Status: Implemented in candidate; signed Vault/GitHub validation required before merge
- Date: 2026-09-23
- Extends: [ADR 0047](0047-protected-git-https-transport.md)

## Context

Ordinary rebases need non-fast-forward pushes. The protected remote helper
previously rejected both unconditional force and leases. The
[feasibility assessment](../git-remote-helper-security-review.md#force-pushes-and-leases-feasibility-assessment)
found no need to broaden credential confinement, but demonstrated two unsafe
implementations: a `+` force marker overrides stale-lease rejection, and storing
all `cas` options under one key silently discards branch expectations.

## Decision

Extend only the native configuration-selected helper's branch-update surface.
The earlier fixed-form `av git` harness retains its existing limitations.

- An unconditional force update carries `+` with one resolved commit ID and
  one exact `refs/heads/` destination.
- A leased update carries one explicit expected SHA-1 ID per destination and
  no `+`. The all-zero expected ID means the branch must not exist. Git expands
  implicit tracking-ref expectations before submitting them to the helper.
- Combining unconditional force and a lease on the same destination fails
  explicitly. Independent modes on different destinations are allowed.
- Duplicate destinations, duplicate/conflicting or unmatched leases, malformed
  refs/IDs, zero new commit IDs, tags, deletions, and unreviewed options fail
  closed. A lease never becomes a plain push as a fallback.

The native adapter retains leases in a separate map keyed by destination. It
resolves source refs before registration, constructs the complete immutable
plan, and validates it before executing the credential-bearing process. Lease
state is consumed by exactly one push batch; applying it to list/fetch or
ending a session with an incomplete lease request fails.

The canonical wire places sorted `option cas REF:OID` entries before sorted
ordinary options, a separator, and the complete push batch. Rust and Swift both
validate it. At most 4,096 updates and 4,096 leases are accepted; existing line
and batch byte limits remain, with a separate 1 MiB lease-value limit and an
8,202-field wire ceiling. Registration retains the complete plan in credential
scope and Authorization History. Approval detail explicitly identifies
unconditional force and every required lease.

The helper requests protocol version 3 before any network phase. Older apps
reject the new CLI early. The updated service retains versions 1 and 2 for
older clients, whose parsers cannot construct the new operations.

## Security boundary

Classification remains Remote Write under the existing gh Authorization Gate.
Neither Read Only nor Local Write authorizes these requests automatically.
Existing Write Access may authorize them; this decision introduces no new
Access Level. Approval of discovery does not approve the later update.

The protected runtime, fixed GitHub HTTPS destination, TLS settings, empty
configuration, native ownership of stdin, original-process verification,
record-before-release checks, fresh HTTPS process per request, and registration
lifetime are unchanged. No arbitrary flags or helper commands are forwarded.
The lease check executes inside the constrained transport. Expected IDs are
never refreshed after Approval, and server ref transactions handle changes
between discovery and update. Multi-branch pushes retain ordinary non-atomic
partial-success behavior; this does not add atomic pushes or signed pushes.

A lease is a condition on an authorized write, not proof of benign intent. The
outer Git may select an expectation. Unconditional force can overwrite remote
history, so Approval and Authorization History must describe it accurately.

## Validation and release gate

Rust session tests cover source freezing, exact payload/wire content, multiple
leases, lease lifetime, invalid requests before execution, and termination on
denial. Rust and Swift plan tests cover force/lease conflicts, duplicates,
unmatched leases, zero IDs, malformed inputs, bounds, and Remote Write policy.
The loopback probe exercises the installed Git 2.50.1 transport using dummy
credentials, including stale/concurrent remote state, dry-run, server policy,
credential-store/tracing, and redirect rejection.

The updated `scripts/test-git-remote-e2e.py` is the signed candidate test for
actual GitHub force/lease effects, tracking refs, native stale/multiple leases,
malformed input, complete Authorization History, and existing replay defenses.
It requires a disposable private repository and an installed signed candidate;
it has not yet been run for this change. Human Approval/denial, record failure,
and mutation while Approval is pending remain required before merge, as
specified by the feasibility assessment. Local test success does not replace
these checks. Keep the PR draft until the release gate is satisfied.
