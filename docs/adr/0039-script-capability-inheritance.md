# ADR 0039: Preserve Script Capability Inheritance Until a Major Version

- Status: Accepted
- Date: 2026-09-08

## Context

Scripts without a capabilities manifest currently continue beneath authority
available from their execution context. Users may rely on that behavior. Making
an omitted manifest mean no inherited authority would be safer, but would break
existing automation without an explicit migration.

Scripts also need a way to state that no calling Launcher, outer Blessed Script,
or Temporary Access Grant may automatically authorize their later gated
operations. Starting a script with that restriction grants no authority and
therefore does not itself need Approval when the script requests no Secret.

## Decision

An omitted capabilities manifest retains Capability Inheritance.
`capabilities: { inherit: true }` expresses that behavior explicitly.
`capabilities: {}` disables Capability Inheritance and establishes an empty
capability ceiling for the exact script execution.

Blessing records created before Capability Inheritance was stored explicitly
retain their previous inheritance behavior. Reblessing records the current
declaration mode.

The empty ceiling blocks automic authorization from outer Blessings, Launcher
policy, Direct Access Rules, and Temporary Access Grants. It does not block a
human Approval or constrain ungated process execution. Secret Names in the
script's own `av inject` shebang remain part of a separate complete Authorization
Request and must be authorized and recorded before release.

A snapshot-compatible script with no requested Secret Names and an explicit
empty ceiling may start without Approval. The approval service validates the
complete declaration and registers the ceiling before allowing execution.
The ceiling remains memory-only and attributable through live process ancestry;
an Automic Vault restart or loss of observable ancestry ends it.

## Consequences

- Existing scripts keep working without modification.
- Security-sensitive scripts can opt out of ambient automic authority now.
- Explicit inheritance documents compatibility dependencies before the next
  major version.
- A future major version should make omission equivalent to the empty ceiling;
  the migration is tracked in `docs/future-breaking-changes.md`.
