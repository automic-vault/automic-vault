# ADR 0048: Authorize SSH authentication from Blessed Scripts

Status: accepted

Per-credential authority and the scope of legacy script Capabilities are amended
by [ADR 0064](0064-per-credential-ssh-authority.md).

## Context

ADR 0044 excluded script authority from the SSH Agent Gate. That gate derives
the SSH socket peer from kernel evidence and verifies original parent executions,
while ordinary Blessed Script matching walks a different process ancestry.
A Script Declaration can nevertheless name `ssh-agent: trusted`, making an
approved release script appear authorized even though its Git children prompt.

## Decision

Permit an active Blessed Script with an explicit `ssh-agent: trusted` Capability
to authorize recognized SSH authentication signatures. Reuse the SSH Agent
Gate's original-parent checks, including its narrow Apple `login` relay, to
collect the exact live ancestors between socket peer and Verified Launcher.
Match active Blessed Script executions and empty capability ceilings only within
that verified chain. Recheck the same process executions, peer, Launcher,
credential configuration, and authentication payload before the Authorization
Record and again immediately before Secret Application. A revoked active
Blessing acts as an empty ceiling until its execution ends, so revocation never
exposes an outer Blessing or Launcher policy. A missing, replaced, or
unverifiable execution fails closed. Keep per-request Authorization Records and
prohibit transient decision reuse, Temporary Access Grants, and Retained Launcher
Provenance.

`ssh-agent: trusted` delegates authentication to the script's runtime and
children, including possible remote writes. The gate cannot establish the
destination of a forwarded or shared agent connection, so this Capability does
not claim destination restrictions. A script without an explicit SSH Capability
may use inherited Launcher policy only under normal Capability Inheritance; an
empty capability ceiling blocks both paths.

## Consequences

Reviewed release automation can use Git over SSH without a separate Approval
for each authentication signature. A Blessed Script's dependencies and commands
can exercise this authority while they remain in its verified live ancestry,
as with other script Capabilities. The Blessing remains bound to the script's
exact reviewed contents and Script Declaration.
