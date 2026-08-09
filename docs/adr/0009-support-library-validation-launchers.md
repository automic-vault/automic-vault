# ADR 0009: Support Launchers That Disable Library Validation

- Status: Accepted
- Date: 2026-08-09

## Context

ADR-backed enforcement introduced by pull request #102 requires Hardened
Runtime for new Secret Gate Launcher rules. It permits JIT executable-memory
exceptions but rejects disabled library validation. Claude Code's official
Developer ID-signed executable enables Hardened Runtime together with JIT,
unsigned executable memory, and disabled library validation. As a result,
making its version-numbered executable selectable for issue #141 would still
leave an important agent Launcher ineligible for ordinary gate policy.

Apple describes disabled library validation as allowing a process to load
third-party code that is not signed by Apple or the same Team. This weakens the
Launcher's in-process trust boundary, but it is distinct from the entitlement
that permits DYLD environment variables to inject code or change library search
paths. Treating both capabilities as the same hard failure prevents legitimate
plug-in hosts without preserving that distinction.

A global eligibility expansion must not silently broaden existing rules. A
strictly hardened Launcher could otherwise add disabled library validation in a
later release and retain authority that the user granted under a stronger
posture.

## Decision

A Launcher remains eligible when it enables Hardened Runtime and its only
additional supported runtime exception is disabled library validation. The UI
warns that third-party libraries and plug-ins can run inside the Launcher and
inherit its Secret Gate authority.

Automic Vault continues to reject a Launcher that lacks Hardened Runtime or
enables DYLD environment variables, disables executable-page protection, or
allows debugger attachment. JIT and unsigned executable memory remain supported
as before.

New Launcher-specific Secret Gate rules and Direct Access Rules store a
Launcher Runtime Requirement derived from the live signing posture at
enrollment. Runtime authorization accepts the same posture or a stronger one:

- a strict Hardened Runtime rule accepts only a strictly hardened Launcher;
- a rule created with library validation disabled accepts that exception or its
  later removal; and
- neither rule accepts a missing Hardened Runtime flag or a blocked exception.

Existing strict records from #102 decode as strict. Older explicit policies
that were deliberately grandfathered continue to decode as legacy unchecked
records. Existing Direct Access Rules decode as strict because their enrollment
path has always required the then-current runtime eligibility check.

Default Authorization Policy applies only to a live Launcher that satisfies the
current eligibility classifier. Defaults do not persist a per-Launcher posture;
their authority follows the user's chosen default and the current definition of
a Verified Launcher.

Launcher identity remains exact designated-requirement equality. No exception
is specific to Anthropic, a path, a display name, or a Team ID alone.

## Consequences

- Claude Code can participate in ordinary Secret Gate policy once its signed
  executable is selectable.
- Third-party code loaded inside an eligible Launcher can exercise that
  Launcher's authority, so enrollment and Direct Access confirmation show a
  warning.
- Existing strict durable rules do not gain authority when a Launcher later
  disables library validation.
- A Launcher that adds an injection, executable-page, debugger, or unknown
  blocked exception loses automic authorization and requires Approval.
- The stored policy formats gain an additive runtime-requirement field; existing
  records decode without migration.
