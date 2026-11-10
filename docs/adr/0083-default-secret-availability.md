# ADR 0083: Opt-in default Secret Availability

Status: accepted
Date: 2026-11-10

## Context

Remote users may add a Secret and discover later that authorized operations
cannot use it while the Mac is locked. Issue #314 requests an opt-in creation
default and an explicit `av save` option, preserving ADR 0003's separation of
availability and authorization.

## Decision

Extend the closed `av settings` catalog from ADR 0076 with
`default-secret-availability`: `when-unlocked` (default) or
`available-while-locked`. Store it in the app's Data Protection Keychain.
Changes require human Approval showing both values, comparison against the
reviewed value, and a verified Authorization Record before persistence.
Ordinary same-user preference writes cannot broaden availability.

New Secrets without an explicit availability choice inherit the setting.
Existing Secrets, including new Project Values under an existing Secret Name,
retain their availability. Missing settings mean When Unlocked. Invalid or
unreadable settings deny implicit creation. The Add Secret form initializes its
existing availability control from the setting, with a When Unlocked fallback.
The existing internal `PresentationSetting` and storage service names remain
for compatibility; this new setting controls Secret Availability.

`av save --available-while-locked` selects Available While Locked for all Values
of the named Secret, including when replacing a Value. The signed Gate Client
uses a distinct `save-available-while-locked` operation so older apps reject the
request rather than silently ignore the flag. Only the trusted `av` route accepts
it. Approval and its Authorization Record include the option and all-Value scope.
The existing availability mutation journal handles interrupted multi-item
updates. The app changes availability before saving the supplied Value. If that
write fails, the approved availability change remains; Approval explains this.

## Consequences

- The shipped default stays When Unlocked; no upgrade migrates existing Secrets.
- Available While Locked increases availability after the first unlock following
  a restart. Every Secret Use still needs its own Authorization Decision.
- No Launcher policy, Approval method, synchronization choice, or Secret access
  group changes.
- Tests cover creation defaults, explicit choices, existing-Secret preservation,
  invalid settings, recording failure, stale review, CLI parsing, and all-Value
  availability updates.
