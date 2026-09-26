# 0053: Launcher denial thresholds and temporary denial

Status: accepted

## Context

A Launcher can repeatedly restart a Gate Client before the user answers its
Approval prompt. Process-scoped denial reuse cannot cover those retries.
Repeated prompts can pressure the user into approving Secret Disclosure merely
to stop the interruptions (issue #358).

## Decision

Add an optional Denial Threshold to each Launcher-specific gate policy. The
threshold includes its selected Access Level and everything above it in that
gate's supported preset list. It is the complement of the preceding allow
preset, not a new global risk ordering. Approval Required denies everything;
Unknown is denied for every configured threshold. Denial wins over all allow
sources. Existing policies decode with no threshold. Invalid or unreadable
policy must not bypass denial by falling through to Approval.

Use the existing protected policy store and authority-change approval for
removing or weakening denial. Allow-preset edits preserve denial. Rule deletion
that removes denial also requires that approval.

After three prompts from the same eligible Verified Launcher within thirty
seconds, offer a two-minute Temporary Launcher Denial. Only an explicit user
action activates it. Match designated requirements, never display names or PIDs.
Use elapsed time and memory-only state; caller restarts do not clear it. Expiry
or service restart restores ordinary policy. Already released Secrets and
already running operations are not recalled.

Recheck denial before queued Approval and Secret release. Record automatic
Denials with their source, without further approval notifications. Never infer
a rule from a cancellation or reuse a historical display name as identity.

## Consequences

An allow ceiling and a deny threshold can overlap; denial wins. Operations
between them require Approval. Gates with signing-only or authentication-only
presets can deny those operations without inventing unrelated levels.

Prompt flood detection is bounded and offers a control; it does not silently
change policy. Fast rejection may expose a caller's busy retry loop. History
remains bounded by its existing retention policy. CLI history pagination is a
separate change and the 1 MiB reply boundary remains intact.
