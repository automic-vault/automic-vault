# 0054: Scoped temporary denial and explicit cancellation

Status: accepted; supersedes the temporary-denial scope and UI in ADR 0053.

## Decision

Configure durable Denial Thresholds only in the main app’s Authorization Gates.
An Approval window offers temporary denial through the Deny button’s disclosure
only after two visible prompts for the same eligible Verified Launcher and
gate within thirty seconds. Clicking Deny still denies only the current request.

A temporary rule matches an exact designated requirement, gate ID, and threshold
in that gate’s existing operation ladder. Derive the threshold from the requested
operation, never the current allow policy. Unknown operations and requests without
a level ladder offer no action. A matching rule also denies Unknown operations,
as durable thresholds do. Rules never transfer to Direct Secret requests, Secret
Proxy requests, or Secret mutations without a level ladder.

Use a continuous two-minute deadline in memory. List active rules with scope and
remaining time in the menu bar, where the user can end each rule independently.
Cancellation targets the rule’s unique generation so an old menu action cannot
cancel a replacement. Neither ending nor expiry changes persistent policy or
approves requests. Overlapping rules remain independently effective.

History may offer the same scoped action only when a record explicitly stores
its eligible Launcher requirement and gate/threshold scope. Do not reconstruct
scope from historical display strings. Old records remain readable.

## Consequences

This deliberately narrows the previous global denial: unrelated gates and lower
operation levels continue through ordinary authorization. Existing denial checks
before queued Approval and before Secret release retain their precedence. Secret
Proxy and mutation paths retain their own existing authorization requirements.
Already released Secrets and running operations cannot be recalled.
