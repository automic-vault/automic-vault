# ADR 0076: CLI presentation settings with protected visibility controls

Status: accepted; catalog extended by [ADR 0083](0083-default-secret-availability.md).

## Context

Agents need a supported way to discover and adjust presentation settings.
Compact notifications change layout. Suppressing feedback or collapsing a
Temporary Access Grant strip changes the visibility of security activity even
though neither grants Developer Authority. Protecting only the CLI entry point
would leave a bypass through the existing same-user-writable defaults.

## Decision

Expose a closed catalog through `av settings list`, `get`, and `set`, with
`--json` on each command. The signed `av` Gate Client talks to the running app;
the app validates every key and value. The catalog contains only:

- `compact-notifications`: `true` (default) or `false`; directly writable.
- `automatic-authorization-feedback`: `notification` (default),
  `menu-bar-flash`, or `none`; changes require Approval.
- `auto-collapse-grant-strip`: `false` (default) or `true`; changes require
  Approval.

Reads need no Approval and disclose only these presentation values and their
schema. Authority settings, Launcher rules, Secret Names, and Approval-method
configuration are outside this interface. JSON returns an array of snapshots
with `key`, `value`, `defaultValue`, `acceptedValues`, and `requiresApproval`.
Values use their CLI string representation, including `true` and `false`.

Store the two visibility settings in the app's Data Protection Keychain using
the canonical access group. Stop reading their legacy UserDefaults keys. Do not
import those values: software running as the user could have written them.
Upgrading therefore restores notification feedback and the full grant strip
until the user chooses otherwise. Missing storage uses these defaults;
unreadable or malformed storage also keeps presentation visible, but settings
reads and mutations report an error instead of treating failure as a value.
Compact notifications retain their existing UserDefaults key and value.

CLI visibility changes use the normal per-request Approval presentation,
including configured iPhone and Touch ID surfaces, with the exact old and new
values. No durable grant, Temporary Access Grant, or decision reuse authorizes
these changes. Cancellation, changed Gate Client execution, failed live signing
validation, and unavailable human Approval prevent the mutation. Launcher Bundle
integrity checks still apply. Launcher attribution supplies review context;
human Approval may authorize an otherwise unverifiable Launcher.

The app's Settings controls use the existing authority-change Approval flow.
The explicit UI action supplies consent when neither iPhone nor Touch ID
Approval is enabled. Both paths compare the stored value against the reviewed
value and persist and verify an Authorization Record before changing visibility
settings. A changed value or recording failure prevents the write. Setting the
current value again is a no-op. Storage errors never report success.

## Consequences

An agent can make notifications compact without prompting, and can propose a
visibility change for human review. Direct defaults edits cannot suppress the
protected feedback or enable persistent strip auto-collapse. The warning tab,
orange shield, and End action remain available under ADR 0041. The existing
one-time UI action to collapse the strip remains unchanged.

This does not make presentation tamper-proof against root, prevent an agent
from operating pointer-driven UI when that Approval surface is enabled, or
change Authorization Policy. Existing users must choose quieter feedback and
auto-collapse again after upgrading.
