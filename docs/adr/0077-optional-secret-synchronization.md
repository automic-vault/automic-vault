# ADR 0077: Optional Secret synchronization through iCloud Keychain

Status: accepted

## Context

Issue #175 proposes reusing Secrets on multiple Macs without an Automic Vault
account or synchronization service. Synchronization expands custody beyond one
Mac. It must be an explicit user choice, independent of local authorization.

## Decision

Offer iCloud Keychain synchronization in each Secret's detail view. New Secrets
remain local-only. The user reviews a warning covering all Values, trusted
devices, eventual delivery, concurrent changes, and remote deletion. Both enable
and disable use the existing authority-change Approval flow, honoring configured
iPhone and Touch ID surfaces. With neither enabled, explicit confirmation is the
human decision. Compare the reviewed attributes with current inventory and
persist and verify an Authorization Record before changing custody. No CLI,
policy, or Temporary Access Grant can enable synchronization.

Use `kSecAttrSynchronizable` on the existing Data Protection Keychain Value items
in the app's existing private access group. Never copy Secret bytes into
preferences, a synchronization service, or the Approval transport. Keep the
existing When Unlocked / After First Unlock availability. Do not use a
ThisDeviceOnly accessibility class for synchronized items. Policy, enrollment,
configuration, Approval preferences, history, and the mutation journal retain
their existing storage and do not join Secret synchronization.

Inventory explicitly includes local and synchronized items. Exact Value reads
bind the synchronization class selected before authorization. A disappearing
selected item fails rather than falling back. Duplicate local/synchronized
items for the same source fail inventory; mixed synchronization settings fail
Secret selection. If complete inventory is unavailable while locked, the availability-filtered
fallback is allowed only after an unfiltered query proves there are no
synchronized Values. A store containing synchronized Values may therefore
require unlocking even for an Available While Locked Value; incomplete
inventory must not hide a conflicting source.

Saving or migrating a Value inherits the existing Secret's
setting and rejects mixed custody. New names default to local-only. Renames,
availability changes, and deletion support synchronized Values too.

The local forward-repair journal records the exact reviewed Value accounts and
the desired setting before updating attributes in place. Recovery touches only
those accounts, skips Values already changed, and verifies resulting attributes
before clearing the journal. It never recreates a removed Value or enrolls a
newly arriving source. Affected Secret Names remain blocked while repair is
pending. If concurrent arrivals leave mixed settings, use the Secret's explicit
synchronization control to reconcile all currently reviewed Values. Same-source
duplicates require resolving the conflicting Keychain items; the app never
chooses or overwrites one arbitrarily.

## Consequences

Apple owns transport and conflict resolution. There is no cross-device
transaction, conflict history, delivery receipt, or synchronized local mutation
journal. The displayed state is configuration, not a claim of completed delivery.
Users should avoid simultaneous edits. Older app versions do not query
synchronized items; update each Mac before enabling this feature.

Updates, renames, availability changes, and deletions can affect other devices.
Turning synchronization off makes the local Values non-synchronizable and may
propagate removal of synchronized copies. It cannot revoke copies already
received or used. This is not a remote wipe guarantee.

Project Directory paths are unchanged. Missing directories are displayed as
missing; no directories are created and no paths are remapped. A Project Value
becomes selectable when the same physical canonical path exists. Existing
Global Value selection rules continue to apply elsewhere.

Synchronization creates no Authorization Policy. A receiving Mac's existing
name-based policy can authorize the incoming Secret. Integration configuration
and hardening remain local; syncing a credential alone does not configure its
Tool. The iPhone Approval companion does not gain the Mac's Secret access group.

## Validation

Unit tests cover default-off state, mixed-custody denial, changed-inventory
rejection, recording-before-mutation, recording failure, no-op behavior, and
explicit reconciliation. An entitled Keychain integration test covers enable,
read, inherited Project Values, conditional save, availability, rename, and
disable using synthetic Values in a unique service.

Before release, validate with signed builds on two Macs: enable and receive;
replace and delete; simultaneous edits and name collisions; interrupted
multi-Value changes; locked-device availability; iCloud disabled/offline; and
opt-out. Confirm that policy, enrollment, history, and integration configuration
remain local. Unit tests cannot establish iCloud delivery behavior.

## References

- [Issue #175](https://github.com/automic-vault/automic-vault/issues/175)
- [Apple: kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [Apple: kSecAttrSynchronizableAny](https://developer.apple.com/documentation/security/ksecattrsynchronizableany)
- [Canonical domain language](../domain-language.md#secret-synchronization)
