# ADR 0034: Require explicit approval for discovered Launcher helpers

Status: accepted

## Context

Applications often ship separately signed command-line helpers or login-item
apps that perform the same operations as the containing product. These helpers
may run without the app's main executable in their live ancestry, so the rule
established for the app does not match them. Requiring a separate rule for each
implementation component exposes packaging details and often conflicts with the
user's intent.

Automatically attributing every bundle-contained executable to the app is not
acceptable. Development apps may contain unrelated tools, plug-ins, runtimes,
and utilities. A shared Team ID or bundle location establishes neither intent
nor the scope the user meant to authorize.

## Decision

When the user adds an app as a Verified Launcher at an Authorization Gate,
Automic Vault may inspect the app for separately signed executable helpers. The
inspection is discovery only and runs outside the main actor. It excludes the
app's declared main executable and offers only helpers whose exact signing
identity can be read and whose executable is a required, unmodified member of
the app's resource seal.

Automic Vault presents the discovered helpers unselected. The user may select
individual helpers and must see a warning that each enabled association makes
that helper represent the app at every Authorization Gate where the app has a
current or future Launcher-specific rule. Adding an association is an authority
change and uses the configured human Approval surface.

The positive catalog combines reviewed built-in associations with exact
user-approved associations stored in the Data Protection Keychain. Each
association binds the app bundle identifier and Team ID to the helper signing
identifier, Team ID, and exact relative path inside the app. Runtime
authorization continues to verify the live helper, bind it to that on-disk
executable, validate the app's signed executable, and validate the helper
against the app's resource seal. Discovery results, paths, containment, and
Team IDs alone never grant authority.

A malformed stored configuration disables every helper association. A user may
disable an association without deleting any Launcher-specific policy rule.

## Consequences

Apps with intentional background or CLI components can share one reviewed
Launcher Identity without restoring blanket bundle inheritance. The user sees
the authority expansion at the moment it is relevant and can decline it.

Large apps may contain many signed executables, so discovery can add latency and
must remain cancelable and off the main actor. Associations are global rather
than gate-specific; the warning must not imply that the helper is limited to the
gate where it was discovered.
