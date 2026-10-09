# ADR 0055: Explicitly allow individual Launcher helpers outside their parent bundle

Status: accepted; live executable verification refined by [ADR 0066](0066-live-helper-executable-validation.md); Claude Code default amended by [ADR 0062](0062-claude-code-outside-parent-default.md).

## Context

A vendor-signed helper may be moved or copied out of its parent app. The
containment requirement in ADR 0034 intentionally prevents that executable from
representing the app. Some users want to delegate the same Launcher authority
to that helper regardless of its installation path.

## Decision

Verified Launcher Helpers settings offers an “Allow outside the parent bundle”
checkbox for each association. It defaults off for new and existing records
and is not offered in the initial helper chooser. Enabling it uses the current
human Approval surface and explains the cross-gate expansion and loss of the
parent resource-seal check. Disabling it requires no Approval.

The choice is stored alongside the association in the Data Protection Keychain.
A disabled association remains disabled regardless of its relocation setting.
Malformed settings fail closed; a missing relocation field means no exceptions.

For an opted-in helper outside its resolved parent bundle, runtime verification
still requires the exact helper signing identifier and Team ID, Developer ID,
eligible runtime protections, valid live code, and equality of the live and
on-disk code identity. Launch Services locates the installed parent app; its
signed main executable and exact Developer ID association are verified before
its Launcher Identity is attributed. A missing or invalid parent cannot confer
authority. Helpers inside that parent bundle still require their original
relative path, when stored, and required unmodified resource-seal membership.

## Consequences

This explicitly broadens one association: any valid vendor-signed executable
with that helper identity can qualify outside the parent bundle, including a
copy or another vendor-signed version. The option does not prove the file was
historically moved from that app or pin it to the app's current helper version.
Code signing establishes identity and integrity, not intent. The user accepts
that scope through Approval; existing settings and initial enrollment retain
the containment requirement.

The parent app must remain installed. On systems without targeted resource
validation, complete-bundle validation remains the fail-closed fallback and may
reject an app whose sealed helper was removed.
