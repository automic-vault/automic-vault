# ADR 0020: Attribute app Launcher identity only to its main executable

Status: accepted

App validation scope was refined by
[ADR 0033](0033-targeted-app-launcher-validation.md).

## Context

A signed executable may live inside an app bundle without being that app's
Launcher. For example, Git supplied by Xcode runs from
`Xcode.app/Contents/Developer/usr/bin/git` between Terminal and `av-gpg`.
Treating every bundle-contained executable as the containing app made this
intermediary appear to be the Xcode Launcher and forced full validation of the
large Xcode resource seal before each signing Approval.

That attribution also conflicts with the existing definition of a Launcher as
the app or executable at the root of the operation's verified launch chain.

## Decision

An ordinary app bundle is a Launcher candidate only when the live process path
or its code-signing main executable matches the bundle's declared main
executable. Automic Vault then performs static code-signature and exact
executable resource validation before accepting that app as a Verified
Launcher.

Bundle-contained intermediary executables remain visible in the process chain
and retain their live code-signature and runtime-posture checks, but they do not
inherit the containing app's Launcher Identity unless they match an enabled
Verified Launcher Helper association. Each association positively identifies
both the app and helper by signing identifier and Team ID. A matching helper
must be the exact live executable and a required, unaltered member of the app's
resource seal. Disabled associations are persisted in the Data Protection
Keychain so same-user preference writes cannot enable them.

App and helper validation checks the app's signed executable without scanning
unrelated resources, then validates only the exact representing executable
against the app's resource seal. If the targeted macOS validation facility is
unavailable, validation falls back to the complete bundle seal. Existing
explicit rules for Automic Vault Launcher Bundle payloads and the Vaultty
session bridge remain unchanged. Eligible standalone Developer ID executables
retain their existing fallback identity.

## Consequences

Terminal, Portal, and other app main processes keep their existing app Launcher
identity with targeted executable validation. ChatGPT's signed, sealed Codex
helper can represent ChatGPT when its built-in association is enabled. The
built-in Claude Code association remains dormant unless Anthropic seals its
signed Claude Code executable inside the exact Claude app identity. Xcode's Git
does not match an association, so it neither claims Xcode Launcher authority nor
causes Xcode's complete resource seal to be scanned while authorizing a Git
signature. A helper without its app's main process in the live ancestry must
qualify under an enabled helper association, Launcher Bundle enrollment, or
standalone Launcher rules instead of inheriting ambient authority from its
containing app.
