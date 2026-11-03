# Stable ib signing identity

Supersedes the per-build hash admission in ADR 0079.

The installer signs ib using Developer ID Application for team `ZU76A67LGU`,
identifier `dev.mxcl.ib`, Hardened Runtime, and no entitlements. AV verifies
that fixed identifier, team, Apple anchor, Developer ID intermediate, and
Developer ID Application leaf. An arbitrary signer or ad-hoc signature cannot
claim this identity. A new build by the same signer remains eligible without
restarting AV; certificate renewal within that team does not pin a build hash.

Root-owned schema-2 enrollment retains the package UID/GID. Protected directories,
executable ownership/mode, live audit-token identity, runtime protections,
post-Approval revalidation, and approval-only execution authority remain required.
The stable listener rule admits connections even before installation, but missing
or invalid enrollment denies every request. No Secret API access is granted.

Signing happens before elevation, using the installing developer's Keychain.
The privileged installer verifies the copied signature before publication.
Local source installation requires the project signing identity; there is no
ad-hoc fallback. The worker remains ad-hoc signed and cannot act as Gate Client.

This deliberately trusts future builds from the project signer rather than
requiring root to enroll every hash. Root still controls installation and the
package account. Migration requires installing the updated AV app once and
rerunning ib's installer. Old enrollment and old clients fail closed.
