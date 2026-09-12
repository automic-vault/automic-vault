# Authorization Gates and Approval

An Authorization Gate classifies the complete operation and applies its default
Access Level or a rule for the requesting Verified Launcher. Policy may allow a
recognized operation; you decide requests that need Approval.

## Access Levels

Each gate offers the Access Levels that describe its operations:

1. **Approval Required:** Automic Vault asks for Approval on every Secret Use or
   gated execution request.
2. **Read Only:** Automic Vault automically authorizes recognized reads.
3. **Read & Update:** Automic Vault automically authorizes Homebrew reads and
   `brew update`.
4. **Local Write:** Automic Vault automically authorizes recognized reads and
   local-only writes where the Tool supports this distinction.
5. **Write Access:** Automic Vault automically authorizes recognized reads and
   writes. Disclosure and elevated application still need Approval.
6. **Full Access:** Automic Vault may automically authorize recognized sensitive
   operations. Unknown operations still need Approval.

The GPG Signing Gate offers **Approval Required** and **Allow Signing**. The
Direct Secret Gate defaults to **Approval Required** and offers explicit
[Direct Access Rules](direct-secret-access.md) for exact Secret Names.
See the canonical [Access Levels](domain-language.md#access-levels) for the full
mapping; these presets are not a universal ladder shared by every gate.

## Approval While Locked

Mac-local Approval requires an active user session and awake displays. Automic
Vault aborts pending Mac-local approvals when either becomes inactive.
Policy-authorized requests may continue only if every requested Secret has
**Available While Locked** enabled.

iPhone Approval lets a request wait for a human decision while the Mac session
is inactive or its displays sleep. The originating process must remain alive,
and Secret Availability still applies. AWS MFA entry remains Mac-local and
requires an active session and awake displays.

### Remote work from a locked Mac

iPhone Approval does not unlock the Mac's Keychain. A Secret configured as
**When Unlocked** stays unavailable while the Mac is locked, even if you can
approve on your phone. Automic Vault may reject the request before it reaches
Approval, so you receive no phone notification. A missing notification alone
does not establish a relay or phone problem.

To let a remote agent use a particular Secret while the Mac is locked:

1. Unlock the Mac and open Automic Vault with `av open`.
2. Open **Secrets**, select the Secret, and enable **Available While Locked**.
   Repeat for each Secret the operation needs. For GitHub, check the relevant
   `GH_TOKEN_…` account and host entries.
3. Keep iPhone Approval enabled if you want to approve remotely, then retry a
   read such as `gh auth status` from the same remote agent while the Mac is locked.

This choice makes all Values of that Secret available after the first unlock
following a restart. Enable it only for Secrets needed by your remote workflow.
The Secret Gate still verifies and authorizes every operation; policy may allow
a recognized read without prompting, and a request that needs Approval goes to
an eligible iPhone. The Mac and originating process must keep running.

Unlock the Mac for login or credential changes that fail with Keychain error
`-25308`. Saving Secrets requires a complete inventory, which may be unavailable
while locked even when a particular Secret allows use while locked. Some app
versions also report an unavailable GitHub Secret as an "invalid token"; retry
while unlocked before treating this as an expired or revoked GitHub token.

See the canonical [Secret Availability](domain-language.md#secret-availability)
definition for the storage and authorization boundaries.

## iPhone Approval

iPhone Approval is optional and enabled per Mac. Once enabled, every human
Approval for that Mac moves to eligible iPhones on the same iCloud Keychain
account. The Mac shows the request and its cancellation state without a pointer-
or keyboard-driven allow action. If you separately enable Touch ID Approval,
either a valid phone response or Touch ID on that Mac may carry the Approval.

The Mac remains the Local Execution Boundary. It verifies the complete
Authorization Request, rejects stale or mismatched responses, persists the
Authorization Record, and enforces the final decision. The iPhone never
receives Secret Values or Authorization History.

To enroll:

1. Sign in to the same iCloud account on the Mac and iPhone, with iCloud
   Keychain enabled.
2. Open Automic Vault on the iPhone, tap **Enable iPhone Approval**, and allow
   notifications.
3. On the Mac, open **Settings → iPhone Approval** and click
   **Enable iPhone Approval**.

If you will use an agent while the Mac is locked, also configure
[Secret Availability for remote work](#remote-work-from-a-locked-mac).

Routine requests can offer **Approve Once** in an authenticated notification.
Requests with Unknown operation risk, Secret Disclosure, Unconstrained Secret
Application, or a security warning require review in the full app. Face ID or
Touch ID is optional and configured on each iPhone. When enabled, a passcode,
Apple Watch, or companion Mac cannot substitute for biometrics on that phone.

Every iPhone enabled on the account can carry Approvals. The initial release
has no per-device pairing or revocation; emergency recovery invalidates the
whole account enrollment.

> [!WARNING]
> iPhone Mirroring and **Show on Mac** can put Approval controls back onto a Mac
> when biometric protection is off. Disable those features wherever an agent
> can control the Mac, or require Face ID or Touch ID on every eligible iPhone.

If no phone or relay is available, the request waits until its Gate Client
cancels, unless you already enabled Touch ID Approval and approve on that Mac.
Relay failure never enables another Approval surface. Emergency recovery
from the Mac requires system authentication, cancels pending requests, rotates
the iCloud key, and invalidates every enrolled iPhone and Mac on the account.

An iPhone needs an active, App Store-verified iPhone Approval subscription to
send an allow response. Denial does not require a subscription. Each enrolled
Mac keeps its own Secret Custody, policy, enforcement, and Authorization History.

## Touch ID Approval

Open **Settings → Touch ID Approval** and select **Enable Touch ID Approval**.
Enrollment requires the current human Approval surface and Touch ID on that Mac.
Disabling it removes the surface immediately.

Every allow action requires a fresh biometric result for the exact request.
A password, passcode, Apple Watch, pointer, or keyboard action cannot substitute.
Touch ID requires an active Mac session and awake displays. It may coexist with
iPhone Approval: the first valid result wins and cancels the other pending
transport. Relay availability never changes this choice.

## Temporary Access Grants

When an eligible Codex task or Claude Code session requests a write, the
Approval window can offer **Allow Write Access for 10 Minutes…**. Automic Vault
stores the Temporary Access Grant in memory and binds it to the Verified
Launcher, Tool-specific gate, runtime posture, and current agent task.

The persistent strip shows every grant and lets you add ten minutes, suspend or
resume its active-time countdown and Write Access, or end it early. Automic
Vault also revokes grants when the user session becomes inactive, displays
sleep, an update begins, or the app stops.

The Verified Launcher remains the identity boundary. The task identifier is a
forgeable label that narrows the grant. Temporary Access Grants exclude the
Direct Secret Gate, Secret mutations, Elevated Secret Application, Secret
Disclosure, and unknown operations.

An optional setting collapses the strip after five seconds into a visible
warning tab. The menu-bar shield stays orange, and the menu keeps each grant
and its End action available.

## Authorization History

Automic Vault keeps local records of allowed and denied requests, including the
operation, software identities, Secret Names, and decision source. It persists
and verifies an allowed Secret Use's Authorization Record before releasing the
Secret. Failure to record that use denies release; denial and failure records
are best effort.

Authorization History is bounded local operational history. Same-user compromise
or storage failure can damage it. It provides neither tamper resistance nor a
complete forensic log. The iPhone's separate Request History records only what
that phone observed and does not prove that a Mac accepted a response.

The Mac retains up to 30 days or 25 MiB of encrypted record payloads, whichever
limit comes first. The dashboard and `av history` show the newest 50 records by
default. Use `av history --since 7d` to request a specific window, and add
`--json` for machine-readable, display-safe output. History access requires
Approval unless the exact Verified Launcher has Authorization History Access.

See the [Domain Language](domain-language.md) and [Architecture](architecture.md)
for the authoritative terms and security boundaries.
