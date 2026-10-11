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

The GPG Signing Gate offers **Approval Required**, **Allow Signing**, and **Deny**.
Each SSH credential has its own gate with **Approval Required**,
**Allow Authentication**, and **Deny**. Authentication can permit remote writes. The
Direct Secret Gate defaults to **Approval Required** and offers explicit
[Direct Access Rules](direct-secret-access.md) for exact Secret Names.
See the canonical [Access Levels](domain-language.md#access-levels) for the full
mapping; these presets are not a universal ladder shared by every gate.

## Default Policy and denial

Each gate's **Default Policy** combines its default Access Level with an optional
Denial Threshold. Launcher-specific rules can set their own allow and deny
boundaries. Operations above the allow level need Approval unless a denial
applies. A Denial Threshold blocks its selected level and everything above it
without offering Approval. **Unknown only**, where available, blocks unclassified
operations without denying recognized ones.

Explicit matching denials take precedence over allow rules, Blessings, Temporary
Access Grants, and reused decisions. A denial-only Launcher row uses the default
allow level but has its own denial. Adding a rule that weakens default denial,
or weakening an existing denial, requires Approval.

The default denial applies when no Launcher-specific record matches an attributed
Launcher, even if no Launcher can be verified. SSH uses the nearest Verified
Launcher for this check; an upper ancestor's rule cannot suppress default Deny.

## Descendant Launcher rule overrides

Normally, the nearest Verified Launcher with an explicit Access Level supplies
policy. Intermediaries without an explicit Access Level do not displace that rule.
For example, at the GitHub gate:

```text
Terminal (Write Access) → agent (Read Only) → gh issue create
                         ^ agent rule: Approval required
```

To make a harness supply its rule for Launchers it starts:

1. Open **Authorization Gates** and select the relevant gate.
2. Add or select the harness's Verified Launcher rule and choose its Access Level.
3. Enable **Override descendant Launcher rules** on that row.
4. Choose **Review Changes** and approve the change.

The choice applies to that Launcher at that gate only, and defaults off for new
and existing rules. A denial-only row cannot supply an override. If several
verified ancestors enable it, the outermost eligible override wins.

| Harness rule with override enabled | Agent rule | GitHub write under Launcher policy |
| --- | --- | --- |
| Read Only | Write Access | Requires Approval |
| Write Access | Read Only | Automic authorization, with an override warning |
| Write Access | Deny | Denied |

These examples assume valid live identities and runtime protections, a recognized
write, and no other denial or independent authority source. An override replaces
the selected Launcher Access Level; it is not a ceiling on all authority. Direct
Access, Blessings, and Temporary Access Grants keep their own scope and rules.

Automic Vault requires live original-parent execution evidence connecting the
ancestor to the nearer Launcher. A helper alias for the same process or Retained
Launcher Provenance alone cannot prove that relationship. Missing override
evidence requires Approval instead of falling back to a potentially broader
child rule. Runtime requirements on overridden explicit rules still apply, and
all matching explicit denials remain vetoes. Unknown operations still require
Approval unless denied.

Both enabling and disabling require Approval. Removing an enabled override rule
also requires Approval: removing a restrictive parent rule can expose a child's
broader access. Launcher Bundle replacement or removal cannot silently clean up
an enabled override; remove its rule through the gate's reviewed flow first.

Authorization History and automic notifications warn when an override permits an
operation that an overridden explicit rule would have sent to Approval. Check
the decision source and warning when verifying your setup.

SSH retains its nearest-Launcher boundary: without an explicit rule there, an
ordinary ancestor rule does not supply fallback access. An approved ancestor
override can supply an Access Level, but cannot suppress default Deny for a nearest
Launcher with no explicit rule. Each SSH key's gate evaluates this separately.

See [ADR 0065](adr/0065-descendant-launcher-rule-overrides.md) for the security
invariants and [Signed CLI Launchers](signed-cli-launchers.md) for eligibility.

## Temporary Launcher Denial

After two Approval presentations for the same eligible Launcher and gate within
thirty seconds, the Mac Deny menu and full iPhone app offer a two-minute denial
at the requested operation level and above. You must select it; repeated prompts
never activate it on their own. Unknown operations do not offer this action.

The denial follows that Launcher at that gate, blocks new matching requests,
and leaves already released Secrets untouched. End it from the Mac menu bar,
let it expire, or restart the service to return to ordinary policy. Expiry does
not approve a request. Use a durable Denial Threshold for a lasting rule.

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

## Reviewing the execution chain

The Approval window shows the available process path, code-signing status, and
runtime posture, including observed ancestors above the selected Launcher.
Those extra ancestors provide diagnostic context; their presence in the display
does not grant authority. A signed interpreter does not authenticate the scripts,
dependencies, or plug-ins it loads.

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

The Mac stores separately encrypted records in one SQLite database in
Application Support. The encryption key stays in the Data Protection Keychain.
The rolling store makes up to 30 days of encrypted record payloads available,
with a configurable 1–1024 MiB payload retention target (25 MiB by default).
Periodic maintenance enforces the target; temporary overshoot is allowed.
SQLite overhead is additional. The dashboard browses all retained
records by day; `av history` shows the newest 50 by default. See the
[canonical definition](domain-language.md#authorization-history).

```sh
av history
av history --since 7d --json
```

`--since` accepts whole-number seconds, minutes, hours, days, or weeks (`s`,
`m`, `h`, `d`, `w`), up to 30 days. `--json` returns machine-readable records
with display-safe commands, never Secret Values. The full retained window is
retrieved automatically, even when it exceeds one transport reply. The successful
read is itself recorded and included in the response.

Tables shown in a terminal open in the system pager: use arrow keys to navigate
and `q` to quit. `--no-pager` writes directly. JSON, pipes, and redirected output
always bypass the pager; JSON remains one complete array. A failed retrieval
returns a nonzero status without printing partial history. Older running apps
must be updated to support complete-window retrieval.

Each read requires Approval unless its exact Verified Launcher has
Authorization History Access in Settings. This grant has its own setting row;
Secret Name Access for `av list` does not grant history access, or vice versa.
An unverifiable Launcher cannot use the automatic grant and needs Approval.
The menu bar app filters records before returning them to `av`.

On records with the required gate and Launcher metadata, **Configure Launcher…**
opens the exact rule after reverifying the installed Launcher. If no rule exists,
it opens the reviewed creation flow; opening it grants no authority. Older records
may not offer this action.

Migration leaves older Keychain and UserDefaults history in place to avoid
deleting an older helper's concurrent write. Those pre-existing copies can
outlive the rolling store's limits; they are not part of its retention guarantee.

See the [Domain Language](domain-language.md) and [Architecture](architecture.md)
for the authoritative terms and security boundaries.
