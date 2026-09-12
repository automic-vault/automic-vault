# Secret Gate security audit

Date: 2026-07-14

## Incident finding

The reported AWS commands did not reach the approval helper. The unified log has no XPC connection or Authorization Record for either command. A reused PID Approval cannot explain that result: the transient key includes the PID, process start time, Launcher identity, exact operation, Secret Names, Target, arguments, working directory, flags, environment conflicts, script, and Tool. Reuse also writes an Authorization Record before returning secrets.

The terminal process visible after the incident started at 19:09:27, 21 seconds after the 19:09:06 screenshot. Its later `which aws` result and environment do not describe the incident shell.

Two paths reproduce the observed no-XPC/no-log signature:

1. The installed CLI honored `AUTOMIC_VAULT_TEST_KEYCHAIN_DIR` outside tests. Pointing it at a directory containing a file named for a requested key skipped XPC and loaded that file. The exact installed `/usr/local/bin/av` reproduced this bypass. No surviving process or file proves that the incident used it.
2. Calling `/opt/homebrew/bin/aws` directly bypasses the PATH wrapper. It can succeed if the process has any ambient AWS provider, including temporary environment credentials, a credential process, SSO/login state, container credentials, or instance metadata. No surviving provider explains the incident.

The available evidence rules out the approval cache and confirms a helper bypass. It does not distinguish the two paths above or a shell-resolution variation that disappeared when the terminal restarted.

## Execution matrix

| Path or variation | Result | Change |
| --- | --- | --- |
| Missing, unreadable, or malformed gate policy | Previously fell back to permissive behavior | Fail closed to Approval Required |
| Existing onboarding grants | Legacy Trusted Access was stored as an explicit choice | Preserve the stored grant under the Write Access label and persist every explicit default |
| Launcher identity unavailable | Resolver applied “All Other Apps” without knowing whether an override matched | Disable durable automic authorization and require Approval |
| Policy or human authorization | Reply could precede Authorization Record persistence | Persist and verify the record before returning secrets |
| Authorization History storage | Same-user processes could alter `UserDefaults` | Store production records in the app-private Data Protection Keychain |
| Transient PID Approval | Includes process birth time and complete request identity | No bypass found; every reuse remains recorded |
| Installed CLI test hooks | Release/copy could use test Keychain and path overrides | Accept test overrides only from debug binaries inside their Cargo profile |
| XPC server identity | Rust, GH, and Supabase clients checked an identifier only | Pin Apple anchor, team ID, and current app identifier |
| Keychain item group | Wildcard entitlement was first, so omitted `kSecAttrAccessGroup` stored items there | Write/query the private app-ID group and migrate verified legacy items |
| AWS profile selection | The credential helper and AWS CLI could use different profiles | Parse the command profile once and bind it to the registered process |
| AWS config/provider chain | Real AWS inherited HOME, config, credential process, SSO/login cache, metadata, and pager hooks | Run it with an empty HOME/config/credentials file, disabled metadata and pager, and scrubbed provider variables |
| AWS aliases and pager | Read-only argv could invoke a shell alias or external pager with credentials | Isolate config and force `--no-cli-pager` |
| AWS temporary files | Predictable PID-based pass path | Use a mode-0700 random directory and remove it on exit |
| AWS zsh startup | User `.zshenv` ran after long-term keys were injected | Invoke zsh with `-f`; use `/bin/sh` for the pass shim |
| GH/Supabase credential access | Signed clients request tokens over XPC and keep them in memory | No token environment inheritance found; peer verification tightened |
| Generic environment wrappers | `/bin/sh` exports approved values then execs the target | Shell startup is clean; the target and its children still receive the secret by design |
| Direct real executable | `/opt/.../bin/<tool>` remains callable without the wrapper | Architectural residual risk |

## Confirmed fixes

Automic Vault commits:

- `3482108` Fail closed when secret gate policy is unavailable
- `714e757` Record gate decisions before replying
- `0317818` Pin approval service to signing team
- `bd1661b` Isolate hardened AWS runtime
- `fddf4dd` Disable test keychain bypass in installed CLI
- `e9328d4` Fail closed when approval logging fails
- `4ac3fe2` Disable test overrides in installed CLI
- `5cd5b88` Migrate secrets to private keychain group
- `8d4a0d0` Skip shell startup files in AWS gate
- `4c3e734` Protect approval audit records in Keychain
- `e779532` Require launcher identity for auto approval

### Ungated trusted-client load

The follow-up review found that the approval service accepted a generic `load`
operation from the signed `av` Gate Client and returned an arbitrary existing
Secret without an Authorization Decision or Authorization Record. GitHub and
Argo CD migration code used the operation for comparison and compatibility.

The operation is removed. Equality and read-back verification now happen
inside the menu bar app and return only status. GitHub migration uses that
approved mutation path, and the legacy `ARGOCD_CONFIG_YAML` automatic migration
is retired. See [ADR 0010](adr/0010-no-ungated-secret-retrieval.md).

Isotope commits:

- GH CLI `d80395cbb` Pin approval service to signing team
- Supabase CLI `f2e0e5da` Pin approval service to signing team

## Residual risks

### Wrapper bypass

Secret Gates shadow commands on PATH; they do not mediate `exec`. A process can run the underlying Target directly. Vault-managed credentials should remain unavailable, but any ambient provider can still authorize the direct process. Closing this boundary requires moving the Target behind an access-controlled Launcher or adding execution mediation such as Endpoint Security. Doctor can detect PATH order but cannot prevent an absolute-path call.

The AWS Hardener no longer uses Homebrew's mutable Python distribution as its
credential-bearing Target. It verifies and extracts AWS's signed, notarized,
Hardened Runtime release under `/opt/av/aws`; binds helper registration to the
installed launcher generation; and rejects Homebrew helper use after migration.
This improves Target integrity but does not change the general PATH-wrapper
limit above.

### Generic Write Access

Generic wrappers apply a Secret to the Target process. The Target can load plugins, invoke helpers, or expose its environment. Automic Vault cannot identify every sensitive secret operation for an arbitrary third-party CLI from arguments alone. Write Access therefore trusts the Target's complete runtime, configuration, and child-process behavior for recognized writes. Approval Required or per-command Approval is the defensible setting for an untrusted Launcher.

### Keychain migration

The single-user migration completed on 2026-07-14. The signed transitional build copied each legacy item, verified the bytes in the private group, deleted the old item, and verified that the wildcard group was empty. Production source now signs only for `ZU76A67LGU.com.automicvault`; the wildcard entitlement and migration helper have been removed.

### Authorization History scope

Authorization History records are AES-GCM encrypted with a key in the app's
Data Protection Keychain access group. Allowed requests fail closed if their
committed record cannot be authenticated, decoded, and compared with the
expected record. Retention is bounded to 30 days and 25 MiB of encrypted
payloads; the dashboard shows the newest 50. This is not a remote, append-only,
or complete forensic log. Denied and failed requests remain best effort because
they never receive a Secret.

### Deployment

Rebuild and install all affected artifacts together. Mixing the new isotope clients with the old `com.automicvault.menu-helper` app identifier will fail closed at XPC peer verification.
