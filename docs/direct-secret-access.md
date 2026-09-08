# Direct Secret Access

Direct Secret Access lets one Verified Launcher use one exact Secret Name in
future direct `av inject` requests without asking for Approval each time.

This is intentionally not the preferred way to use Automic Vault. The Launcher
may select any Target and arguments, and the Target receives the Secret. Code
signing establishes the Launcher's identity and integrity; it does not prove the
Launcher's intent or make the selected Target trustworthy.

## Safer alternatives

Choose the narrowest option that works:

1. **Harden the Tool.** A Tool-specific Secret Gate recognizes its Target and
   operations, allowing policy to distinguish read-only work, writes, elevated
   credentials, and Secret Disclosure.
2. **Bless an exact script.** A Blessing binds the script’s canonical path,
   contents, declared Secret Names, Target, injection options, and Gate
   capabilities. A Launcher Endorsement can then authorize that reviewed script.
3. **Approve each request.** Approval binds one complete request and live process
   and creates no durable delegation.

Direct Secret Access is appropriate only when commands must be selected
dynamically, no suitable Hardener exists, and an exact Blessed Script is too
restrictive.

## Blessed Script lifecycle

Automic Vault keeps a running Blessed Script's active execution state in
memory. Quitting, restarting, or updating Automic Vault ends that state, even
if the script continues running and its Blessing remains valid. Later gated
operations from that execution require fresh Approval.

Wait for running Blessed Scripts to finish before quitting, restarting, or
updating Automic Vault.

## What a rule permits

A Direct Access Rule binds:

- one exact Secret Name;
- one designated requirement for a Verified Launcher; and
- direct `av inject` Secret Application.

It does not permit listing Secret Names, reading a raw Secret from Automic Vault,
changing or deleting Secrets, using sibling Launchers, or bypassing another Gate
Client’s policy. A request for several Secrets is automically authorized only
when the same Verified Launcher has a rule for every requested Secret Name.

The live Launcher must continue to pass code-signature, identity, Hardened
Runtime, and entitlement checks. A path, filename, icon, process identifier, or
bundle display name is not an identity.

## Adding and removing access

Select a Secret in the Automic Vault app and use **Allow Launcher** under Direct
Secret Access. The app requires a fresh acknowledgement every time, verifies the
selected signed app or executable, and shows the identity before saving it.

Remove a Launcher from the same Secret to revoke the rule. Renaming or deleting
the Secret also revokes every Direct Access Rule for that Secret Name.

All allowed uses still require a persisted Authorization Record before Automic
Vault releases the Secret.

## Apply Secrets through file descriptors

For a consumer that reads credentials from file descriptors:

```sh
av inject --mode=fd +FOO:3 +BAR:4 -- /bin/foo
```

Each mapping supplies the exact stored UTF-8 bytes through its own anonymous
pipe, followed by EOF. There is no bundle format, trimming, or added newline.
The consumer must know which descriptor to read for each Secret. The requested
Secret Names are removed from its environment, including any existing values.
Other invocations keep the default environment delivery (`--mode=env`).

FD delivery requires Approval for every invocation, even when a Direct Access
Rule or Blessing exists. The Approval shows the mappings and selected Global or
Project Values; Authorization History records them before release. Keep the app
and CLI updated together: older apps reject this delivery operation.

Descriptors must be distinct, unused, canonical decimal integers of 3 or higher;
stdin, stdout, and stderr are preserved. Duplicate Secret Names, omitted mappings,
missing Secrets, `--allow-missing-keys`, `--replace-existing-env`, and FD shebangs
are rejected. If any Value exceeds the available kernel pipe buffer capacity,
the command fails without starting the Target. FD delivery preserves bytes already
stored; it cannot recover whitespace removed by an earlier import.

The Target can copy the bytes or pass its read descriptors to children. Pipes
avoid a named plaintext file and Secret environment injection; they do not make
the consumer trustworthy or provide encrypted backup/recovery.
