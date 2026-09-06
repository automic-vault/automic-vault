# Choosing a Mechanism

Automic Vault gates access to your credentials: before code can use a stored
secret, or perform certain sensitive operations, it needs authority over that
complete operation, not just an identity check. It offers several mechanisms
for granting that authority, each suited to a different situation. This guide
starts from your situation and points at the mechanism that fits, then links
to the doc or README section with the full detail.

See [Domain Language](domain-language.md) for precise definitions of every
term used here.

## Start here: what are you trying to do?

| Your situation | Use | Why |
| --- | --- | --- |
| "What on this machine could leak a credential?" | `av scan` (**Detectors**) | Read-only audit. Produces Findings with mitigations; changes nothing. |
| "I want to protect a tool I already use (`gh`, `aws`, `docker`, etc.)" | `av harden <tool>` (**Hardened Tools**) | Creates a Tool-specific **Authorization Gate** that understands that tool's operations (read/write/disclosure/elevated/unknown). This is almost always the right first move for a supported tool. Hardened State isn't itself a safety guarantee, it's what makes the gate's policy apply. |
| "Did hardening actually take effect?" | **Doctor** | Verifies Automic Vault's own installed protections (identity, ownership, permissions, content manifest, command resolution). Different from Detectors, which look at your environment, not Automic Vault's work. |
| "I have a one-off script that does reviewed work and then exits" | **Bless** it (`av bless`) | Binds a Blessing to the script's exact path and contents. Editing the script invalidates it, so review stays current. A multi-step task can still fit this: a reentrant Blessed Script does one step, exits, and picks up where it left off on the next invocation. |
| "I have a long-running process or agent that repeatedly calls a supported tool" | **Hardened Tool** + Authorization Gate policy, not a Blessing | Blessed Scripts (reentrant or not) still work by exiting between steps; a Tool Authorization Gate's Access Level policy is the right control for something that stays running continuously, not just bounded step by step. |
| "My app reads a secret from an env var at startup, and its HTTP client can use a supplied proxy and CA (Node 24+ with `--use-env-proxy`, or another compatible client)" | **Secret Proxy** (`av proxy`) | The app gets a random Secret Reference instead of the real value. No raw Secret value ever lands in the launched Target's environment; the proxy applies the real value only to approved outbound HTTP destinations. The Secret Reference and Proxy Credential are still bearer values for that session, not a guarantee the app can't request Secret Application at all. |
| "I need a secret directly via `av inject` and none of the above fits" | **Direct Secret Access** | Broadest and least preferred option: it grants one Launcher access to one Secret Name across any Target and arguments it chooses, though it still can't disclose the raw Secret, list Secret Names, or change Secrets. Prefer hardening, blessing, or the proxy first, see [Direct Secret Access](direct-secret-access.md#safer-alternatives). |
| "My CLI tool isn't code-signed, so Automic Vault won't treat it as a Verified Launcher" | **Launcher Bundle** | Wraps the unsigned executable so macOS (and Automic Vault) can verify its identity. It's an identity artifact, not a gate or a grant of authority by itself, see [Signed CLI Launchers](signed-cli-launchers.md). |
| "What has Automic Vault allowed or denied recently?" | **Authorization History** | Local, bounded log of Authorization Requests and Decisions. Not tamper-proof or a complete audit trail. |
| "An eligible agent task needs write access to an already-hardened tool for a few minutes, not a standing rule" | **Temporary Access Grant** | Offered inline in an Approval prompt for eligible agent tasks (Codex, Claude Code): ten active minutes of Write Access scoped to one Tool-specific gate, Verified Launcher, and runtime posture. It's not general secret access; the Direct Secret Gate, Secret mutation, Elevated Secret Application, Secret Disclosure, Unknown operations, and unverifiable Launchers stay excluded. |

## The two axes that matter

Most of the confusion is really two separate questions:

1. **Does this code already have a verifiable identity?** A signed app or an
   official vendor binary does. An unsigned, compiled single-file CLI you
   downloaded does not, and needs a **Launcher Bundle** before it can become
   a Verified Launcher at all. A script is different: Automic Vault doesn't
   support wrapping scripts in a Launcher Bundle at all, so a script gets its
   authority from a **Blessing** instead. A Blessing binds to the script
   itself (its path, contents, and declared capabilities); a separate
   Launcher Endorsement then names which Verified Launcher may run that
   Blessing automically.
2. **Is the work bounded step by step, or continuously running?** Reviewed
   work that exits at each step (a deploy script, a release script, even a
   multi-step reentrant script that pauses for agent input between runs)
   fits a **Blessed Script**, bound to its exact contents. A process that
   stays running and makes many calls over time fits a **Hardened Tool**'s
   Authorization Gate instead, so policy governs each call, not a one-time
   content match.

Identity and duration are independent: you can have a signed app (no bundle
needed) running long-lived (gate, not blessing), or an unsigned compiled CLI
(needs a bundle) that exits after one reviewed run (blessing).

## Typical end-to-end flow

```sh
av scan                    # 1. see what's exposed
av harden gh                # 2. protect a supported tool
av doctor gh                 # 3. confirm hardening took effect
av save API_TOKEN            # 4. store a secret you need directly
av bless ./scripts/deploy    # 5. (optional) review a script that uses it
av proxy +API_TOKEN -- node app.js   # 6. (optional) hand a secret to an app via reference only
```

Steps 4 onward are situational. Most users only ever need 1 through 3 for
their supported tools, and reach for Blessed Scripts, the Proxy, or Launcher
Bundles only when a specific tool or workflow doesn't fit the built-in
Hardeners.
