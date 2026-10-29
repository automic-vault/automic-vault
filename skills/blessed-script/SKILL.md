---
name: blessed-script
description: Write an Automic Vault Blessed Script, a reviewed script whose `av inject` shebang and Script Declaration name the Secrets and per-Gate Capabilities it needs, then ask the user to bless it with `av bless`. Use when the user wants to script or automate work that uses Automic Vault Secrets or hardened Tools (`gh`, `aws`, `docker`, Git signing), when the same reviewed task keeps needing Approval, or when `av bless` rejects a script.
---

# Making a Blessed Script

A Blessed Script is reviewed work that exits. The user reviews it once in
Automic Vault. The Blessing binds the script's canonical path, exact contents,
and complete Script Declaration. Changing any byte invalidates it.

You are the kind of code Automic Vault guards against: a process running with
the user's privileges. You may write the script and request review. The user
decides whether to bless it, which Capabilities it gets, and whether any
Launcher is endorsed.

## Choose the mechanism first

- Reviewed, bounded work that exits (deploy, release, publish): a Blessed
  Script. If it needs your input partway through, also read the
  `reentrant-blessed-script` skill.
- A long-running process or agent loop that keeps calling a Tool: not a
  Blessing. Use the hardened Tool and its Authorization Gate policy.
- One command, once: just run it and let the user approve it.

See [Choosing a Mechanism](https://github.com/automic-vault/automic-vault/blob/main/docs/choosing-a-mechanism.md).

## Steps

1. Write the script with its Script Declaration in the first lines (below).
2. Declare the least authority the script needs.
3. Make it executable: `chmod +x ./scripts/deploy`.
4. Run `av bless ./scripts/deploy`. Automic Vault opens a review for the user.
   Tell them what the script does and why each Secret and Capability is
   needed. `already blessed` means the reviewed contents are unchanged.
5. Run the file itself: `./scripts/deploy ARGS`. Running `bash ./scripts/deploy`
   skips the `av inject` shebang, so no Blessing or Secrets apply.

Do not pass `--endorse-launcher` unless the user asks for it. A Launcher
Endorsement lets the Verified Launcher that ran `av bless` (often your agent
harness) run this exact Blessing without Approval each time. Without it, each
run needs Approval to start, unless the script requests no Secret Names and
declares `capabilities: {}`, which grants no authority.

## Script Declaration

The format is line-exact. The approval service rejects variations.

```sh
#!/usr/local/bin/av inject +DEPLOY_TOKEN -- /bin/bash
# --- automic-vault
# capabilities:
#   gh: read-only
#   aws: write
# ---
```

Line 1 is the `av inject` shebang:

- The absolute path to `av` (normally `/usr/local/bin/av`), then `inject`.
- Zero or more `+SECRET_NAME`. A name starts with a letter or `_` and contains
  only letters, digits, and `_`. Check stored names with `av list`. If one is
  missing, ask the user to run `av save NAME`. Never ask for or handle a
  Secret Value yourself.
- Optionally `--replace-existing-env` or `--allow-missing-keys`.
- `--`, then the absolute interpreter path and its arguments. `--` is required
  when there are no Secret Names (`#!/usr/local/bin/av inject -- /bin/bash`).
  Always write it.
- FD delivery (`--mode=fd`) is not supported in a shebang.

Line 2 is exactly `# --- automic-vault`. Without this block the script uses
Capability Inheritance. Always include it.

Then exactly one of:

- `# capabilities: {}`: an empty capability ceiling. After the shebang's
  Secret Names are authorized, every later gated operation in this run needs
  Approval, whichever Launcher started it.
- `# capabilities:` followed by one `#   <gate>: <level>` line per Gate (`#`
  and three spaces). At least one line, each Gate once.
- `# capabilities: { inherit: true }`: keep the calling context's automic
  authority (outer Blessed Script, Launcher policy, Direct Access Rules,
  Temporary Access Grants). Use only when the user asks for it.

Close with `# ---`. The script must be UTF-8 and at most 1 MiB.

### Capabilities

A Capability is the maximum Access Level the script may receive through one
Authorization Gate. The Blessing does not cover gated operations at an
undeclared Gate or above the declared level; they normally need Approval. A
Capability grants nothing the Gate does not recognize: Unknown operations
always need Approval.

Gate IDs are Tool-specific, for example `gh`, `aws`, `docker`, `brew`. List
the hardener Gates with:

```sh
av hardeners --json | jq -r '.hardeners[].secret_gate.id // empty'
```

`gpg-signing` and `ssh-agent` are also Gates. `ssh-agent: trusted` permits
SSH authentication with the original SSH credential only, to any destination
that accepts it. `av bless` rejects an unknown Gate ID with
`unknown script capability`.

| Level | Access Level |
| --- | --- |
| `read-only` | Read Only |
| `local-write` | Local Write |
| `read-and-updates` | Read & Update (Homebrew) |
| `write` (alias `trusted`) | Write Access |
| `full` | Full Access, including Secret Disclosure and Elevated Secret Application |

Gates offer only the levels that fit their operations. Pick the narrowest
level that works. Do not declare `full` unless the user explicitly requires
it, and say why in your request.

Prefer a hardened Tool plus a Capability (`gh: write`) over a Secret Name in
the shebang. The Tool's Gate then checks each operation, and the script never
holds the raw Secret Value.

## Writing the body

- The script runs from a verified `/dev/fd/N` snapshot, so `$0` is not its
  path. Use `AV_SCRIPT_PATH` and `AV_SCRIPT_DIR` instead.
- Use `set -euo pipefail`. Never `set -x`: it can print expanded Secret Values.
- Secrets arrive as environment variables named after their Secret Names.
  Never echo, log, or write them to files or command-line arguments. Pass them
  only to the command that needs them.
- Validate every argument before using it. Use fixed repositories, buckets,
  and hosts instead of taking them from arguments.
- Name the interpreter by absolute path, not through `/usr/bin/env`, so the
  reviewed declaration says what runs. `/bin/bash`, `/bin/zsh`, and `/bin/sh`
  work. Apple's `/usr/bin/python3` and `uv` cannot run the snapshot: the user
  must choose **Bless Anyway**, and the script then runs from its canonical
  path with a warning on every run. Prefer a fixed Python build at another
  path.

## After blessing

- Editing the script, even a comment, invalidates the Blessing. Run
  `av bless` again and tell the user what changed. Never edit a Blessed
  Script to get past a denial.
- An Approval prompt or denial is a decision for the user, not a bug to work
  around. Report what the script was doing and wait.
- Quitting, restarting, or updating Automic Vault ends a running script's
  active Blessing authority and its memory-only capability ceiling, including
  `capabilities: {}`. Later gated operations in that run use ordinary
  authorization policy, such as Launcher policy, which may allow them or
  require Approval. Let running Blessed Scripts finish before Automic Vault
  quits, restarts, or updates.

## Reference

- [Blessed Scripts](https://github.com/automic-vault/automic-vault/blob/main/README.md#blessed-scripts)
- [Domain Language: Blessed Script](https://github.com/automic-vault/automic-vault/blob/main/docs/domain-language.md#blessed-script)
- [ADR 0005: Bind Reviewed Automation to Exact Scripts](https://github.com/automic-vault/automic-vault/blob/main/docs/adr/0005-reviewed-automation.md)
- [ADR 0039: Script Capability Inheritance](https://github.com/automic-vault/automic-vault/blob/main/docs/adr/0039-script-capability-inheritance.md)
