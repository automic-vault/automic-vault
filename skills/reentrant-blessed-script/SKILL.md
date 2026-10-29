---
name: reentrant-blessed-script
description: Write or follow an Automic Vault reentrant Blessed Script, a reviewed script that does deterministic work until it needs agent input, prints a prompt, exits, and continues when invoked again. Use when a release, deploy, or other multi-step workflow that uses Automic Vault Secrets or hardened Tools needs your judgment partway through (release notes, a changelog, a choice), or when a Blessed Script printed instructions for you and exited.
---

# Making a Reentrant Blessed Script

A reentrant Blessed Script splits work between reviewed code and you. The
script does every gated step. When it needs agent input, it prints a prompt
and exits. You produce the input, then run the continue command it printed.

Automic Vault authorizes every invocation separately. You never need to run
the underlying Tools yourself.

Read the [`blessed-script`](../blessed-script/SKILL.md) skill first. Everything
there applies: Script Declaration syntax, least Capability, `av bless`, and
never editing a Blessed Script to get past a denial. If it is not installed,
read it at
<https://github.com/automic-vault/automic-vault/blob/main/skills/blessed-script/SKILL.md>.

## Following one

1. Run the command you were given.
2. If it prints a prompt and exits, produce exactly the output it names. For
   context, run only the `agent:` subcommands it lists.
3. Run the exact continue command it printed.
4. Any other failure is a result to report, not a reason to run `gh`, `aws`,
   or `av inject` directly, or to edit the script.

## Shape

```sh
#!/usr/local/bin/av inject -- /bin/bash
# --- automic-vault
# capabilities:
#   gh: write
# ---
set -euo pipefail

SELF="${AV_SCRIPT_PATH:-$0}"
ROOT="$(cd "$(dirname "$SELF")/.." && pwd)"
REPOSITORY="example/widget"
ACTION="${1:-continue}"
VERSION="${2:-}"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "usage: $SELF {continue|agent:context} VERSION" >&2
  exit 64
}
NOTES="$ROOT/.release/$VERSION/notes.md"

case "$ACTION" in
  agent:context)
    gh release list --repo "$REPOSITORY" --limit 5
    ;;
  continue)
    if [[ ! -s "$NOTES" ]]; then
      mkdir -p "$(dirname "$NOTES")"
      cat <<EOF
Write release notes for $REPOSITORY $VERSION to:
  $NOTES
For recent releases, run:
  "$SELF" agent:context "$VERSION"
Do not run gh directly. Do not include secrets. Then continue with:
  "$SELF" continue "$VERSION"
EOF
      exit 75
    fi
    [[ -f "$NOTES" && ! -L "$NOTES" ]] || {
      echo "error: notes must be a regular file" >&2
      exit 65
    }
    [[ $(wc -c <"$NOTES") -le 65536 ]] || {
      echo "error: notes exceed 64 KiB" >&2
      exit 65
    }
    if ! gh release view "$VERSION" --repo "$REPOSITORY" >/dev/null 2>&1; then
      gh release create "$VERSION" --repo "$REPOSITORY" \
        --notes-file "$NOTES" --verify-tag
    fi
    IS_DRAFT="$(gh release view "$VERSION" --repo "$REPOSITORY" \
      --json isDraft --jq .isDraft)"
    [[ "$IS_DRAFT" == false ]] || {
      echo "error: GitHub release $VERSION is still a draft" >&2
      exit 1
    }
    ;;
  *) echo "error: unknown action: $ACTION" >&2; exit 64 ;;
esac
```

## Rules for the script

- **Validate arguments first.** Check every argument against a strict pattern
  before any other work. Keep repositories, buckets, and hosts fixed in the
  script.
- **The prompt is a contract.** Name the exact output (path, format, limits),
  the fixed `agent:` subcommands you may use, and the exact continue command.
  Tell the agent not to run the underlying Tools and not to include secrets.
- **Exit with a distinct status after prompting**, such as `75`, so callers
  can tell "needs input" from success and failure.
- **Treat agent output as untrusted data.** Require a regular file, not a
  symlink, with a size limit and the expected format. Never `eval` it, source
  it, or splice it unquoted into a command.
- **Keep `agent:` subcommands fixed and read-only.** They run under the same
  Script Declaration as the gated steps, so give them no free-form arguments
  and no writes.
- **Keep Secret Values inside the script.** Never print them in the prompt or
  in `agent:` output. Prefer hardened Tools with Capabilities over Secret Names
  in the shebang.
- **Make every step idempotent.** A run can stop between any two steps. Check
  remote state before writing, use conditional writes, and verify digests, so
  rerunning `continue` finishes the job instead of repeating it. Verify the
  end state too: an existing release may still be a draft, so fail instead of
  reporting success.
- **Keep state in files the script checks**, not in memory or environment
  variables, because every invocation starts fresh.

## Reference

- [Reentrant Blessed Scripts](https://github.com/automic-vault/automic-vault/blob/main/README.md#reentrant-blessed-scripts)
- [Release example with GitHub, S3, and CloudFront](https://github.com/automic-vault/automic-vault/blob/main/docs/examples/reentrant-release.sh):
  input validation, digest checks, conditional writes, and idempotent retries
- [Choosing a Mechanism](https://github.com/automic-vault/automic-vault/blob/main/docs/choosing-a-mechanism.md)
