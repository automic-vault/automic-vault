# Testing ordinary Git with Vault before merge

This follows the [domain language](domain-language.md),
[architecture](architecture.md), and [positioning](positioning.md).
**Legacy transport only.** The Git HTTPS transport is deprecated and its
installer is disabled. This guide applies only to an already-installed signed
runtime and adapter; `av harden gh` no longer installs or repairs them. Use
[SSH](securing-git.md) for new setups. The [security boundary and measured evidence](adr/0047-protected-git-https-transport.md)
still apply to existing use.

## Start with the private fixture

Use the configured clone supplied after installation or created by the
automated test below. Its feature branch tracks the private test repository:

```sh
cd /path/to/test-clone
git fetch
git pull --ff-only
git commit --allow-empty -m "Manual Vault Git test"
git push
```

Open Vault's Authorization History. Credential-bearing requests should show
the original Git command and a protected HTTPS request with URL, options and
object IDs. Push records include the exact commit and destination branch.
One Git command can produce several records or Approval requests because each
HTTPS phase gets a fresh process and authorization. Public reads may require
no credential and therefore produce no Secret-use record.

## Inspect legacy routing

Inspect existing routing with `git config --includes --show-origin --get-regexp
'^url\.av::.*\.(insteadof|pushinsteadof)$'`. The transport still checks the
installed runtime at use. A URL rewrite does not install or verify it.
Do not add routing to work around a missing adapter. See the
[removal guidance](../src/isotopes/hardeners/gh_cli.md#git-https-transport-deprecated).

## Check Approval behavior

In Vault, set the relevant `gh` access to **Local Write**. Fetch and pull are
Local Write operations; push is Remote Write and should require Approval.
Make a disposable commit in the fixture, run `git push`, and decline: the
remote must stay unchanged. Run it again and approve: only the displayed
commit/branch should be sent. Check both outcomes in Authorization History.
A discovery phase can ask first; approval of discovery does not approve a
later update. Read Only also requires Approval for fetch/pull. Restore your
preferred access setting after testing.

The automated live run exercised the existing Write Access policy, not this
human interaction. Approval/cancellation testing is part of the pre-merge review.

## Current limits

Only explicit `https://github.com/OWNER/REPO.git` destinations, full SHA-1
repositories, and branch updates (including force and leases) are supported by the candidate
in [ADR 0052](adr/0052-protected-git-force-and-leases.md). Tags, shallow or
partial clones, deletion, atomic/signed pushes, submodules and LFS
are outside this candidate's surface. Unsupported helper commands/options fail
explicitly. Use SSH for repositories that need these features. Large transfers and GUI/embedded Git
clients have not been validated.

Try `git push --dry-run`: it must leave the remote unchanged. Try
`git push --force-with-lease` on a disposable rebased branch: the candidate
must preserve the exact expected remote commit and reject stale state.
`--force` must display unconditional force; combining it with a lease for the
same branch must fail. Repeat both with `--dry-run` and verify unchanged refs. These discovery requests conservatively require
Remote Write authority even when no update follows.

## Roll back routing

In each opted-in repository:

```sh
git config --local --fixed-value --unset-all url."av::https://github.com/".insteadOf https://github.com/
```

If you enabled the global setting, remove it with the same command using
`--global`. This restores your previous transport selection. It does not grant
ordinary Git access to Vault's protected credential provider. Keep the
candidate app installed during testing. Doctor reports remaining legacy rewrites
as deprecated. The compatibility flag does not undo routing.

## Repeat the automated live test

```sh
python3 scripts/test-git-remote-e2e.py \
  --repository OWNER/PRIVATE_TEST_REPO
```

It requires an existing runtime and adapter, configures routing only in an
isolated test home, then creates and retains a new feature branch and local clones. It verifies
actual GitHub commits, upstream tracking, dry-run, hostile config isolation,
malformed request denial, copied-nonce denial, and fresh Vault records without
reading or displaying the raw token. It also exercises force, implicit/explicit
leases, multiple native lease checks, and expected-absent branch creation.
The signed force/lease run is pending; do not treat the earlier ordinary-push
results as validation of this extension.
