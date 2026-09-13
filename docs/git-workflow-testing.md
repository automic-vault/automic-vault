# Testing ordinary Git with Vault before merge

This follows the [domain language](domain-language.md),
[architecture](architecture.md), and [positioning](positioning.md).
This guide requires the signed candidate app, CLI, protected runtime and
`/usr/local/bin/git-remote-av` to be installed. The [security boundary and measured evidence](adr/0047-protected-git-https-transport.md)
apply to the narrow surface below. Your existing Vault policy is unchanged.

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

## Enable another repository

For an existing repository with a GitHub HTTPS origin ending in `.git`, run once:

```sh
git config --local url."av::https://github.com/".insteadOf https://github.com/
```

Continue using ordinary `git fetch`, `git pull`, and `git push`. The saved
origin URL remains unchanged. Inspect it with `git config --get remote.origin.url`;
`git remote get-url origin` displays the effective rewritten URL.
SSH origins continue using SSH. This setting does not redirect them.

To opt in globally, including new clones, use `--global` instead of `--local`.
Native Git must be able to find `/usr/local/bin/git-remote-av` on PATH.
No `av git` command or replacement Git binary is required.

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
repositories, and ordinary branch operations are supported. Tags, shallow or
partial clones, force/deletion, leases, atomic/signed pushes, submodules and LFS
are outside this candidate's surface. Unsupported helper commands/options fail
explicitly. Repositories using these features may need to stay outside the
opt-in while the surface is extended. Large transfers and GUI/embedded Git
clients have not been validated.

Try `git push --dry-run`: it must leave the remote unchanged. Try
`git push --force-with-lease`: this candidate must reject it explicitly rather
than dropping the lease. These discovery requests conservatively require
Remote Write authority even when no update follows.

## Roll back routing

In each opted-in repository:

```sh
git config --local --unset-all url."av::https://github.com/".insteadOf
```

If you enabled the global setting, remove it with the same command using
`--global`. This restores your previous transport selection. It does not grant
ordinary Git access to Vault's protected credential provider. Keep the
candidate app installed during testing; app/CLI/runtime distribution and
refresh integration remain pending in the draft PR.

## Repeat the automated live test

```sh
python3 scripts/test-git-remote-e2e.py \
  --repository OWNER/PRIVATE_TEST_REPO
```

It creates and retains a new feature branch and local clones. It verifies
actual GitHub commits, upstream tracking, dry-run, hostile config isolation,
malformed request denial, copied-nonce denial, and fresh Vault records without
reading or displaying the raw token.
