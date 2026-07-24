# Homebrew

## Summary

- Only `brew` can alter `/opt/homebrew`
- Approval gates can be configured to stop agents installing things behind your
  back.

## What it Does

Installs `/usr/local/bin/brew` as a small setuid/setgid Automic Vault launcher
for `/opt/homebrew/bin/brew`.

The root phase creates the `automic` user and `vault` group when needed, owns
`/opt/homebrew` as `automic:vault`, and installs the launcher as
`06755 automic:vault`.

## Rationale

Modern macOS has numerous protections to prevent malware or agents from
altering installed sofware.

These protections apply to `.apps` and other bundle types, not to command line
tools. Command line tools are protected by their parent `.app` which is often
a Terminal but nowadays is often an Agent Harness.

Thus we need to apply UNIX security permissions to our command line tools to
ensure what is installed *remains what is installed*. Automic Vault hardening
is that solution.

## Details

- This targets Apple Silicon Homebrew at `/opt/homebrew`.
- Existing `/usr/local/bin/brew` files are left alone unless they are already
  the Automic Vault brew stub.
- Hardening copies missing files from the invoking user's `~/.homebrew` into
  the hardened account, preserving configuration already created there. This
  includes Homebrew's tap trust store.
- The invoking user's `~/Library/Caches/Homebrew` contents are merged into the
  hardened cache and removed from their original location instead of being
  downloaded again.
- `/usr/local/bin` must precede `/opt/homebrew/bin` in `PATH`. After hardening,
  run `hash -r` or start a new shell so it does not keep using a cached path to
  the original `brew` executable.
- Every launcher invocation is authorized by the menu bar app before Homebrew
  runs. Read Only Access approves known inspection commands automatically and
  prompts for writes or unknown commands; Read & Update Access additionally
  approves `brew update` and is the default; No Access prompts for every
  command, while Full Access approves every command automatically.
- The launcher fails closed when the approval service is unavailable.
- The stub clears the environment, restores only safe terminal/locale values,
  and executes `/opt/homebrew/bin/brew` directly.

## Casks

The desktop account that runs `sudo av harden brew` is configured as the cask
app owner. Homebrew still performs cask transactions as `automic:vault`, so its
prefix checks and formula state remain protected. After a successful
install, reinstall, or upgrade, the launcher verifies each declared
`/Applications/*.app` with Gatekeeper and transfers that bundle to the
configured account's UID and primary group. It verifies the bundle and
resulting ownership again before returning success.

Caskroom receipts, caches, locks, and trust configuration remain
`automic:vault`. Obsolete per-user Caskroom and trust-store ACLs from earlier
launcher versions are removed during hardening.

For commands without `--cask` or `--formula`, the launcher asks Homebrew to
resolve each package and pins the result before execution. Mixed formula/cask
commands must be split. Missing formula dependencies must be installed first so
Cellar content always remains `automic:vault`.

Casks that install packages, plugins, fonts, or other artifacts outside an app
bundle are rejected because their ownership cannot be transferred safely.
Caskroom-backed executables, services, shell completions, and links into signed
app bundles remain `automic:vault`.
