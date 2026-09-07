# Homebrew

## Summary

- Homebrew hardening is defense in depth for most Isotopes. Automic Vault
  already verifies their code-signing identity before Secret Application.
- It gates `brew install` and other Homebrew writes, and prevents same-user code
  from modifying installed command-line tools such as `node`.
- Environment-wrapper hardeners do not have the same Isotope identity boundary
  and are gradually being phased out.
- Only `brew` can alter `/opt/homebrew`.
- Hardened Homebrew manages formulae and a narrow class of CLI-only casks.
- Homebrew services are incompatible with hardened Homebrew.

**Homebrew shell completions are unavailable while hardened.** Completion files
remain protected inside `/opt/homebrew`; the launcher never copies them into a
user-owned location or weakens shell ownership checks.

## What it Does

Installs `/usr/local/bin/brew` as a small setuid/setgid Automic Vault launcher
for `/opt/homebrew/bin/brew`.

The root phase creates the `automic` user and `vault` group when needed, owns
`/opt/homebrew` as `automic:vault`, and installs the launcher as
`06755 automic:vault`.

## Rationale

Most Isotopes are code signed. Before Automic Vault applies a Secret to one of
them, its Secret Gate verifies the Isotope's code-signing identity. Malware that
modifies or replaces the Isotope therefore cannot use it to obtain the Secret.
Homebrew hardening adds defense in depth for these tools; it is not their
primary Secret Application boundary.

Homebrew hardening still adds an Execution Gate for `brew install` and other
writes. It also makes `/opt/homebrew` unavailable for same-user modification,
so malware or an agent cannot replace an installed command-line tool such as
`node`. This protects the integrity of Homebrew-installed tools whether or not
they use a Secret.

Environment-wrapper hardeners are the exception. They wrap mutable upstream
commands rather than rely on a signed Isotope identity, so protecting their
installed Targets remains more important until those wrappers are phased out.

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
- Shell startup must evaluate the hardened launcher's environment instead of
  invoking `/opt/homebrew/bin/brew` directly:

  ```sh
  eval "$(/usr/local/bin/brew shellenv)"
  ```

  For compatibility with existing startup files, `brew shellenv zsh` is
  normalized to generic shell output and does not add Homebrew's protected zsh
  completion directory to `fpath`.
- Every Launcher invocation is authorized by the menu bar app before Homebrew
  runs. Read & Update automically authorizes recognized inspection commands and
  `brew update`; Homebrew may perform the same update while running an
  inspection command. Installs and upgrades require Approval at this level.
  Approval Required prompts for every command. Full Access automically
  authorizes every recognized command; unknown commands still require Approval.
- The launcher fails closed when the approval service is unavailable.
- The stub clears the environment, restores only safe terminal/locale values,
  and executes `/opt/homebrew/bin/brew` directly.
- Do not add `/opt/homebrew/share/zsh/site-functions` to `fpath` or bypass zsh's
  ownership checks. Older user-owned Automic Vault completion mirrors are no
  longer updated and may be removed.

## Caveats

- Hardening refuses to run while any Homebrew service is loaded or registered.
  Stop each service with `/opt/homebrew/bin/brew services stop <formula>` before
  hardening.
- If the protected `automic` account cannot read the current working directory,
  the hardened launcher runs Homebrew from `/` instead.

## Casks

**Application and installer casks are categorically incompatible with this
hardener.** A normal cask is not confined to the Homebrew prefix: it may modify
`/Applications`, `/Library`, launch services, system plugins, privileged
packages, and user data. Running that package manager as the protected
`automic` account also makes its nested `sudo` operations authenticate the
wrong identity. Pretending this is the same ownership model as a formula
weakens the security guarantee and still fails for ordinary casks.

The sole exception is a CLI-only cask from the official `homebrew/cask`
repository. It must declare one or more `binary` artifacts whose sources remain
inside its staged Caskroom and whose targets are directly inside
`/opt/homebrew/bin`. Generated shell completions may remain protected inside the
Homebrew prefix but are not added to shell paths. `zap` metadata may be present,
but `--zap` is rejected and never runs. Cask dependencies and every app,
package, installer, script, flight block, service, plugin, arbitrary artifact,
completion-file, manpage, or external target are rejected.

Cask mutations must use `--cask` and name every cask explicitly. The launcher
checks Homebrew's effective JSON metadata after approval and validates the
protected installation receipt before upgrades, reinstalls, or removals.
Homebrew's own in-process forbidden-artifact check is also enabled for the
actual installation. Path-based casks, custom destination flags, bulk cask
upgrades, and `brew bundle` are unavailable. Commands without `--cask` remain
pinned to `--formula`.

Hardening refuses to proceed while `/opt/homebrew/Caskroom` contains anything
other than validated CLI-only casks. For an existing hardened installation, run
`av unharden brew`, follow its explicit sudo step, remove or migrate incompatible casks using
`/opt/homebrew/bin/brew`, then run `av harden brew` again. Homebrew is
user-writable between those commands; do not run hardened tools or expose
credentials through them during that migration window.
