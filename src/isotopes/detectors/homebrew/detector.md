# Homebrew

Software running as you can replace CLI executables in a Homebrew installation
that you can modify. The next invocation can then run the replacement with your
credentials and permissions. This finding concerns writable executable code,
even when no Secret is stored in the Homebrew prefix.

> ### What we check
>
> - Homebrew exists at `/opt/homebrew/bin/brew`.
> - The current user can modify `/opt/homebrew` or an immediate child directory.
>
> #### Sensitive Files
>
> - `/opt/homebrew`
> - `/opt/homebrew/*/`

## Mitigation

```sh
av harden brew
```

The hardener requests elevation when needed and offers to replace direct
`/opt/homebrew/bin/brew` references in common shell startup files with the
hardened `/usr/local/bin/brew` launcher.

See the [hardening reference](../../hardeners/homebrew.md) for setup and coverage.

---

## Rationale

macOS has numerous protections to prevent same user processes from modifying
`.apps`. Most of these protections do not apply to command line tools. Automic Vault
[aims to be the adapter bringing these protections to the command line][blog].

[blog]: https://www.automicvault.com/blog/bringing-macos-security-to-the-terminal/

> The simple fact is: not hardening Homebrew can make everything else Automic
> Vault does moot. If malware can just modify your hardened packages then the
> hardening is either *much less effective* or potentially *completely useless*.

## Overview

- After hardening, use `brew install` as usual; installed packages are owned by
  `automic:vault`.
- We add approval gates for sensitive actions like `brew upgrade` and
  `brew install` so if an agent tries to sneakily install a package you can
  vet its decision first.

## Important Caveats

- This is not an officially supported configuration for Homebrew.
- `brew services` is unsupported. Hardening refuses to proceed while any
  Homebrew service is loaded or registered.
- Casks that are not simple wrappers around executables are unsupported.
- ZSH requires its completions to be owned by the executing user for some reason
  so we remove them from `brew shellenv zsh`.

> Many people have hardened their `brew` without issues.
> The hardening has gone through several iterations of battle testing.

> If you have issues with Homebrew while Automic Vault hardening is enabled
> please report the bug to *us* first.
