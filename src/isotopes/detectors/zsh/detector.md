# zsh Detector

## Trigger Conditions

- Zsh startup file contains plaintext-looking credential assignment.
- Zsh `PATH` places a user-writable directory before protected system
  directories.

## Sensitive Files

- `$ZDOTDIR/.zshenv`
- `$ZDOTDIR/.zprofile`
- `$ZDOTDIR/.zshrc`
- `$ZDOTDIR/.zlogin`
- `$ZDOTDIR/.zlogout`
- `~/.zshenv`
- `~/.zprofile`
- `~/.zshrc`
- `~/.zlogin`
- `~/.zlogout`
- Directories listed in `$PATH`

## Mitigation

Zsh startup files contain arbitrary user programs and shared environment
configuration. Automic Vault cannot rewrite them without changing shell
behavior or guessing which commands need each secret. Move the reported value
with `av save KEY`, then inject it only into the command that needs it.

## PATH Mitigation

Version managers commonly prepend user-writable tool directories to `PATH`;
this is expected, but those directories can still shadow later commands. Remove
empty, relative, and unexpected entries. If the ordering is intentional, use
absolute paths for security-sensitive commands and keep reusable secrets out of
the shell environment with `av inject` or `av proxy`; these reduce exposure but
do not make the `PATH` safe.

## Why This is not Yet Hardened

Automic Vault does not rewrite shell startup programs because doing so could
change command resolution, alter shell behavior, or execute attacker-controlled
configuration.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
