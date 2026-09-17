# midnight-commander Detector

> ### What we check
>
> - Midnight Commander profile file contains VFS credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/mc/**`
> - `~/.config/mc/**`

## Why This is not Yet Hardened

The retired `midnight-commander` hardener moved the detected secret to the macOS
Keychain, then recreated `$XDG_CONFIG_HOME/mc/**` inside a temporary directory
for each run. We no longer consider a temporary plaintext file a sufficient
security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
