# graphite Detector

> ### What we check
>
> - Graphite CLI auth token is stored in plaintext config.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/graphite/auth`
> - `$XDG_CONFIG_HOME/graphite/user_config`
> - `~/.config/graphite/auth`
> - `~/.config/graphite/user_config`

## Why This is not Yet Hardened

The retired `graphite` hardener moved the detected secret to the macOS Keychain,
then recreated `$XDG_CONFIG_HOME/graphite/auth` inside a temporary directory for
each run. We no longer consider a temporary plaintext file a sufficient security
boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
