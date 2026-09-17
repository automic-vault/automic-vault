# graphite

It is trivial for anything on your computer to exfiltrate graphite’s secret:

```sh
cat "$HOME/.config/graphite/auth"
```

This prints the file, including any Graphite tokens it contains. Software
running as you with read access can copy the same material.

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

## Mitigation

The retired `graphite` hardener moved the detected secret to the macOS Keychain,
then recreated `$XDG_CONFIG_HOME/graphite/auth` inside a temporary directory for
each run. We no longer consider a temporary plaintext file a sufficient security
boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
