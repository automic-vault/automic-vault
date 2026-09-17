# poetry

```sh
cat "$HOME/.config/pypoetry/auth.toml"
```

This prints the file, including any repository passwords or PyPI tokens it
contains. Software running as you with read access can copy the same material.

> ### What we check
>
> - Poetry auth.toml contains plaintext repository credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/pypoetry/auth.toml`
> - `~/.config/pypoetry/auth.toml`
> - `~/Library/Application Support/pypoetry/auth.toml`
> - `~/Library/Preferences/pypoetry/auth.toml`

## Mitigation

Poetry can store repository passwords and PyPI tokens in `auth.toml` when a
usable system keyring is unavailable. This detector reports those fallback
credentials without changing Poetry's keyring behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
