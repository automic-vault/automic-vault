# poetry Detector

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

## Why This is not Yet Hardened

Poetry can store repository passwords and PyPI tokens in `auth.toml` when a
usable system keyring is unavailable. This detector reports those fallback
credentials without changing Poetry's keyring behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
