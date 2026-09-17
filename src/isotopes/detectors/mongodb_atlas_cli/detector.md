# mongodb-atlas-cli Detector

> ### What we check
>
> - MongoDB Atlas CLI config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/atlascli/config.toml`
> - `$XDG_CONFIG_HOME/atlascli/config.toml`
> - `~/.config/atlascli/config.toml`

## Why This is not Yet Hardened

MongoDB Atlas CLI already provides an upstream keyring-backed store. A safe
remediation must use or repair that store instead of wrapping the CLI.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
