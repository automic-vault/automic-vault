# mongodb-atlas-cli

```sh
cat "$HOME/Library/Application Support/atlascli/config.toml"
```

This prints the file, including any MongoDB Atlas credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - MongoDB Atlas CLI config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/atlascli/config.toml`
> - `$XDG_CONFIG_HOME/atlascli/config.toml`
> - `~/.config/atlascli/config.toml`

## Mitigation

MongoDB Atlas CLI already provides an upstream keyring-backed store. A safe
remediation must use or repair that store instead of wrapping the CLI.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
