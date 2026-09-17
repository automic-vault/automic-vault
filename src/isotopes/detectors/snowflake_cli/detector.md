# snowflake-cli

```sh
cat "$HOME/.snowflake/config.toml"
```

This prints the file, including any Snowflake credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Snowflake CLI config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.snowflake/config.toml`
> - `~/.snowflake/connections.toml`
> - `~/Library/Application Support/snowflake/config.toml`
> - `~/Library/Application Support/snowflake/connections.toml`
> - `~/.config/snowflake/config.toml`
> - `~/.config/snowflake/connections.toml`

## Mitigation

```sh
av harden snowflake-cli
```
