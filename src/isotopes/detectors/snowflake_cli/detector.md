# snowflake-cli Detector

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
