# databricks Detector

> ### What we check
>
> - Databricks config contains plaintext profile credentials.
>
> #### Sensitive Files
>
> - `~/.databrickscfg`
> - `$XDG_CONFIG_HOME/databricks/config`
> - `$XDG_CONFIG_HOME/databricks/databrickscfg`
> - `~/.config/databricks/config`
> - `~/.config/databricks/databrickscfg`

## Why This is not Yet Hardened

Databricks CLI can store profile tokens and client secrets in config files even
when OAuth token storage uses the OS keyring. This detector reports those
plaintext profile secrets without changing the CLI's auth behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
