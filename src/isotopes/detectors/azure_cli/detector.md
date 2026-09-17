# azure-cli

```sh
cat "$HOME/.azure/msal_token_cache.json"
```

This prints the file, including any Azure authentication tokens it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Azure CLI MSAL token cache contains plaintext credentials.
> - Azure CLI service principal cache contains plaintext credentials.
> - Azure CLI legacy token cache contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$AZURE_CONFIG_DIR/msal_token_cache.json`
> - `$AZURE_CONFIG_DIR/service_principal_entries.json`
> - `$AZURE_CONFIG_DIR/accessTokens.json`
> - `~/.azure/msal_token_cache.json`
> - `~/.azure/service_principal_entries.json`
> - `~/.azure/accessTokens.json`

## Mitigation

Azure CLI owns a complex, mutable MSAL token cache. A safe fix needs an upstream
default or migration change, or a source isotope that patches the persistence
layer.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
