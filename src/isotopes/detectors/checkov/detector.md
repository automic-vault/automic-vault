# checkov

```sh
cat "$HOME/.bridgecrew/credentials"
```

This prints the file, including any Checkov API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Checkov API key is stored in plaintext credentials file.
>
> #### Sensitive Files
>
> - `~/.bridgecrew/credentials`

## Mitigation

```sh
av harden checkov
```
