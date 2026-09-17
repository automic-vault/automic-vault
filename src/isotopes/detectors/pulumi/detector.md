# pulumi

It is trivial for anything on your computer to exfiltrate pulumi’s secret:

```sh
cat "$HOME/.pulumi/credentials.json"
```

This prints the file, including any Pulumi access tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Pulumi credentials file contains plaintext access tokens.
>
> #### Sensitive Files
>
> - `$PULUMI_CREDENTIALS_PATH`
> - `$PULUMI_HOME/credentials.json`
> - `~/.pulumi/credentials.json`

## Mitigation

```sh
av harden pulumi
```
