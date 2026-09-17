# pulumi Detector

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
