# ast-cli Detector

> ### What we check
>
> - Checkmarx AST config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$CX_CONFIG_FILE_PATH`
> - `~/.checkmarx/checkmarxcli.yaml`

## Mitigation

```sh
av harden ast-cli
```
