# ast-cli

It is trivial for anything on your computer to exfiltrate ast-cli’s secret:

```sh
cat "$HOME/.checkmarx/checkmarxcli.yaml"
```

This prints the file, including any Checkmarx credentials it contains. Software
running as you with read access can copy the same material.

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
