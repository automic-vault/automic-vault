# vault

It is trivial for anything on your computer to exfiltrate vault’s secret:

```sh
cat "$HOME/.vault-token"
```

This prints the file, including any Vault tokens it contains. Software running
as you with read access can copy the same material.

> ### What we check
>
> - Vault token helper file contains a plaintext token.
>
> #### Sensitive Files
>
> - `~/.vault-token`

## Mitigation

```sh
av harden vault
```
