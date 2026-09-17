# vault Detector

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
