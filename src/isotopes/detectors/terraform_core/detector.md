# terraform-core

It is trivial for anything on your computer to exfiltrate terraform-core’s secret:

```sh
cat "$HOME/.terraform.d/credentials.tfrc.json"
```

This prints the file, including any Terraform API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Terraform credentials file contains plaintext API tokens.
>
> #### Sensitive Files
>
> - `~/.terraform.d/credentials.tfrc.json`

## Mitigation

Run `av harden terraform` to install HashiCorp's signed native Terraform Target,
migrate host tokens into Secret Custody, and configure the hostname-bound
Automic Vault credential helper. The hardener refuses competing token sources
that could bypass the helper.

[Terraform hardener details](../../hardeners/terraform.md).
