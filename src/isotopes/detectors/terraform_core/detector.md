# terraform-core Detector

> ### What we check
>
> - Terraform credentials file contains plaintext API tokens.
>
> #### Sensitive Files
>
> - `~/.terraform.d/credentials.tfrc.json`

## Hardening

Run `av harden terraform` to install HashiCorp's signed native Terraform Target,
migrate host tokens into Secret Custody, and configure the hostname-bound
Automic Vault credential helper. The hardener refuses competing token sources
that could bypass the helper.

[Terraform hardener details](../../hardeners/terraform.md).
