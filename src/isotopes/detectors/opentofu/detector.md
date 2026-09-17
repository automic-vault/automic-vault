# opentofu Detector

> ### What we check
>
> - OpenTofu credentials file contains plaintext API tokens.
>
> #### Sensitive Files
>
> - `~/.terraform.d/credentials.tfrc.json`

## Hardening

Run `av harden opentofu` to install this repository's signed, Hardened Runtime
OpenTofu Isotope, migrate host tokens into Secret Custody, and configure the
hostname-bound Automic Vault credential helper. The hardener refuses competing
token sources that could bypass the helper.

[OpenTofu hardener details](../../hardeners/opentofu.md).
