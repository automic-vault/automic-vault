# opentofu

```sh
cat "$HOME/.terraform.d/credentials.tfrc.json"
```

This prints the file, including any OpenTofu API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - OpenTofu credentials file contains plaintext API tokens.
>
> #### Sensitive Files
>
> - `~/.terraform.d/credentials.tfrc.json`

## Mitigation

Run `av harden opentofu` to install this repository's signed, Hardened Runtime
OpenTofu Isotope, migrate host tokens into Secret Custody, and configure the
hostname-bound Automic Vault credential helper. The hardener refuses competing
token sources that could bypass the helper.

[OpenTofu hardener details](../../hardeners/opentofu.md).
