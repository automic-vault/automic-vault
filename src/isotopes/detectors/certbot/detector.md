# certbot Detector

> ### What we check
>
> - Certbot key material is stored without passphrase encryption.
>
> #### Sensitive Files
>
> - `~/.config/letsencrypt/**`
> - `~/.letsencrypt/**`
> - `~/Library/Application Support/letsencrypt/**`

## Why This is not Yet Hardened

Certbot's ACME account keys and certificate private keys are service deployment
state. This detector reports unencrypted user-level keys without attempting to
move Certbot's renewal-managed files.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
