# certbot

It is trivial for anything on your computer to exfiltrate certbot’s secret:

```sh
cat "/path/to/reported/private-key.pem"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any unencrypted certificate or ACME account private keys it
contains. Software running as you with read access can copy the same material.

> ### What we check
>
> - Certbot key material is stored without passphrase encryption.
>
> #### Sensitive Files
>
> - `~/.config/letsencrypt/**`
> - `~/.letsencrypt/**`
> - `~/Library/Application Support/letsencrypt/**`

## Mitigation

Certbot's ACME account keys and certificate private keys are service deployment
state. This detector reports unencrypted user-level keys without attempting to
move Certbot's renewal-managed files.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
