# openssl@3

It is trivial for anything on your computer to exfiltrate openssl@3’s secret:

```sh
cat "/path/to/reported/private-key.pem"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any unencrypted private keys it contains. Software running as
you with read access can copy the same material.

> ### What we check
>
> - OpenSSL private key is stored without passphrase encryption.
>
> #### Sensitive Files
>
> - `~/.ssl/**`
> - `~/.certs/**`
> - `~/certs/**`
> - `~/.config/openssl/**`

## Mitigation

OpenSSL private keys are arbitrary user-managed PKI assets, not state owned by
one command or account. Automic Vault cannot move or wrap them without knowing
which applications consume each key. Encrypt the reported key and update its
consumers to unlock it through their native mechanism.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
