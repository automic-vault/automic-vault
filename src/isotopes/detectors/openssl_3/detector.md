# openssl@3 Detector

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

## Why This is not Yet Hardened

OpenSSL private keys are arbitrary user-managed PKI assets, not state owned by
one command or account. Automic Vault cannot move or wrap them without knowing
which applications consume each key. Encrypt the reported key and update its
consumers to unlock it through their native mechanism.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
