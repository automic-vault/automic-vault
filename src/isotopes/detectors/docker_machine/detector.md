# docker-machine Detector

> ### What we check
>
> - Docker Machine private key is stored without passphrase encryption.
>
> #### Sensitive Files
>
> - `~/.docker/machine/**`

## Why This is not Yet Hardened

Docker Machine can leave host and client TLS private keys in
`~/.docker/machine`. This detector reports unencrypted private keys without
modifying machine state.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
