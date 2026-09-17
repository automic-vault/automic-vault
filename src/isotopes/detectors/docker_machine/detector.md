# docker-machine

It is trivial for anything on your computer to exfiltrate docker-machine’s secret:

```sh
cat "$HOME/.docker/machine/REPORTED_KEY.pem"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any unencrypted Docker Machine private keys it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Docker Machine private key is stored without passphrase encryption.
>
> #### Sensitive Files
>
> - `~/.docker/machine/**`

## Mitigation

Docker Machine can leave host and client TLS private keys in
`~/.docker/machine`. This detector reports unencrypted private keys without
modifying machine state.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
