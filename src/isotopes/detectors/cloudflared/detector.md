# cloudflared

It is trivial for anything on your computer to exfiltrate cloudflared’s secret:

```sh
cat "$HOME/.cloudflared/REPORTED_FILE"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any tunnel credentials or unencrypted private keys it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - cloudflared certificate contains a plaintext private key.
> - cloudflared tunnel credentials are stored in plaintext.
>
> #### Sensitive Files
>
> - `~/.cloudflared/**`
> - `$XDG_CONFIG_HOME/cloudflared/**`
> - `~/.config/cloudflared/**`

## Mitigation

cloudflared tunnel state can include certificate private keys and tunnel
credential JSON files. These are service credentials, so this detector reports
bounded user-level exposures without changing tunnel configuration.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
