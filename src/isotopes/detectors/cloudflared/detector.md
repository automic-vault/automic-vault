# cloudflared Detector

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

## Why This is not Yet Hardened

cloudflared tunnel state can include certificate private keys and tunnel
credential JSON files. These are service credentials, so this detector reports
bounded user-level exposures without changing tunnel configuration.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
