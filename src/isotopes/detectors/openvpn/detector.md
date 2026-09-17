# openvpn Detector

> ### What we check
>
> - OpenVPN profile contains inline plaintext key or password material.
> - OpenVPN auth-user-pass file contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.openvpn/**`
> - `$XDG_CONFIG_HOME/openvpn/**`
> - `~/.config/openvpn/**`
> - `~/Library/Application Support/OpenVPN/**`
> - `~/Library/Application Support/Tunnelblick/Configurations/**`
> - `auth-user-pass files referenced by scanned profiles`

## Why This is not Yet Hardened

OpenVPN profiles can contain private keys or reference plaintext
`auth-user-pass` files. This detector reports those local files without changing
VPN profile semantics.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
