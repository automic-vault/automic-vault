# openvpn

```sh
cat "/path/to/reported/profile.ovpn"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any VPN passwords or unencrypted private keys it contains.
Software running as you with read access can copy the same material.

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

## Mitigation

OpenVPN profiles can contain private keys or reference plaintext
`auth-user-pass` files. This detector reports those local files without changing
VPN profile semantics.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
