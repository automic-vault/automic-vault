# cloudflare-wrangler

```sh
cat "$HOME/.wrangler/config/default.toml"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any Cloudflare OAuth tokens it contains. Software running as you
with read access can copy the same material.

> ### What we check
>
> - Wrangler auth config contains plaintext Cloudflare tokens.
> - Wrangler encrypted auth config uses a Keychain encryption key that
>   `/usr/bin/security` can retrieve non-interactively.
> - Access to that Keychain encryption key cannot be inspected.
>
> #### Sensitive Files
>
> - `~/Library/Preferences/.wrangler/config/*.toml`
> - `~/Library/Preferences/.wrangler/config/*.enc`
> - `~/.wrangler/config/*.toml`
> - `~/.wrangler/config/*.enc`
> - `~/.config/.wrangler/config/*.toml`
> - `~/.config/.wrangler/config/*.enc`
> - `$XDG_CONFIG_HOME/.wrangler/config/*.toml`
> - `$XDG_CONFIG_HOME/.wrangler/config/*.enc`

## Mitigation

Wrangler 4.107.0 added `wrangler login --use-keyring`, which encrypts OAuth
credentials on disk and stores the encryption key in the macOS Keychain. Its
macOS backend creates and reads that key through `/usr/bin/security`. When the
Keychain item authorizes that tool, other software running as the user can ask
the same tool for the key and decrypt the credentials without crossing an
Authorization Gate.

This mode reduces plaintext-at-rest exposure, but it does not establish the
Secret Custody and authorization boundary required for Hardened State. The
detector inspects the Keychain access-control list without retrieving the key or
credentials and reports inspection uncertainty as a Hazard.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
