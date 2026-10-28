# cloudflare-cf

It is trivial for anything on your computer to exfiltrate the Cloudflare `cf`
CLI’s secret:

```sh
cat "$HOME/Library/Preferences/cloudflare/config/default.json"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including the Cloudflare OAuth access and refresh tokens it contains.
Software running as you with read access can copy the same material. Each
named profile created with `cf auth create <name>` has its own file beside
`default.json`.

> ### What we check
>
> - A `cf` auth profile contains plaintext Cloudflare tokens.
> - An encrypted `cf` auth profile uses a Keychain encryption key that
>   `/usr/bin/security` can retrieve non-interactively.
> - A `cf` auth profile cannot be read or parsed.
> - A `cf` auth profile directory cannot be listed.
> - Access to that Keychain encryption key cannot be inspected.
>
> #### Sensitive Files
>
> - `~/Library/Preferences/cloudflare/config/*.json`
> - `~/Library/Preferences/cloudflare/config/*.enc`
> - `~/.config/cloudflare/config/*.json`
> - `~/.config/cloudflare/config/*.enc`
> - `$XDG_CONFIG_HOME/cloudflare/config/*.json`
> - `$XDG_CONFIG_HOME/cloudflare/config/*.enc`

## Mitigation

`cf auth login --use-keyring` encrypts the profile on disk as `<profile>.enc`
and stores the encryption key in the macOS Keychain under the service
`cloudflare` and the profile name. Its macOS backend creates and reads that key
through `/usr/bin/security`. When the Keychain item authorizes that tool, other
software running as the user can ask the same tool for the key and decrypt the
profile without crossing an Authorization Gate.

This mode reduces plaintext-at-rest Exposure, but it does not establish the
Secret Custody and authorization boundary required for Hardened State. The
detector inspects the Keychain access-control list without retrieving the key or
credentials and reports inspection uncertainty as a Hazard.

`cf auth logout` removes a profile you no longer need. This detector is
detect-only; Automic Vault does not yet harden `cf`.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
