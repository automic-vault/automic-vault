# fastly

```sh
cat "$HOME/Library/Application Support/fastly/config.toml"
```

This prints the file, including any Fastly tokens it contains. Software running
as you with read access can copy the same material.

> ### What we check
>
> - Fastly config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/fastly/config.toml`
> - `~/Library/Application Support/fastly/config.toml`
> - `~/.fastly/config.toml`

## Mitigation

Run `av harden fastly-cli`. The Hardener installs the signed Fastly Isotope,
migrates named static tokens into Automic Vault, and leaves only token metadata
and the non-secret `@av` marker in Fastly's config.

SSO, legacy profiles, alternate endpoints, and unknown auth fields are not
rewritten. Resolve those manually before hardening.

If more than `~/Library/Application Support/fastly/config.toml` exists among
the sensitive files above, move or merge the legacy config into that active
path first. Go's `os.UserConfigDir` never consults `$XDG_CONFIG_HOME` on
macOS, so that variable never selects where the live Fastly Target reads or
writes; a config found only there is inactive. The Hardener will not guess
which credential set should win.

See the [hardening reference](../../hardeners/fastly_cli.md) for setup and coverage.
