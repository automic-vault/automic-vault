# oxide-cli

It is trivial for anything on your computer to exfiltrate oxide-cli’s secret:

```sh
cat "$HOME/.config/oxide/credentials.toml"
```

This prints the file, including any Oxide access tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Oxide CLI credentials contain plaintext access tokens.
>
> #### Sensitive Files
>
> - `~/.config/oxide/credentials.toml`

## Mitigation

`av harden oxide-cli` installs the signed Oxide Isotope and migrates supported
profile tokens into Automic Vault. The config retains non-secret profile
metadata and the reserved `@av` marker; the patched Target obtains credentials
through authenticated XPC operations instead of recreating plaintext files.

Unknown credential fields are refused so a future upstream schema cannot be
silently discarded. The patched Target refuses `OXIDE_TOKEN`; process
environments are outside this detector's file-scanning boundary.

See the [hardening reference](../../hardeners/oxide_cli.md) for setup and coverage.
