# railway

It is trivial for anything on your computer to exfiltrate railway’s secret:

```sh
cat "$HOME/.railway/config.json"
```

This prints the file, including any Railway session credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Railway CLI auth state is stored in plaintext config.
>
> #### Sensitive Files
>
> - `~/.railway/config.json`
> - `~/.railway/config-staging.json`
> - `~/.railway/config-dev.json`

## Mitigation

Run `sudo av harden railway` to replace the supported Railway CLI with the
signed Railway Isotope and move stored legacy or OAuth credentials behind the
Automic Vault XPC service. The config files retain only `@av` custody markers;
OAuth refresh and logout update the stored credential without writing it back
to disk.

Explicit `RAILWAY_TOKEN` and `RAILWAY_API_TOKEN` environment variables remain
outside this hardener's stored-session boundary.

[Learn about Hardeners](https://github.com/automic-vault/automic-vault#hardeners).

See the [hardening reference](../../hardeners/railway.md) for setup and coverage.
