# wakatime-cli

```sh
cat "$HOME/.wakatime.cfg"
```

This prints the file, including any WakaTime API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - WakaTime config contains plaintext API keys.
>
> #### Sensitive Files
>
> - `~/.wakatime.cfg`

## Mitigation

Run `av harden wakatime-cli`. The hardener installs the signed WakaTime CLI
Isotope, stores the global API key in Automic Vault, configures the native
credential helper, and points editor plugins at the verified Target.

Project-specific API keys and alternate credential destinations are rejected;
remove them manually before hardening.

See the [hardening reference](../../hardeners/wakatime_cli.md) for setup and coverage.
