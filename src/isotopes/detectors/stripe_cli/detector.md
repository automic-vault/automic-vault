# stripe-cli

```sh
cat "$HOME/.config/stripe/config.toml"
```

This prints the file, including any Stripe API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Stripe CLI config contains plaintext API keys.
> - Stripe CLI Keychain credentials can be extracted non-interactively through
>   `/usr/bin/security`.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/stripe/config.toml`
> - `~/.config/stripe/config.toml`

## Mitigation

```sh
av harden stripe
```

See the [hardening reference](../../hardeners/stripe_cli.md) for setup and coverage.
