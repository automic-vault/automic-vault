# stripe-cli Detector

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
