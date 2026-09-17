# doctl Detector

> ### What we check
>
> - doctl config contains plaintext DigitalOcean tokens.
>
> #### Sensitive Files
>
> - `$DIGITALOCEAN_CONFIG`
> - `~/Library/Application Support/doctl/config.yaml`
> - `$XDG_CONFIG_HOME/doctl/config.yaml`
> - `~/.config/doctl/config.yaml`

## Mitigation

```sh
av harden doctl
```
