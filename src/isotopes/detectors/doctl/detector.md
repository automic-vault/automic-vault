# doctl

It is trivial for anything on your computer to exfiltrate doctl’s secret:

```sh
cat "$HOME/Library/Application Support/doctl/config.yaml"
```

This prints the file, including any DigitalOcean tokens it contains. Software
running as you with read access can copy the same material.

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
