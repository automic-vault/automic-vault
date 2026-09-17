# hcloud Detector

> ### What we check
>
> - hcloud config file contains plaintext API tokens.
>
> #### Sensitive Files
>
> - `$HCLOUD_CONFIG`
> - `$XDG_CONFIG_HOME/hcloud/cli.toml`
> - `~/.config/hcloud/cli.toml`

## Mitigation

```sh
av harden hcloud
```
