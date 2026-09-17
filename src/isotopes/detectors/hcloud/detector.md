# hcloud

It is trivial for anything on your computer to exfiltrate hcloud’s secret:

```sh
cat "$HOME/.config/hcloud/cli.toml"
```

This prints the file, including any Hetzner Cloud API tokens it contains.
Software running as you with read access can copy the same material.

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
