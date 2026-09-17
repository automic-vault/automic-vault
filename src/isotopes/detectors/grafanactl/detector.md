# grafanactl

It is trivial for anything on your computer to exfiltrate grafanactl’s secret:

```sh
cat "$HOME/.config/grafanactl/config.yaml"
```

This prints the file, including any Grafana credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - grafanactl config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/grafanactl/config.yaml`
> - `~/.config/grafanactl/config.yaml`

## Mitigation

```sh
av harden grafanactl
```
