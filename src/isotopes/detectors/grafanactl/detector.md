# grafanactl Detector

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
