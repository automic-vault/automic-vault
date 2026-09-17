# snyk Detector

> ### What we check
>
> - Snyk CLI configstore contains credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/configstore/snyk.json`
> - `~/.config/configstore/snyk.json`

## Mitigation

```sh
av harden snyk
```
