# snyk

```sh
cat "$HOME/.config/configstore/snyk.json"
```

This prints the file, including any Snyk credentials it contains. Software
running as you with read access can copy the same material.

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
