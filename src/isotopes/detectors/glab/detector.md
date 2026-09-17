# glab Detector

> ### What we check
>
> - GLab config file contains plaintext tokens.
>
> #### Sensitive Files
>
> - `$GLAB_CONFIG_DIR/config.yml`
> - `$XDG_CONFIG_HOME/glab-cli/config.yml`
> - `~/.config/glab-cli/config.yml`
> - `~/Library/Application Support/glab-cli/config.yml`

## Mitigation

```sh
av harden glab
```
