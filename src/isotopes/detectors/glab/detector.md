# glab

It is trivial for anything on your computer to exfiltrate glab’s secret:

```sh
cat "$HOME/.config/glab-cli/config.yml"
```

This prints the file, including any GitLab tokens it contains. Software running
as you with read access can copy the same material.

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
