# argocd

It is trivial for anything on your computer to exfiltrate argocd’s secret:

```sh
cat "$HOME/.argocd/config"
```

This prints the file, including any Argo CD tokens it contains. Software running
as you with read access can copy the same material.

> ### What we check
>
> - Argo CD config file contains plaintext tokens.
>
> #### Sensitive Files
>
> - `$ARGOCD_CONFIG_DIR/config`
> - `~/.argocd/config`
> - `$XDG_CONFIG_HOME/argocd/config`
> - `~/.config/argocd/config`

## Mitigation

```sh
av harden argocd
```

Older Automic Vault builds could store the entire config as the legacy Secret
Name `ARGOCD_CONFIG_YAML`. Current builds intentionally do not retrieve that
Secret during hardening. To recover it, explicitly approve one Secret
Application that restores the config, then immediately harden it:

```sh
av inject --replace-existing-env +ARGOCD_CONFIG_YAML -- /bin/sh -c \
  'umask 077; mkdir -p "$HOME/.argocd"; printf %s "$ARGOCD_CONFIG_YAML" > "$HOME/.argocd/config"'
av harden argocd
```

The first command temporarily restores the plaintext token. Do not leave the
recovered config unhardened.
