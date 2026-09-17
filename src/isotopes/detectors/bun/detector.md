# bun Detector

> ### What we check
>
> - Bun config sets a package minimum release age below 24 hours.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/.bunfig.toml`
> - `~/.bunfig.toml`

## Mitigation

Set `minimumReleaseAge = 86400` under `[install]` in the reported Bun config
file.
