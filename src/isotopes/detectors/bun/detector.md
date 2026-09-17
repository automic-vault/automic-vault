# bun

A short package release-age delay allows newly published dependencies into your
installation sooner, leaving less time to discover a malicious release. This
check concerns package-installation policy rather than a stored token.

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
