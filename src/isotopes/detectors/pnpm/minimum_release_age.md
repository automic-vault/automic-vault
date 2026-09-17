# pnpm-minimum-release-age

A short package release-age delay allows newly published dependencies into your
installation sooner, leaving less time to discover a malicious release. This
check concerns package-installation policy; the pnpm token detector separately
checks stored authentication tokens.

> ### What we check
>
> - pnpm config sets a package minimum release age below 24 hours.
>
> #### Sensitive Files
>
> - `$NPM_CONFIG_USERCONFIG`
> - `~/.npmrc`
> - `$XDG_CONFIG_HOME/pnpm/rc`
> - `~/.config/pnpm/rc`
> - `~/Library/Preferences/pnpm/rc`

## Mitigation

Set `minimum-release-age=1440` in the reported pnpm config file.
