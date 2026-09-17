# pnpm-minimum-release-age Detector

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
