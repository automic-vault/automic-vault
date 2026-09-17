# npm

A short package release-age delay allows newly published dependencies into your
installation sooner, leaving less time to discover a malicious release. This
check concerns package-installation policy; the Node detector separately checks
npm's stored authentication tokens.

> ### What we check
>
> - npm config sets a package minimum release age below 24 hours.
>
> #### Sensitive Files
>
> - `$NPM_CONFIG_USERCONFIG`
> - `~/.npmrc`

## Mitigation

Set `min-release-age=1` in the reported npm config file.
