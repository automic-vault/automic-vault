# yarn

A short package release-age delay allows newly published dependencies into your
installation sooner, leaving less time to discover a malicious release. This
check concerns package-installation policy rather than a stored token.

> ### What we check
>
> - Yarn config sets a package minimum release age below 24 hours.
>
> #### Sensitive Files
>
> - `~/.yarnrc.yml`

## Mitigation

Set `npmMinimalAgeGate: 1d` in the reported Yarn config file.
