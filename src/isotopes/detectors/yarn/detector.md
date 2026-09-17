# yarn Detector

> ### What we check
>
> - Yarn config sets a package minimum release age below 24 hours.
>
> #### Sensitive Files
>
> - `~/.yarnrc.yml`

## Mitigation

Set `npmMinimalAgeGate: 1d` in the reported Yarn config file.
