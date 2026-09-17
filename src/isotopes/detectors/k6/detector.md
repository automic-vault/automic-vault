# k6 Detector

> ### What we check
>
> - k6 config file contains a plaintext cloud token.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/k6/config.json`
> - `~/.config/k6/config.json`

## Mitigation

```sh
av harden k6
```
