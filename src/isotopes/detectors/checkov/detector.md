# checkov Detector

> ### What we check
>
> - Checkov API key is stored in plaintext credentials file.
>
> #### Sensitive Files
>
> - `~/.bridgecrew/credentials`

## Mitigation

```sh
av harden checkov
```
