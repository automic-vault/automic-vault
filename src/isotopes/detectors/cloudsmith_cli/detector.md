# cloudsmith-cli Detector

> ### What we check
>
> - cloudsmith credentials contain a plaintext API key.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/cloudsmith/credentials.ini`
> - `~/.cloudsmith/credentials.ini`

## Mitigation

```sh
av harden cloudsmith-cli
```
