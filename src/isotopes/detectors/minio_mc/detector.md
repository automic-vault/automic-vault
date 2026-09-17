# minio-mc Detector

> ### What we check
>
> - MinIO mc config file contains plaintext alias secrets.
>
> #### Sensitive Files
>
> - `~/.mc/config.json`

## Mitigation

```sh
av harden minio-mc
```
