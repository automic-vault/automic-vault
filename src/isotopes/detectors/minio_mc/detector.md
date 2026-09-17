# minio-mc

```sh
cat "$HOME/.mc/config.json"
```

This prints the file, including any MinIO alias credentials it contains.
Software running as you with read access can copy the same material.

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
