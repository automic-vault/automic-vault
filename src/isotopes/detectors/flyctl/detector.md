# flyctl

It is trivial for anything on your computer to exfiltrate flyctl’s secret:

```sh
cat "$HOME/.fly/config.yml"
```

This prints the file, including any Fly.io access tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - flyctl config file contains a plaintext access token.
>
> #### Sensitive Files
>
> - `~/.fly/config.yml`

## Mitigation

```sh
av harden flyctl
```
