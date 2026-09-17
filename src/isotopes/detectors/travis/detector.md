# travis

It is trivial for anything on your computer to exfiltrate travis’s secret:

```sh
cat "$HOME/.travis/config.yml"
```

This prints the file, including any Travis access tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Travis CLI config contains a plaintext access token.
>
> #### Sensitive Files
>
> - `~/.travis/config.yml`

## Mitigation

```sh
av harden travis
```
