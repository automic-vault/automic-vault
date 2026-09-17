# cloudsmith-cli

It is trivial for anything on your computer to exfiltrate cloudsmith-cli’s secret:

```sh
cat "$HOME/Library/Application Support/cloudsmith/credentials.ini"
```

This prints the file, including any Cloudsmith API keys it contains. Software
running as you with read access can copy the same material.

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
