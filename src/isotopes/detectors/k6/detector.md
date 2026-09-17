# k6

It is trivial for anything on your computer to exfiltrate k6’s secret:

```sh
cat "$HOME/Library/Application Support/k6/config.json"
```

This prints the file, including any k6 cloud tokens it contains. Software
running as you with read access can copy the same material.

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
