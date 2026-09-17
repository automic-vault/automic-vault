# twine

It is trivial for anything on your computer to exfiltrate twine’s secret:

```sh
cat "$HOME/.pypirc"
```

This prints the file, including any package-index credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Twine config contains plaintext package index credentials.
>
> #### Sensitive Files
>
> - `~/.pypirc`

## Mitigation

```sh
av harden twine
```
