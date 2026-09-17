# buf

It is trivial for anything on your computer to exfiltrate buf’s secret:

```sh
cat "$HOME/.netrc"
```

This prints the file, including any Buf registry credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Buf registry token is stored in plaintext netrc.
>
> #### Sensitive Files
>
> - `~/.netrc`

## Mitigation

```sh
av harden buf
```
