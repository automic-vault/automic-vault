# censys

```sh
cat "$HOME/.config/censys/censys.cfg"
```

This prints the file, including any Censys API credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Censys config contains plaintext API credentials.
>
> #### Sensitive Files
>
> - `~/.config/censys/censys.cfg`

## Mitigation

```sh
av harden censys
```
