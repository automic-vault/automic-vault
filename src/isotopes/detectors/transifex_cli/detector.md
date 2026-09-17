# transifex-cli

```sh
cat "$HOME/.transifexrc"
```

This prints the file, including any Transifex credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Transifex root config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.transifexrc`

## Mitigation

```sh
av harden transifex-cli
```
