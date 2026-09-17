# qwen-code

It is trivial for anything on your computer to exfiltrate qwen-code’s secret:

```sh
cat "$HOME/.qwen/settings.json"
```

This prints the file, including any Qwen Code API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Qwen Code settings contain plaintext API keys.
>
> #### Sensitive Files
>
> - `~/.qwen/settings.json`

## Mitigation

```sh
av harden qwen-code
```
