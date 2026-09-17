# gptcommit

```sh
cat "$HOME/.config/gptcommit/config.toml"
```

This prints the file, including any gptcommit API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - gptcommit global config contains a plaintext API key.
> - gptcommit repository config contains a plaintext API key.
>
> #### Sensitive Files
>
> - `~/.config/gptcommit/config.toml`
> - `./gptcommit.toml`

## Mitigation

```sh
av harden gptcommit
```
