# gptcommit Detector

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
