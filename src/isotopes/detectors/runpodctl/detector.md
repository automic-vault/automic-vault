# runpodctl

```sh
cat "$HOME/.runpod/config.toml"
```

This prints the file, including any RunPod API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - runpodctl config contains a plaintext API key.
>
> #### Sensitive Files
>
> - `~/.runpod/config.toml`
> - `~/.runpod.yaml`

## Mitigation

```sh
av harden runpodctl
```
