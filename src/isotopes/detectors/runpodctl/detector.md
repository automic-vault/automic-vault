# runpodctl Detector

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
