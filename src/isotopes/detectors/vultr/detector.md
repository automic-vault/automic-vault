# vultr Detector

> ### What we check
>
> - vultr-cli config contains a plaintext API key.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/vultr-cli.yaml`
> - `~/.vultr-cli.yaml`

## Mitigation

```sh
av harden vultr
```
