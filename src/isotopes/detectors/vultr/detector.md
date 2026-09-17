# vultr

```sh
cat "$HOME/Library/Application Support/vultr-cli.yaml"
```

This prints the file, including any Vultr API keys it contains. Software running
as you with read access can copy the same material.

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
