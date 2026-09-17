# virustotal-cli

It is trivial for anything on your computer to exfiltrate virustotal-cli’s secret:

```sh
cat "$HOME/.vt.toml"
```

This prints the file, including any VirusTotal API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - VirusTotal config contains a plaintext API key.
>
> #### Sensitive Files
>
> - `~/.vt.toml`

## Mitigation

```sh
av harden virustotal-cli
```
