# aliyun-cli

It is trivial for anything on your computer to exfiltrate aliyun-cli’s secret:

```sh
cat "$HOME/.aliyun/config.json"
```

This prints the file, including any Alibaba Cloud credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Alibaba Cloud CLI config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.aliyun/config.json`

## Mitigation

Run `av harden aliyun-cli` to migrate AccessKey and STS profiles into Automic
Vault custody. The Hardener replaces inline credentials with Alibaba Cloud
CLI's native External credential provider and installs an eligible Isotope as
the gated Target.

OAuth, bearer-token, and private-key profiles remain report-only and are refused
by the Hardener.

See the [hardening reference](../../hardeners/aliyun_cli.md) for setup and coverage.
