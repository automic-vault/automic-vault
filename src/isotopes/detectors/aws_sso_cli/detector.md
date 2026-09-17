# aws-sso-cli

```sh
cat "$HOME/.aws/sso/cache/REPORTED_FILE.json"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any AWS SSO tokens or temporary credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - AWS SSO cache contains plaintext token or role credentials.
>
> #### Sensitive Files
>
> - `~/.aws/sso/cache/*.json`
> - `~/.aws/cli/cache/*.json`

## Mitigation

aws-sso-cli manages AWS Identity Center flows and can share cache files with AWS
CLI and SDK tooling. This detector reports plaintext token and temporary
credential cache files without changing that shared state.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
