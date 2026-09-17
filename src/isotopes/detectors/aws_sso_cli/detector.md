# aws-sso-cli Detector

> ### What we check
>
> - AWS SSO cache contains plaintext token or role credentials.
>
> #### Sensitive Files
>
> - `~/.aws/sso/cache/*.json`
> - `~/.aws/cli/cache/*.json`

## Why This is not Yet Hardened

aws-sso-cli manages AWS Identity Center flows and can share cache files with AWS
CLI and SDK tooling. This detector reports plaintext token and temporary
credential cache files without changing that shared state.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
