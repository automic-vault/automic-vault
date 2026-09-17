# aws-vault Detector

> ### What we check
>
> - AWS config invokes aws-vault as an ambient credential_process.
> - aws-vault file backend directory contains credential vault files.
>
> #### Sensitive Files
>
> - `~/.aws/config`
> - `~/.awsvault/keys/*`

## Why This is not Yet Hardened

aws-vault is already a credential manager, so this detector does not move its
backend data. It reports AWS config entries that invoke aws-vault and the
default file backend directory when present.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
