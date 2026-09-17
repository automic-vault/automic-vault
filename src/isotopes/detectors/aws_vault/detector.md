# aws-vault

An AWS `credential_process` entry can let software invoke aws-vault to obtain
credentials through your existing authentication setup. Automic Vault reports
that configuration and file-backend state without invoking aws-vault or
assuming that a detected vault file is unencrypted.

> ### What we check
>
> - AWS config invokes aws-vault as an ambient credential_process.
> - aws-vault file backend directory contains credential vault files.
>
> #### Sensitive Files
>
> - `~/.aws/config`
> - `~/.awsvault/keys/*`

## Mitigation

aws-vault is already a credential manager, so this detector does not move its
backend data. It reports AWS config entries that invoke aws-vault and the
default file backend directory when present.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
