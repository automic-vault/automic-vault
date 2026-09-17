# aws-cli-credentials-file

It is trivial for anything on your computer to exfiltrate AWS CLI’s secret:

```sh
cat "$HOME/.aws/credentials"
```

This prints the file, including any AWS access keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - AWS shared credentials file contains plaintext access keys.
>
> #### Sensitive Files
>
> - `$AWS_SHARED_CREDENTIALS_FILE`
> - `~/.aws/credentials`

## Mitigation

```sh
av harden aws
```

See the [hardening reference](../../hardeners/aws_cli.md) for setup and coverage.
