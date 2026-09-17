# aws-cli-credentials-file Detector

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
