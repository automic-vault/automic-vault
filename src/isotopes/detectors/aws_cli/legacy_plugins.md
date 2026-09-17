# aws-cli-legacy-plugins

Legacy AWS CLI plugins run code inside credential-bearing CLI processes.
An unexpected plugin can use that access to copy your AWS credentials.

> ### What we check
>
> - AWS CLI legacy plugins are configured.
>
> #### Sensitive Files
>
> - `$AWS_CONFIG_FILE`
> - `~/.aws/config`

## Mitigation

Edit your configuration file and delete the legacy plugins section.

---

## Rationale

Legacy plugins are a trivial hook for malware to use to steal your keys.
