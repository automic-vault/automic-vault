# aws-cli-legacy-plugins Detector

> ### What we check
>
> - AWS CLI legacy plugins are configured.
>
> #### Sensitive Files
>
> - `$AWS_CONFIG_FILE`
> - `~/.aws/config`

## Rationale

Legacy plugins are a trivial hook for malware to use to steal your keys.

## Mitigation

Edit your configuration file and delete the legacy plugins section.
