# helm Detector

> ### What we check
>
> - Helm repositories.yaml contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$HELM_REPOSITORY_CONFIG`
> - `$HELM_CONFIG_HOME/repositories.yaml`
> - `~/Library/Preferences/helm/repositories.yaml`

## Why This is not Yet Hardened

The retired `helm` hardener moved the detected secret to the macOS Keychain,
then recreated `$HELM_REPOSITORY_CONFIG` inside a temporary directory for each
run. We no longer consider a temporary plaintext file a sufficient security
boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
