# oci-cli

It is trivial for anything on your computer to exfiltrate oci-cli’s secret:

```sh
cat "${OCI_CLI_CONFIG_FILE:-$HOME/.oci/config}"
```

OCI configuration can expose inline credential material or identify a separate
private-key file. Reading a key path does not itself disclose the key; software
that can also read an unencrypted key file can copy that credential.

> ### What we check
>
> - OCI CLI config references plaintext credential material.
>
> #### Sensitive Files
>
> - `$OCI_CLI_CONFIG_FILE`
> - `~/.oci/config`

## Mitigation

The retired `oci-cli` hardener moved the detected secret to the macOS Keychain,
then recreated `$OCI_CLI_CONFIG_FILE` inside a temporary directory for each run.
We no longer consider a temporary plaintext file a sufficient security boundary,
so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
