# ossutil

It is trivial for anything on your computer to exfiltrate ossutil’s secret:

```sh
cat "$HOME/.ossutilconfig"
```

This prints the file, including any Object Storage Service credentials it
contains. Software running as you with read access can copy the same material.

> ### What we check
>
> - ossutil config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.ossutilconfig`

## Mitigation

The retired `ossutil` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.ossutilconfig` inside a temporary directory for each run. We
no longer consider a temporary plaintext file a sufficient security boundary, so
this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
