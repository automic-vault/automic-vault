# maven

```sh
cat "$HOME/.m2/settings.xml"
```

This prints the file, including any Maven server credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Maven settings.xml contains plaintext server credentials.
>
> #### Sensitive Files
>
> - `~/.m2/settings.xml`

## Mitigation

The retired `maven` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.m2/settings.xml` inside a temporary directory for each run.
We no longer consider a temporary plaintext file a sufficient security boundary,
so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
