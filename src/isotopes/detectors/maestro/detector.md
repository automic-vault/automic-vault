# maestro

```sh
cat "$HOME/.mobiledev/authtoken"
```

This prints the file, including any Maestro Cloud tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Maestro Cloud token is stored in a plaintext token file.
> - Maestro Studio OpenAI token is stored in a plaintext token file.
>
> #### Sensitive Files
>
> - `~/.mobiledev/authtoken`
> - `~/.mobiledev/openaitoken`

## Mitigation

The retired `maestro` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.mobiledev/authtoken` inside a temporary directory for each
run. We no longer consider a temporary plaintext file a sufficient security
boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
