# nuget

It is trivial for anything on your computer to exfiltrate nuget’s secret:

```sh
cat "$HOME/.config/NuGet/NuGet.Config"
```

This prints the file, including any NuGet package credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - NuGet user config contains package credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/NuGet/NuGet.Config`
> - `~/.config/NuGet/NuGet.Config`
> - `~/.nuget/NuGet/NuGet.Config`

## Mitigation

The retired `nuget` hardener moved the detected secret to the macOS Keychain,
then recreated `$XDG_CONFIG_HOME/NuGet/NuGet.Config` inside a temporary
directory for each run. We no longer consider a temporary plaintext file a
sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
