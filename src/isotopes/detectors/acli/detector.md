# acli

It is trivial for anything on your computer to exfiltrate acli’s secret:

```sh
cat "$HOME/.config/acli/confluence_config.yaml"
```

This prints the file, including any Atlassian credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Atlassian CLI credentials are stored in plaintext config.
>
> #### Sensitive Files
>
> - `~/.config/acli/confluence_config.yaml`
> - `~/.config/acli/jira_config.yaml`
> - `~/.config/acli/assets_config.yaml`
> - `~/.config/acli/rovodev_config.yaml`
> - `~/.config/acli/brie_config.yaml`
> - `~/.config/acli/global_auth_config.yaml`
> - `~/.config/acli/global_config.yaml`
> - `~/.config/acli/admin_config.yaml`

## Mitigation

The retired `acli` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.config/acli/confluence_config.yaml` inside a temporary
directory for each run. We no longer consider a temporary plaintext file a
sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
