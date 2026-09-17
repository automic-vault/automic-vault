# envchain

Shell history can reveal the envchain namespaces you use to inject Secrets into
process environments. This is evidence of a credential-use path, not proof that
the history contains a Secret or that the Keychain permits unattended access.

> ### What we check
>
> - Shell history shows envchain namespaces storing environment secrets.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Mitigation

envchain is itself a keychain-backed environment injector. This detector reports
obvious namespace setup from shell history without moving platform keychain or
Secret Service entries.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
