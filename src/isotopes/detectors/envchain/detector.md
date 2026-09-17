# envchain Detector

> ### What we check
>
> - Shell history shows envchain namespaces storing environment secrets.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Why This is not Yet Hardened

envchain is itself a keychain-backed environment injector. This detector reports
obvious namespace setup from shell history without moving platform keychain or
Secret Service entries.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
