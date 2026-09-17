# sshpass Detector

> ### What we check
>
> - Shell history contains sshpass password material.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Why This is not Yet Hardened

sshpass can place SSH passwords in command history, process arguments, or
environment variables. This detector reports obvious shell history use and does
not try to migrate password-based SSH workflows.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
