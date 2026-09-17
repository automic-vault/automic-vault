# sshpass

It is trivial for anything on your computer to exfiltrate sshpass’s secret:

```sh
rg -n 'sshpass' "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history"
```

A password passed to sshpass can survive in shell history. This example prints
matching entries, including any recorded password; software with access to the
history file can retrieve it too.

> ### What we check
>
> - Shell history contains sshpass password material.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Mitigation

sshpass can place SSH passwords in command history, process arguments, or
environment variables. This detector reports obvious shell history use and does
not try to migrate password-based SSH workflows.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
