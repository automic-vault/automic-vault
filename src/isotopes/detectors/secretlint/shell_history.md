# secretlint-shell-history

```sh
rg -n 'secretlint' "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history"
```

These history entries can show invocations that expose unmasked secrets. The
command prints saved command text; a matching invocation alone does not prove
that its output contained a credential.

> ### What we check
>
> - Shell history contains Secretlint invocations that can expose unmasked secrets.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Mitigation

This finding concerns command text already recorded by the shell. A Secretlint
wrapper cannot remove existing history safely or control every shell's history
policy. Remove the reported entries and avoid unmasked secret output in shell
commands.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
