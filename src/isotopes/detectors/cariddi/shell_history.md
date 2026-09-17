# cariddi-shell-history

```sh
rg -n 'cariddi' "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history"
```

Saved scanner commands can include authorization headers or other sensitive
arguments. This example prints matching history entries, including any secrets
in them; software with access to the history files can read the same text.

> ### What we check
>
> - Shell history contains cariddi header or custom secret-scanner arguments.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Mitigation

This finding concerns command text already recorded by the shell. A cariddi
wrapper cannot remove existing history safely or control every shell's history
policy. Remove the reported entries and avoid passing sensitive scanner
arguments on the command line.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
