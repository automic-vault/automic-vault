# cariddi-shell-history Detector

> ### What we check
>
> - Shell history contains cariddi header or custom secret-scanner arguments.
>
> #### Sensitive Files
>
> - `~/.zsh_history`
> - `~/.bash_history`
> - `~/.history`

## Why This is not Yet Hardened

This finding concerns command text already recorded by the shell. A cariddi
wrapper cannot remove existing history safely or control every shell's history
policy. Remove the reported entries and avoid passing sensitive scanner
arguments on the command line.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
