# secretlint-persisted-report

```sh
cat "$HOME/secretlint-report.json"
```

This prints the file, including any secrets copied into a Secretlint report it
contains. Software running as you with read access can copy the same material.

> ### What we check
>
> - Secretlint report may contain persisted secret findings.
>
> #### Sensitive Files
>
> - `~/secretlint-report.json`
> - `~/secretlint-output.json`
> - `./secretlint-report.json`
> - `./secretlint-output.json`

## Mitigation

This finding concerns a report that may already contain copied secrets, not a
credential that Automic Vault can inject. Delete the report after reviewing it.
Preventing persistence requires Secretlint to redact findings or keep the report
in memory.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
