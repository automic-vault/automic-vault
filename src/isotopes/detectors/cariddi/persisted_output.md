# cariddi-persisted-output

It is trivial for anything on your computer to exfiltrate cariddi’s secret:

```sh
cat "$HOME/output-cariddi/secrets/REPORTED_FILE"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any secrets discovered by cariddi it contains. Software running
as you with read access can copy the same material.

> ### What we check
>
> - cariddi default output can contain discovered secrets.
>
> #### Sensitive Files
>
> - `~/output-cariddi/secrets/**`
> - `./output-cariddi/secrets/**`

## Mitigation

This finding concerns secret-bearing scan output left behind by cariddi, not a
credential that Automic Vault can inject at runtime. Delete the reported output
after reviewing it. Preventing persistence requires a change in cariddi's output
handling.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
