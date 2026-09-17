# cariddi-persisted-output Detector

> ### What we check
>
> - cariddi default output can contain discovered secrets.
>
> #### Sensitive Files
>
> - `~/output-cariddi/secrets/**`
> - `./output-cariddi/secrets/**`

## Why This is not Yet Hardened

This finding concerns secret-bearing scan output left behind by cariddi, not a
credential that Automic Vault can inject at runtime. Delete the reported output
after reviewing it. Preventing persistence requires a change in cariddi's output
handling.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
