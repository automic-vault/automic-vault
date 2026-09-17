# oauth2l

It is trivial for anything on your computer to exfiltrate oauth2l’s secret:

```sh
cat "$HOME/.oauth2l"
```

This prints the file, including any cached OAuth tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - oauth2l default cache contains plaintext OAuth tokens.
>
> #### Sensitive Files
>
> - `~/.oauth2l`

## Mitigation

oauth2l stores fetched OAuth tokens in `~/.oauth2l` unless caching is disabled
or redirected. This detector reports that default plaintext cache without
changing oauth2l behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
