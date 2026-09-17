# heroku

```sh
cat "$HOME/.netrc"
```

This prints the file, including any Heroku API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Heroku API token is stored in plaintext netrc.
>
> #### Sensitive Files
>
> - `$NETRC`
> - `~/.netrc`

## Mitigation

```sh
av harden heroku
```
