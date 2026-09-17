# heroku Detector

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
