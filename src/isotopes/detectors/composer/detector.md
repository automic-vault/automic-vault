# composer

```sh
cat "$HOME/.composer/auth.json"
```

This prints the file, including any Composer repository credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Composer auth.json contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$COMPOSER_HOME/auth.json`
> - `$XDG_CONFIG_HOME/composer/auth.json`
> - `~/.composer/auth.json`
> - `~/Library/Application Support/Composer/auth.json`

## Mitigation

```sh
av harden composer
```
