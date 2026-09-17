# composer Detector

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
