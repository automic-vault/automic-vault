# oauth2l Detector

> ### What we check
>
> - oauth2l default cache contains plaintext OAuth tokens.
>
> #### Sensitive Files
>
> - `~/.oauth2l`

## Why This is not Yet Hardened

oauth2l stores fetched OAuth tokens in `~/.oauth2l` unless caching is disabled
or redirected. This detector reports that default plaintext cache without
changing oauth2l behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
