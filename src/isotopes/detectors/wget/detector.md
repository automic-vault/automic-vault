# wget Detector

> ### What we check
>
> - Wget netrc file contains plaintext credentials.
> - Wget config contains plaintext password options.
>
> #### Sensitive Files
>
> - `~/.netrc`
> - `~/.wgetrc`

## Why This is not Yet Hardened

Wget can consume credentials from `~/.netrc` and from password options in
`~/.wgetrc`. Those are generic user config files rather than a stable
package-owned secret store.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
