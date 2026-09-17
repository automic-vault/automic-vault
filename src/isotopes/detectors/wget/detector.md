# wget

```sh
cat "$HOME/.netrc"
```

This prints the file, including any stored request credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Wget netrc file contains plaintext credentials.
> - Wget config contains plaintext password options.
>
> #### Sensitive Files
>
> - `~/.netrc`
> - `~/.wgetrc`

## Mitigation

Wget can consume credentials from `~/.netrc` and from password options in
`~/.wgetrc`. Those are generic user config files rather than a stable
package-owned secret store.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
