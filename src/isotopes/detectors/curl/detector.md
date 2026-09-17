# curl

It is trivial for anything on your computer to exfiltrate curl’s secret:

```sh
cat "$HOME/.netrc"
```

This prints the file, including any stored request credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - curl netrc file contains plaintext credentials.
> - curl config contains plaintext auth material.
>
> #### Sensitive Files
>
> - `~/.netrc`
> - `~/.curlrc`

## Mitigation

curl reads credentials from generic request configuration shared across hosts
and protocols. There is no package-owned account store or single environment
variable that preserves `.netrc` and `.curlrc` routing semantics.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
