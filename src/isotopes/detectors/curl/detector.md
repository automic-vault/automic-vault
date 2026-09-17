# curl Detector

> ### What we check
>
> - curl netrc file contains plaintext credentials.
> - curl config contains plaintext auth material.
>
> #### Sensitive Files
>
> - `~/.netrc`
> - `~/.curlrc`

## Why This is not Yet Hardened

curl reads credentials from generic request configuration shared across hosts
and protocols. There is no package-owned account store or single environment
variable that preserves `.netrc` and `.curlrc` routing semantics.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
