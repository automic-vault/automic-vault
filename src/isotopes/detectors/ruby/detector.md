# ruby Detector

> ### What we check
>
> - RubyGems credentials file contains plaintext API keys.
>
> #### Sensitive Files
>
> - `~/.gem/credentials`

## Why This is not Yet Hardened

RubyGems can store keys for multiple gem servers in one credentials file. The
CLI has no credential-provider interface that lets Automic Vault preserve that
server-to-key mapping without recreating the file.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
