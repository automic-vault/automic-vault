# ruby

It is trivial for anything on your computer to exfiltrate ruby’s secret:

```sh
cat "$HOME/.gem/credentials"
```

This prints the file, including any RubyGems API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - RubyGems credentials file contains plaintext API keys.
>
> #### Sensitive Files
>
> - `~/.gem/credentials`

## Mitigation

RubyGems can store keys for multiple gem servers in one credentials file. The
CLI has no credential-provider interface that lets Automic Vault preserve that
server-to-key mapping without recreating the file.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
