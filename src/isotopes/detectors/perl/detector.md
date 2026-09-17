# perl

```sh
cat "$HOME/.cpan/CPAN/MyConfig.pm"
```

This prints the file, including any CPAN repository credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - CPAN config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.cpan/CPAN/MyConfig.pm`
> - `~/.cpan/CPAN/Config.pm`
> - `~/.cpan/CPAN/Config_local.pm`

## Mitigation

CPAN configuration can hold multiple repository identities alongside unrelated
Perl settings. Perl does not provide a narrow credential-provider boundary that
Automic Vault can replace without rewriting shared user configuration.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
