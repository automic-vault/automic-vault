# perl Detector

> ### What we check
>
> - CPAN config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.cpan/CPAN/MyConfig.pm`
> - `~/.cpan/CPAN/Config.pm`
> - `~/.cpan/CPAN/Config_local.pm`

## Why This is not Yet Hardened

CPAN configuration can hold multiple repository identities alongside unrelated
Perl settings. Perl does not provide a narrow credential-provider boundary that
Automic Vault can replace without rewriting shared user configuration.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
