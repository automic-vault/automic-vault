# aws-cli-login-cache

```sh
cat "$HOME/.aws/login/cache/REPORTED_FILE.json"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any cached AWS access credentials it contains. Software running
as you with read access can copy the same material.

> ### What we check
>
> - AWS login cache contains cached access credentials.
>
> #### Sensitive Files
>
> - `~/.aws/login/cache/*.json`

## Mitigation

AWS CLI owns and refreshes the login cache as part of its authentication flow.
Moving individual cache entries would leave mutable session state split between
AWS CLI and Automic Vault. A safe hardener needs an upstream credential-provider
boundary that avoids copying cached access credentials back to disk.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
