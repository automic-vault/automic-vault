# rust

```sh
cat "$HOME/.cargo/credentials.toml"
```

This prints the file, including any Cargo registry tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Cargo credentials contain a plaintext registry token.
>
> #### Sensitive Files
>
> - `$CARGO_HOME/credentials.toml`
> - `$CARGO_HOME/credentials`
> - `~/.cargo/credentials.toml`
> - `~/.cargo/credentials`

## Mitigation

The retired hardener moved the registry token to the macOS Keychain and changed
Cargo's credential-provider configuration to call `av credential-helper cargo`.
The current `av` CLI does not ship that credential-helper route. We need to
review Cargo's subprocess and approval boundaries before restoring it.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
