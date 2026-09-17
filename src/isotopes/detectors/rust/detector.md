# rust Detector

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

## Why This is not Yet Hardened

The retired hardener moved the registry token to the macOS Keychain and changed
Cargo's credential-provider configuration to call `av credential-helper cargo`.
The current `av` CLI does not ship that credential-helper route. We need to
review Cargo's subprocess and approval boundaries before restoring it.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
