# ordercli

```sh
cat "$HOME/Library/Application Support/ordercli/config.json"
```

This prints the file, including any Foodora session credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - ordercli session state is stored in plaintext config.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/ordercli/config.json`
> - `~/Library/Application Support/foodcli/config.json`
> - `~/Library/Application Support/foodoracli/config.json`

## Mitigation

Run `sudo av harden ordercli` to install the signed ordercli Isotope and move
the supported Foodora session bundle behind the Automic Vault XPC service. The
config retains only provider metadata and `@av` custody markers; login, refresh,
cookie import, MFA, and logout update custody without writing secrets to disk.

Deliveroo config does not contain the detected credential fields and remains
unchanged.

[Learn about Hardeners](https://github.com/automic-vault/automic-vault#hardeners).

See the [hardening reference](../../hardeners/ordercli.md) for setup and coverage.
