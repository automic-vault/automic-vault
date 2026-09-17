# ordercli Detector

> ### What we check
>
> - ordercli session state is stored in plaintext config.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/ordercli/config.json`
> - `~/Library/Application Support/foodcli/config.json`
> - `~/Library/Application Support/foodoracli/config.json`

## Hardener Coverage

Run `sudo av harden ordercli` to install the signed ordercli Isotope and move
the supported Foodora session bundle behind the Automic Vault XPC service. The
config retains only provider metadata and `@av` custody markers; login, refresh,
cookie import, MFA, and logout update custody without writing secrets to disk.

Deliveroo config does not contain the detected credential fields and remains
unchanged.

[Learn about Hardeners](https://github.com/automic-vault/automic-vault#hardeners).
