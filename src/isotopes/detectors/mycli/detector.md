# mycli Detector

## Trigger Conditions

- A mycli config contains a non-empty `password`, `passwd`, or `ssh_password`
  field.
- A mycli DSN contains a password in its URL user information.

## Sensitive Files

- `~/.myclirc`
- `$XDG_CONFIG_HOME/mycli/myclirc`
- `~/.config/mycli/myclirc`

## Why This is not Yet Hardened

The retired `mycli` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.myclirc` inside a temporary directory for each run. We no
longer consider a temporary plaintext file a sufficient security boundary, so
this detector remains report-only.

mycli natively supports [`use_keyring = True`](https://www.mycli.net/credentials).
With a password-free DSN, mycli prompts for the password on first use and stores
it in the system Keychain for later connections. This removes the
plaintext-config Exposure, and the Detector already ignores password-free DSNs.

The native keyring is a storage boundary, not an Automic Vault Secret Gate. It
does not bind Secret Application to a complete Authorization Request or produce
an Authorization Record, so it is not Automic Vault Hardened State. We do not
build an Isotope for mycli because signing its Python interpreter would not
authenticate the mutable application source and dependencies it loads.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
