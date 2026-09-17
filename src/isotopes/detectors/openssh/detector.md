# openssh Detector

> ### What we check
>
> - SSH private key is stored without passphrase encryption.
> - SSH security-key handle is stored without passphrase encryption (medium severity).
>
> #### Sensitive Files
>
> - `~/.ssh/config`
> - `~/.ssh/id_*`
> - `identity files referenced by ~/.ssh/config`

## Why This is not Yet Hardened

Encrypt software SSH private keys with a passphrase and let Apple's OpenSSH
integration store it in the macOS Keychain. For FIDO security-key handles, a
passphrase is optional defense in depth because the signing key remains on the
authenticator.

FIDO `ecdsa-sk` and `ed25519-sk` files contain a key handle rather than the
hardware-bound signing key, so an unencrypted handle is reported at medium
severity instead of high.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
