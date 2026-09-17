# talosctl Detector

> ### What we check
>
> - talosctl config contains client credentials.
>
> #### Sensitive Files
>
> - `$TALOSCONFIG`
> - `$TALOS_HOME/config`
> - `~/.talos/config`

## Why This is not Yet Hardened

The retired `talosctl` hardener moved the detected secret to the macOS Keychain,
then recreated `$TALOSCONFIG` inside a temporary directory for each run. We no
longer consider a temporary plaintext file a sufficient security boundary, so
this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
