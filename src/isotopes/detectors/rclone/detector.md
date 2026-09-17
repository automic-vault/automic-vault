# rclone

It is trivial for anything on your computer to exfiltrate rclone’s secret:

```sh
cat "${RCLONE_CONFIG:-$HOME/.config/rclone/rclone.conf}"
```

An unencrypted rclone config can expose credentials for multiple remotes. Some
stored values are obscured rather than encrypted; copying the file preserves
those values. An encrypted config instead requires its decryption password.

> ### What we check
>
> - rclone config file contains stored credentials.
>
> #### Sensitive Files
>
> - `$RCLONE_CONFIG`
> - `$XDG_CONFIG_HOME/rclone/rclone.conf`
> - `~/.config/rclone/rclone.conf`
> - `~/.rclone.conf`

## Mitigation

`av harden rclone` installs the signed rclone Isotope and uses rclone's native
configuration encryption. The wrapping password remains a Global Value in
Automic Vault and the verified rclone Target requests it through rclone's native
password-command interface.

Because one encrypted configuration contains every remote, one approved Secret
Application unlocks all configured remotes for that rclone process. The Gate
does not claim per-remote access control.

See the [hardening reference](../../hardeners/rclone.md) for setup and coverage.
