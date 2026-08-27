# rclone Detector

## Trigger Conditions

- rclone config file contains stored credentials.

## Sensitive Files

- `$RCLONE_CONFIG`
- `$XDG_CONFIG_HOME/rclone/rclone.conf`
- `~/.config/rclone/rclone.conf`
- `~/.rclone.conf`

## Hardening

`av harden rclone` installs the signed rclone Isotope and uses rclone's native
configuration encryption. The wrapping password remains a Global Value in
Automic Vault and the verified rclone Target requests it through rclone's native
password-command interface.

Because one encrypted configuration contains every remote, one approved Secret
Application unlocks all configured remotes for that rclone process. The Gate
does not claim per-remote access control.
