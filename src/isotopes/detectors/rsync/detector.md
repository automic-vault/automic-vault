# rsync Detector

> ### What we check
>
> - rsync password file contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.rsync_pass`
> - `~/.rsync-password`
> - `~/.rsync.pass`
> - `~/.rsyncd.conf`
> - `~/.config/rsync/rsyncd.conf`
> - `secrets files referenced by scanned rsync config`

## Why This is not Yet Hardened

rsync password files are selected per invocation and may serve unrelated remote
modules. A hardener cannot map one stored secret to the correct invocation
without owning that command's host and module policy. Prefer SSH transport or
inject `RSYNC_PASSWORD` explicitly for a known command.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
