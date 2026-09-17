# rsync

It is trivial for anything on your computer to exfiltrate rsync’s secret:

```sh
cat "$HOME/.rsync_pass"
```

This prints the file, including any rsync passwords it contains. Software
running as you with read access can copy the same material.

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

## Mitigation

rsync password files are selected per invocation and may serve unrelated remote
modules. A hardener cannot map one stored secret to the correct invocation
without owning that command's host and module policy. Prefer SSH transport or
inject `RSYNC_PASSWORD` explicitly for a known command.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
