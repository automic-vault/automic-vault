# tailscale

```sh
cat "$HOME/.local/share/tailscale/tailscaled.state"
```

This prints the file, including any Tailscale node identity state it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Tailscale state file contains plaintext node identity state.
>
> #### Sensitive Files
>
> - `/Library/Tailscale/tailscaled.state`
> - `~/.local/share/tailscale/tailscaled.state`
> - `/opt/homebrew/var/lib/tailscale/tailscaled.state`
> - `/usr/local/var/lib/tailscale/tailscaled.state`
> - `$XDG_DATA_HOME/tailscale/tailscaled.state`

## Mitigation

The Homebrew `tailscale` package installs both `tailscale` and `tailscaled`. The
sensitive identity state belongs to `tailscaled`, not the CLI. Upstream macOS
app builds can use Keychain-backed state, but the Homebrew/self-compiled daemon
path is treated as plaintext state.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
