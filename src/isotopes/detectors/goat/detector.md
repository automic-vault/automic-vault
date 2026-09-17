# goat

It is trivial for anything on your computer to exfiltrate goat’s secret:

```sh
cat "$HOME/.local/state/goat/auth-session.json"
```

This prints the file, including any goat session credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - goat auth session contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$XDG_STATE_HOME/goat/auth-session.json`
> - `~/.local/state/goat/auth-session.json`

## Mitigation

`av harden goat` installs the signed goat Isotope and migrates the password,
access token, and refresh token into one DID-and-PDS-bound Secret. The file
retains only the DID, PDS origin, and reserved `@av` markers; the patched Target
uses fixed XPC operations rather than recreating plaintext files.

Unknown or incomplete session fields are refused. Explicit login credentials
provided through goat's command-line or environment interfaces remain outside
this stored-session Hardener and may still be exposed by those channels.

See the [hardening reference](../../hardeners/goat.md) for setup and coverage.
