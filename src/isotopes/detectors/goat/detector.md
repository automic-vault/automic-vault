# goat Detector

> ### What we check
>
> - goat auth session contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$XDG_STATE_HOME/goat/auth-session.json`
> - `~/.local/state/goat/auth-session.json`

## Hardener Coverage

`av harden goat` installs the signed goat Isotope and migrates the password,
access token, and refresh token into one DID-and-PDS-bound Secret. The file
retains only the DID, PDS origin, and reserved `@av` markers; the patched Target
uses fixed XPC operations rather than recreating plaintext files.

Unknown or incomplete session fields are refused. Explicit login credentials
provided through goat's command-line or environment interfaces remain outside
this stored-session Hardener and may still be exposed by those channels.
