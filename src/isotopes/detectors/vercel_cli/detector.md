# vercel-cli Detector

> ### What we check
>
> - Vercel CLI auth config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/Library/Application Support/com.vercel.cli/auth.json`
> - `~/.local/share/com.vercel.cli/auth.json`
> - `~/.now/auth.json`
> - `~/Library/Application Support/now/auth.json`
> - `~/.local/share/now/auth.json`
> - `~/.vercel/auth.json`
> - `$XDG_DATA_HOME/com.vercel.cli/auth.json`
> - `$XDG_DATA_HOME/now/auth.json`

## Why This is not Yet Hardened

Current Vercel CLI reads and writes `auth.json` in the global config directory.
That file can contain both an access token and a refresh token, and the CLI
updates it after token refreshes or reauthentication.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
