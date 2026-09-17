# mcp-remote Detector

> ### What we check
>
> - mcp-remote auth file contains plaintext OAuth credentials.
>
> #### Sensitive Files
>
> - `$MCP_REMOTE_CONFIG_DIR/**/server_tokens.json`
> - `~/.mcp-auth/**/server_tokens.json`

## Why This is not Yet Hardened

The retired `mcp-remote` hardener moved the detected secret to the macOS
Keychain, then recreated `$MCP_REMOTE_CONFIG_DIR/**/server_tokens.json` inside a
temporary directory for each run. We no longer consider a temporary plaintext
file a sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
