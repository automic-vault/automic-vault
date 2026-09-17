# codex Detector

> ### What we check
>
> - Codex CLI auth file contains a plaintext API key, personal access token,
>   ChatGPT token set, Bedrock API key, or agent identity.
> - Codex CLI auth file exists but cannot be read or parsed.
>
> #### Sensitive Files
>
> - `${CODEX_HOME:-$HOME/.codex}/auth.json`

## Why This Matters

Codex caches login credentials in a plaintext file by default on every platform,
including macOS. The file is created mode `0600`, which stops other users but not
anything running as you. It holds a refresh token alongside any API key, so a
copy keeps working after the access token expires.

## Hardening

Run the configuration-only hardener:

```sh
av harden codex
```

Codex can store credentials in the system keyring itself, so the fix belongs in
its configuration rather than in a wrapper. The hardener sets
`cli_auth_credentials_store` to `keyring` in
`${CODEX_HOME:-$HOME/.codex}/config.toml`, runs `codex login`, confirms the new
login, and only then deletes the plaintext file left behind. It restores the
original configuration and preserves the plaintext credentials if login or
verification fails.

```toml
cli_auth_credentials_store = "keyring"
```

```sh
codex login
rm "${CODEX_HOME:-$HOME/.codex}/auth.json"
```

The last step matters. Changing the setting neither migrates nor removes the file
already on disk, so the plaintext copy survives until you delete it.

Prefer `keyring` over `auto` on a workstation. `auto` falls back to the plaintext
file when no keyring is available, while `keyring` fails loudly.

## ChatGPT Desktop Impact

Codex CLI, the IDE extension, and Codex inside the ChatGPT desktop app share
Codex configuration layers. The desktop app's Codex surface may ask you to sign
in again after this change. OpenAI's documentation does not specify whether this
CLI credential-storage setting affects the desktop app's existing session, so
close the app before changing it and expect to reauthenticate.
