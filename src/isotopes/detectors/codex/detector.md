# codex

It is trivial for anything on your computer to exfiltrate codex’s secret:

```sh
cat "${CODEX_HOME:-$HOME/.codex}/auth.json"
```

This prints the file, including any Codex login credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Codex CLI auth file contains a plaintext API key, personal access token,
>   ChatGPT token set, Bedrock API key, or agent identity.
> - Codex CLI auth file exists but cannot be read or parsed.
>
> #### Sensitive Files
>
> - `${CODEX_HOME:-$HOME/.codex}/auth.json`

## Mitigation

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

See the [hardening reference](../../hardeners/codex.md) for setup and coverage.

---

## Why This Matters

Codex caches login credentials in a plaintext file by default on every platform,
including macOS. The file is created mode `0600`, which stops other users but not
anything running as you. It holds a refresh token alongside any API key, so a
copy keeps working after the access token expires.

## ChatGPT Desktop Impact

Codex CLI, the IDE extension, and Codex inside the ChatGPT desktop app share
Codex configuration layers. The desktop app's Codex surface may ask you to sign
in again after this change. OpenAI's documentation does not specify whether this
CLI credential-storage setting affects the desktop app's existing session, so
close the app before changing it and expect to reauthenticate.
