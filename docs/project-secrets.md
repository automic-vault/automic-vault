# Project Secrets

A Secret Name can have one Global Value and multiple Project Values:

```sh
$ av save API_TOKEN
$ av save --project-directory=. API_TOKEN
```

When `av inject` requests `API_TOKEN`, Automic Vault selects the value for the
nearest physical project directory at or above the working directory. If no
Project Value matches, it selects the Global Value. The same `API_TOKEN` name
works across projects.

Selection follows physical parent directories on the same filesystem. It does
not inspect `.git` or cross a filesystem boundary.

The Project Directory selects a value and grants no authority. The same
name-based policy covers all Values of that Secret. A read failure for the
selected Value ends the request without trying another value.

## Multiline and exact input

`av save NAME` prompts for one hidden line. For a multiline Secret Value such as
a PEM, use:

```sh
$ av save --multiline --project-directory=. DEPLOY_PRIVATE_KEY
```

Input stays hidden. Press Ctrl-D after the final newline to finish. To finish
without a final newline, press Ctrl-D twice. Every received newline and space
is part of the Value; nothing is trimmed. Ctrl-C cancels without saving.
Terminal input still follows the terminal's line editing, line-length limits,
and newline processing.

For exact input from a pipe or redirected descriptor, use `av save --stdin NAME`.
This reads to EOF without trimming or newline conversion and refuses terminal
stdin. Both flags work with Global Values and `--project-directory` and cannot
be combined. Values must be nonempty UTF-8 without NUL bytes, at most 1 MiB.

Both input modes use the existing save Approval and Authorization Record path.
They do not retrieve existing Secrets or authorize later Secret Use. Keep the
producer's Secret output out of command arguments, environment variables,
logs, and plaintext files.

## dotenvx

For dotenvx, store the decryption key in Automic Vault and remove `.env.keys`:

```sh
$ av save --project-directory=. DOTENV_PRIVATE_KEY
$ av inject +DOTENV_PRIVATE_KEY -- dotenvx run -- npm test
```

dotenvx decrypts the project file only after Automic Vault authorizes applying
its project-selected key to that operation.

## mise

Mise supports external secret managers that populate its environment. Keep
Secret Values out of `mise.toml` and apply them only while running a task or
command:

```sh
$ av save --project-directory=. DATABASE_URL
$ av inject +DATABASE_URL -- mise run dev
$ av inject +DATABASE_URL -- mise exec -- npm test
```

The complete Authorization Request names `mise` as the Target. After Secret
Application, mise controls the Secret in the selected task or command and its
child processes.

For `.env` configuration with Secret References, see
[Secret Proxy](secret-proxy.md#keep-secrets-out-of-env).

See the [Domain Language](domain-language.md) and [Architecture](architecture.md)
for the authoritative terms and security boundaries.
