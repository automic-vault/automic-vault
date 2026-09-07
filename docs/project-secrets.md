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
