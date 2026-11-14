# npm launchers and Node version managers

The `node` Hardener installs an npm launcher with one fixed Target path. If that
Target remains executable, `av harden node` keeps it even when another npm is
first on PATH. `nvm use` changes shell resolution; it does not retarget the
installed launcher. Putting `/usr/local/bin` first restores the pinned npm,
which may differ from the version selected by nvm.

There is currently no supported CLI or GUI operation to retarget an existing
launcher while preserving its protected route through an atomic replacement
and rollback. Cancel hardening if the confirmation shows the wrong Target.
Keep the existing Target installed. Do not edit or bless a dynamic replacement
stub, delete the vaulted token, or copy it back into `.npmrc`.

## Inspect the existing route

Run `av doctor node --json` and inspect the reported Target and any command
resolution findings. Inspect the generated launcher at `/usr/local/bin/npm`
without executing it; it names the pinned Target. Run `command -v npm` after
`nvm use` to check which entry point your shell selects. Doctor verifies the
installed intervention; it does not prove that a different npm invocation uses
that route.

## Use another Node version for one authenticated operation

You can leave the existing launcher, Secret, and npm Gate policy in place and
explicitly request an operation through the Direct Secret Gate. After selecting
the desired Node version, verify that `NVM_BIN` names that installation, then:

```sh
av inject +NODE_AUTH_TOKEN -- "$NVM_BIN/node" "$NVM_BIN/../lib/node_modules/npm/bin/npm-cli.js" install
```

Replace `install` with the operation you intend to give the credential to. Keep
the `${NODE_AUTH_TOKEN}` reference in the npm configuration that hardening
migrated. This request uses the Direct Secret Gate, whose default is Approval
Required; it does not use the npm-specific policy or automatically determine
whether the command needs the token. The token reaches npm and its child
processes, including lifecycle scripts. Only use this route for code you intend
to receive that authority.

This one-off invocation does not retarget the installed launcher, so there is
no launcher change to roll back. The old pinned installation remains the
existing route. For commands that need no credential, use ordinary npm without
the protected token. If an unset config reference prevents that, an empty
`NODE_AUTH_TOKEN` supplies no credential, for example `NODE_AUTH_TOKEN= npm --version`.

See the [domain language](domain-language.md) and [architecture](architecture.md)
for the distinction between Tool-specific policy and Direct Secret Application.
