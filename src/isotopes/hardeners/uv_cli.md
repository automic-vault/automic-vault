# uv Hardener

`av harden uv` installs the reviewed official `uv 0.12.12` executable under
`/opt/av/uv/0.12.12`, preserving its Developer ID signature and Hardened Runtime.
It installs root-owned `uv` and `uvx` launchers and a private `keyring` helper.
AV pins both the upstream archive and executable SHA-256 for arm64 and x86_64.
Updating the supported release requires another command-surface review.

The Hardener imports the selected plaintext `credentials.toml` into the protected
`UV_CREDENTIALS` Secret. This contains HTTP Basic credentials, including tokens
with the `__token__` username. Service paths and usernames remain distinct.
Unknown formats, HTTP services, bearer authentication, and duplicate entries are
rejected before migration. Existing AV values must match exactly; AV never
silently replaces them. The plaintext source is removed only after the official
installation verifies and the source still matches the imported snapshot.

Native Keychain credentials, `.netrc`, URL credentials, environment credentials,
and other stores are not migrated. Those remain independent Exposures and must
be removed or migrated separately. Hardening this store does not certify the
absence of ambient credentials. `uv auth login` still manages upstream stores;
it does not add credentials to AV custody.

Private indexes must provide a username (including `__token__` for token
credentials), or set `authenticate = "always"` on the index. For example:

```toml
[[tool.uv.index]]
name = "private"
url = "https://packages.example.com/simple/"
authenticate = "always"
```

The launcher enables `UV_KEYRING_PROVIDER=subprocess`. uv otherwise skips
subprocess lookup when no username is known. An explicit CLI provider override
can disable this integration. Registry URLs and usernames are configuration;
passwords remain in AV custody. No Python keyring installation is required.

The launcher registers the complete arguments, initial working directory, and
live process with the menu app. Registration returns a random nonce and grants
no Secret Use. When uv requests a credential, the menu app verifies the helper's
original parent, registered PID/start time/user/audit session, exact arguments,
pinned live code identity, Hardened Runtime, and current working directory. It
binds the first helper request to the Target's PID version, so another `exec`
cannot reuse the registration. Every credential request then goes through the
uv Authorization Gate and recording before release. The nonce alone grants no
authority. Unregistered and sibling processes cannot use the registration. A direct
child of uv can replace itself with the signed helper and preserve its parent
relationship. The nonce binds the full operation; it does not isolate Python or
package code inside that operation. Even `pip list` can execute a selected Python
interpreter, so these command families are Unknown and require Approval.

The keyring helper receives only the selected username/password, never the
credential bundle. Selection requires HTTPS, the same host and port, a service
path prefix at a segment boundary, and a matching username when specified.
The most specific path wins; ambiguous usernames fail closed. Scheme-less host
fallback is rejected to prevent an HTTP request from obtaining an HTTPS Secret.

The uv Gate defaults to Approval Required. No Python-capable operation can be
automically authorized, even under Full Access. `publish` can be authorized by
a Write Access policy because it uploads existing distributions without running
a selected Python interpreter.

## Reviewed credential-consuming commands

Reviewed against [uv 0.12.12](https://github.com/astral-sh/uv/tree/0.12.12):
the [command surface](https://github.com/astral-sh/uv/blob/0.12.12/crates/uv-cli/src/lib.rs),
[keyring protocol](https://github.com/astral-sh/uv/blob/0.12.12/crates/uv-auth/src/keyring.rs),
and [Python interpreter execution](https://github.com/astral-sh/uv/blob/0.12.12/crates/uv-python/src/interpreter.rs).
Registration occurs only for these command families. A command that does not
actually request keyring credentials produces no Secret Use or Approval.

| Commands | Classification | Credential use |
| --- | --- | --- |
| `add`, `remove`, `sync`, `lock`, `upgrade`, `tree`, `export`, `audit` | Unknown; Approval Required | Resolve dependencies and update project/lock state |
| `version` | Unknown; Approval Required | Version changes may re-lock and sync |
| `venv` / `virtualenv` / `v` | Unknown; Approval Required | Install seed packages |
| `pip compile`, `pip install`, `pip sync`, `pip uninstall` | Unknown; Approval Required | Resolve/install packages or fetch remote requirements |
| `pip list` / `pip ls`, `pip tree`, `tool list` / `tool ls` | Unknown; Approval Required | Look up outdated package versions |
| `tool install`, `tool upgrade` / `tool update` | Unknown; Approval Required | Resolve and install tools |
| `run`, `tool run` / `uvx`, `check`, `build` | Unknown; Approval Required | Resolve dependencies before running arbitrary code |
| `publish` | Remote Write | Upload packages |

Help, version display, auth commands, cache, Python management, workspace
inspection, local pip inspection, `init`, `format`, tool removal, and unknown
commands receive no registration. Unknown leading global options fail without
AV credentials. CLI options and alternate providers may disable the helper, but
cannot retrieve the protected Secret. `uv auth token` has no AV credential store
to dump. AV does not constrain a Target after it receives a credential. uv's mutable
configuration, TLS exceptions, custom certificate roots, and proxies remain
under its control. HTTPS scope matching does not independently verify its TLS
connection. See [ADR 0046](../../../docs/adr/0046-uv-registered-keyring-helper.md).

`av doctor uv` verifies the pinned executable, protected installation paths,
exact launchers, and private helper. Other installations remain callable, but
cannot use this credential helper without a registered operation.

The [dummy-only keyring probe](../../../scripts/check-uv-keyring.py) verifies
both upstream response formats, direct parent identity, plaintext schema, and
`auth token` exclusion. It does not exercise AV's signed XPC boundary.
