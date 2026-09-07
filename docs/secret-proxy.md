# Secret Proxy

Secret Proxy lets a Target use named Secrets in HTTP/S requests without putting
the raw values in its environment or process memory through Automic
Vault.

```sh
$ av proxy +GITHUB_TOKEN +API_KEY -- node --use-env-proxy app.js
```

The Target receives a random Secret Reference for each name, plus standard
proxy and per-session CA environment variables. When a reference appears in an
HTTP/S URL path or query, header, or bounded body, Automic Vault asks whether to
apply the corresponding Secret to that exact destination. The choices are
Deny, Allow Once, and Allow for Session. Session approval binds the exact
canonical origin and exact Secret Names. Automic Vault never persists that
approval.

Every session start requires Approval. Secret Proxy has no Launcher rule,
durable destination rule, or project-directory policy for Secret Proxy.

## Security boundary

The proxy is a separately signed, sandboxed, Hardened Runtime helper without
Keychain authority. The Keychain-owning app records an allowed use before it
returns only the Secret values required for that request. Automic Vault never
gives the launched Target raw Secret values.

Secret References and the Proxy Credential are bearer values. Code that can
inspect an unhardened Target may steal them and reuse an origin already allowed
for the session. It still cannot ask the proxy to send the Secret to a different
origin without another Approval. The approval window reports weak Target
runtime protection; it does not block common interpreters such as Node.

The helper rejects private and reserved destinations, ambiguous DNS, invalid
upstream TLS, protocol upgrades, uninspectable content encodings, bodies over
10 MiB, and transactions exceeding 30 seconds. It never installs a CA in the
system trust store. Authorization History omits query values.

## Compatibility

The Target must use the standard proxy variables and accept one of the scoped
CA variables. Automic Vault supplies upper- and lower-case `HTTP_PROXY`,
`HTTPS_PROXY`, and `ALL_PROXY`, clears `NO_PROXY`, and supplies:

- `SSL_CERT_FILE`
- `NODE_EXTRA_CA_CERTS`
- `REQUESTS_CA_BUNDLE`
- `CURL_CA_BUNDLE`
- `GIT_SSL_CAINFO`
- `AWS_CA_BUNDLE`

`av proxy` refuses an existing proxy or CA environment unless
`--replace-existing-env` is supplied. Software that ignores proxy variables,
pins certificates, uses Security.framework trust, or uses a custom
network stack may fail or bypass the proxy. A bypass sends only inert Secret
References, not raw Secrets.

Credential transformations are not supported. If a Target hashes, signs,
encrypts, chunks, or otherwise transforms a Secret Reference before the proxy
sees it, Automic Vault releases no Secret and the upstream request fails. This
includes schemes such as AWS SigV4 unless the reference itself remains visible
in the request.

The helper inspects responses and replaces direct echoes of a Secret used for
that request with its Secret Reference. This is defense in depth, not a general
output-redaction guarantee; the helper cannot recognize transformed output.

Active sessions and their statistics appear under **Credential Proxies**. Ending a
session terminates only the proxy helper, not the Target. Its records remain in
Authorization History, which has one global 50-entry cap.

See [Canonical Domain Language](domain-language.md),
[Architecture](architecture.md), and
[ADR 0017](adr/0017-process-bound-secret-proxy.md) for the authoritative model.

## Application Example

For an application that reads a credential from its environment:

```js
const response = await fetch('https://api.example.com/me', {
  headers: { Authorization: `Bearer ${process.env.API_TOKEN}` },
});
```

store the Secret, then launch the application through the proxy:

```sh
$ av save API_TOKEN
$ av proxy +API_TOKEN -- node --use-env-proxy app.js
```

`API_TOKEN` is a random, session-specific Secret Reference inside the launched
Target. When that exact reference appears in an outbound request, the signed,
sandboxed proxy asks whether to apply the Secret to that destination. Approval
is required for the Proxy Session and each new destination; **Allow for
Session** remembers only that origin and Secret Name until the Target exits.

Use Node 24.5 or newer with [`--use-env-proxy`](https://nodejs.org/api/cli.html#--use-env-proxy)
for built-in `fetch`. Node also supports the flag in 22.21 or newer on the 22.x line. Other
clients must respect the supplied proxy and scoped CA environment variables.
See [Compatibility](#compatibility) and [Security boundary](#security-boundary)
for the requirements and limits.

## Keep Secrets out of `.env`

Leave non-secret project configuration in `.env`, but omit the Secret:

```dotenv
API_ORIGIN=https://api.example.com
# API_TOKEN comes from Automic Vault
```

Store a Project Value, then load the rest of `.env` normally:

```sh
$ av save --project-directory=. API_TOKEN
$ av proxy +API_TOKEN -- node --use-env-proxy --env-file=.env app.js
```

The working directory selects the Project Value. The loader must preserve an
existing `API_TOKEN`; an override option would replace the Secret Reference and
the proxy could not apply the Secret. Never write the reference into `.env`; it
is random and valid only for one Proxy Session.

For Varlock's resolver and its separate credential proxy, see [Varlock](varlock.md).
