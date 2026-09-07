# Varlock

Install [Varlock](https://varlock.dev) and the published
[Automic Vault plugin](https://github.com/automic-vault/varlock-plugin):

```sh
$ npm install --save-dev varlock @automic-vault/varlock-plugin
$ av save API_TOKEN
```

Declare the Secret in `.env.schema`:

```dotenv
# @plugin(@automic-vault/varlock-plugin)
# @disableProcessEnvInjection
# ---
# @sensitive @required
API_TOKEN=av()
```

Load Varlock, then read the Secret through `ENV` rather than `process.env`:

```js
import 'varlock/auto-load';
import { ENV } from 'varlock/env';

const response = await fetch('https://api.example.com/me', {
  headers: { Authorization: `Bearer ${ENV.API_TOKEN}` },
});
```

The resolver infers the Automic Vault Secret Name from `API_TOKEN`. Use
`API_TOKEN=av(OTHER_SECRET_NAME)` when they differ. Secret Names must
be static so the Approval shows the complete set before any Secret Value is
released.

> [!IMPORTANT]
> Requires Automic Vault 3.9.0 or newer. Varlock currently requires one Approval
> on every run for the complete active Secret set. Automic Authorization and
> Blessings are not supported for the Varlock plugin yet.

## Keep the Application on Varlock Placeholders

Varlock also has its own credential proxy. It composes with the Automic Vault
resolver, so `.env.schema` can own the destination rule while Automic Vault
keeps custody of the Secret:

```dotenv
# @plugin(@automic-vault/varlock-plugin)
# @disableProcessEnvInjection
# ---
# @sensitive @required
# @proxy(domain="api.example.com")
API_TOKEN=av()
```

```sh
$ varlock proxy rules
$ varlock proxy run -- node app.js
```

You approve the complete active Secret set before Automic Vault releases it to
the live Varlock resolution process. Varlock gives the application a placeholder
and applies the real value only to requests matching the schema rule. This is a
[Varlock credential proxy](https://varlock.dev/guides/proxy/) session, not an
Automic Vault Proxy Session; don't nest it inside `av proxy` because both need
to own the process proxy and CA environment. Varlock's proxy is currently a
preview, so read its limitations before relying on its boundary.

See the [Domain Language](domain-language.md) and [Architecture](architecture.md)
for the authoritative terms and security boundaries.
