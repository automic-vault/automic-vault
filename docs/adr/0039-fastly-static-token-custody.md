# ADR 0039: Fastly static token custody

- Status: Accepted
- Date: 2026-09-01

## Context

Fastly CLI stores named API tokens in its user config. It supports static and
SSO credentials, raw token flags and environment variables, named token
selection, and configurable API endpoints. Upstream's macOS release is a
single Go executable but is only linker/ad-hoc signed, so it cannot establish
the Target identity required for Automic Vault Secret Application.

## Decision

Automic Vault publishes a Developer ID-signed, Hardened Runtime Fastly Isotope
with no entitlements. The Isotope replaces supported named static tokens with
`@av` markers and uses fixed `fastly-credential` operations through the signed
`av` Gate Client. SSO and legacy profile commands fail closed in the Isotope.

The Hardener accepts only named static tokens and Fastly's official
`https://api.fastly.com` endpoint. It stores every plaintext token before
atomically replacing the config, refuses unsupported auth fields, and verifies
that every pre-existing marker has a matching Secret Name before making
changes.

The menu helper verifies the Gate Client and its live Fastly parent, including
the configured Target path, identifier `fastly`, Automic Vault team identity,
Developer ID signature, Hardened Runtime, and absence of entitlements. It binds
the Authorization Request to the complete Target arguments, working directory,
token name, official endpoint, and derived Secret Name, then revalidates those
claims immediately before Secret Application.

Fastly's broad command surface does not provide an independently authenticated
operation intent signal. API operations therefore classify as Unknown and
require Approval. `auth token` and `auth show --reveal` classify as Secret
Dumps.

## Consequences

Named static tokens can remain in Secret Custody without recreating plaintext
config files. Authentication changes made through the Isotope store or delete
the corresponding Secret Value through explicit mutation approvals.

SSO, legacy profiles, alternate endpoints, and unknown future auth fields are
unsupported rather than silently weakened. Raw `--token` and
`FASTLY_API_TOKEN` values supplied for an invocation remain outside Automic
Vault custody. The verified Fastly Target necessarily receives an approved
token in memory; Automic Vault cannot control it after Secret Application.
