# ADR 0042: Bind Wrangler Secret Use to a fixed signed runtime

Status: proposed

## Decision

The Wrangler Isotope uses a Node single-executable application as both Gate
Client and Target. Its embedded bootstrap disables external Node options,
checks the complete signed bundle, and requires root ownership without group
or other write access for every resource and ancestor before loading Wrangler.
The installed Target is `/opt/av/wrangler/Wrangler.app/Contents/MacOS/wrangler`.
Ordinary Node processes, npm caches, and per-project JavaScript are not Gate
Clients. npm entry points may delegate to the installed Target.

The in-process native XPC client captures the original native arguments and
binds each credential read to the Target and working directory. The app admits
only the Automic Vault signing identity at the installed path. OAuth access
and refresh tokens share one opaque Credential per profile in Secret Custody;
profile names use reversible hexadecimal encoding under `WRANGLER_AUTH_`.
The initial OAuth store supports Global Values only. A selected Project Value
fails closed so refresh cannot copy it into the Global Value mutation path.
Source-bound refresh and deletion are required before supporting Project Values.
Secret mutations use the existing approved mutation path. Credential reads use
the existing Authorization Request and recording-before-release path.

Every Wrangler credential read is initially Unknown and requires Approval.
A later reviewed command catalog can permit automic authorization. This is a
native credential-store integration, not environment-wrapper Secret routing.
Denial and transport failure do not fall back to upstream credential storage.

## Consequences

The Isotope pins its Wrangler version. It does not authenticate arbitrary
project-selected Wrangler versions, library API consumers, Vite, or Vitest.
Project code and build helpers can still observe Secrets after Application;
this is not process containment. Existing upstream credentials remain exposed
until explicitly removed. This decision does not weaken the Detector or claim
that installing the Isotope alone migrates credentials.
