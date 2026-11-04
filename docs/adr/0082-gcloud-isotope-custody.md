# gcloud user OAuth custody in a fixed Python runtime

Status: accepted; release requires protected-installation OAuth validation

## Decision

The gcloud Isotope preserves upstream user OAuth login and replaces its
credential store, access-token cache, and legacy credential-file writer. It
supports the default Google universe only. Each account has a Global Value
under `GCLOUD_AUTH_` followed by the uppercase hexadecimal UTF-8 account name.
Project Values are rejected to prevent refresh from copying them into global
custody. Account names may remain in local configuration; they grant no authority.

The native `gcloud` executable embeds an isolated Python interpreter and is both
Gate Client and Target. Before executing Python it validates the complete signed
bundle, root ownership, effective write protection, and resource containment.
The interpreter, standard library, SDK and native extensions are pinned and
sealed together under `/opt/av/gcloud/Gcloud.app`. Effective configuration is frozen in memory before command execution; resolved
account, project, billing project, and universe accompany the bound request.
No Python command-line modes,
external import paths, user site packages, or startup hooks are accepted.
Upstream component installation and self-update cannot change this runtime.

Credential reads use the existing complete-request `keys` authorization path,
including recording before release. Native code captures the original arguments
and working directory. Reads initially classify as Unknown and require Approval.
Save and delete use dedicated namespace-restricted operations and the existing
approved mutation transaction. Only an explicit missing-item result means logged
out; denial and transport failure never fall back to upstream credential storage.

Access tokens remain in process memory. Refresh-token changes require an approved
mutation, with stale-write protection against the previously loaded credential.
Logout cannot delete a concurrently replaced credential. The approved Target can
observe the credential after Secret Application; this is not process containment.

The first supported workflow is ordinary user OAuth. ADC export, service-account
keys, federation, alternate token endpoints, impersonation, companion tools and
credential-file overrides, flags files, remote-bootstrap login, `init`, and
alpha/beta/preview commands are rejected in the protected workflow. Existing
upstream credential files are not imported or deleted implicitly. Users revoke
old sessions before logging in through the Isotope; installation alone does not
remove existing Exposures.

## Distribution and verification

The fork owns its signed release archive. The tap pins its exact URL and digest;
the Hardener owns protected installation and updates, following ADRs 0029 and
0042. Doctor verifies the bundle and receipt. Runtime and app checks remain
mandatory independently of Doctor. Release checks cover the packaged artifact,
credential storage/refresh/deletion, denial, missing and malformed replies,
unsupported authentication, and attempts to redirect Python loading.

This decision changes av4 only. It does not introduce an av5 credential endpoint.
