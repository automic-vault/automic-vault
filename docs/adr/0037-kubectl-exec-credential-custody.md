# ADR 0037: kubectl ExecCredential Custody

- Status: Accepted
- Date: 2026-09-01

## Context

kubeconfig can contain bearer tokens, client certificates, and private keys in
plaintext. Kubernetes supports an `ExecCredential` plugin, but its request
describes the cluster rather than the kubectl operation. Upstream macOS kubectl
releases are ad-hoc signed and therefore do not provide the Developer ID,
Hardened Runtime Target identity required by an Automic Vault Authorization
Gate.

## Decision

The kubectl hardener installs an unmodified Automic Vault Isotope signed with
Developer ID, Hardened Runtime, and no entitlements. It migrates supported inline
bearer tokens and complete inline client certificate/key pairs to Global Values,
then rewrites one kubeconfig to invoke `/usr/local/bin/av kubectl-credential`
through Kubernetes' native version-one `ExecCredential` protocol.

The Gate Client and menu helper independently bind each request to the exact
kubeconfig user, Kubernetes API server, credential kind, live parent kubectl
Target, and complete parent arguments. Unknown fields, multiple kubeconfig
paths, basic authentication, credential files, auth-provider plugins,
pre-existing exec plugins, ambiguous credentials, and unsafe filesystem state
fail closed. Cluster endpoints must use HTTPS with certificate verification
enabled. The Authorization Record is persisted before the credential is released.

## Consequences

kubectl receives the credential format it natively expects without a source
patch. The Isotope signature protects Target integrity but does not prove
operation intent. Every request therefore classifies as Unknown and initially
requires Approval. `ExecCredential` caching may retain the credential within the
verified kubectl process until its normal cache invalidation boundary; Automic
Vault does not claim per-API-operation authorization.
