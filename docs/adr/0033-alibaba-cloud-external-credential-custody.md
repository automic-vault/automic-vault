# ADR 0033: Apply Alibaba Cloud credentials through its External provider

Status: accepted

## Context

Alibaba Cloud CLI stores AccessKey and STS credentials in
`~/.aliyun/config.json`. Version 3.3 and later can instead execute an External
credential provider. The official macOS executable is Developer-ID signed, but
its enabled runtime exceptions make it ineligible for Secret Application.

## Decision

The Alibaba Cloud Hardener migrates only complete AccessKey and STS profiles to
profile-bound Secret Values and replaces their inline fields with a fixed
`/usr/local/bin/av aliyun-credential <profile>` External provider command. The
Gate accepts a request only from the trusted `av` helper whose live parent is
the exact configured `aliyun` Target, signed by Automic Vault with Hardened
Runtime and no enabled runtime exceptions. The requested profile and derived
Secret Name must match exactly, and the credential JSON is validated again at
Secret Application.

The Isotope is built from the upstream source tag without a credential patch.
It exists solely to supply an eligible Target identity and follows ADR 0031's
Homebrew-first, executable-only fallback policy. OAuth, bearer-token,
private-key, incomplete, and unknown credential modes fail closed.

## Consequences

Supported credentials are not written back to Alibaba Cloud configuration and
are disclosed only to a verified live CLI process through its native provider
protocol. Unsupported profiles remain detectable but cannot be partially
hardened. Running an upstream configuration command that restores an inline
secret makes the Detector report the file again.
