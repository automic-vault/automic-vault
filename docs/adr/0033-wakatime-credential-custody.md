# ADR 0033: WakaTime Credential Custody

## Decision

WakaTime's global API key is a Global Value applied only through the
`wakatime-cli` Authorization Gate. The Target must be the Automic Vault Isotope,
signed by the Automic Vault team with Hardened Runtime and no entitlements. The
Isotope invokes `/usr/local/bin/av wakatime-credential` directly and accepts the
key only for `https://api.wakatime.com/api/v1` with ordinary TLS verification,
no proxy, and no alternate key source.

The hardener configures WakaTime's native credential-helper setting and points
the editor-plugin executable path at that verified Target. It rejects project
keys, per-project API routes, imported credential config, alternate API URLs,
proxies, custom certificate files, and disabled TLS verification.

## Context

The upstream helper command is executed through a shell and receives no
destination context. WakaTime also loads per-project `.wakatime` configuration
after launch. A Gate around the unmodified binary therefore cannot prove the
effective destination and credential sources at Secret Application time.

## Consequences

The source patch and live Target verification close that gap. Unsupported
configurations fail closed instead of receiving the Global Value. Editor plugin
updaters may replace the managed link; Doctor will then report that the tool is
no longer in Hardened State and the replacement binary cannot use the Gate.
