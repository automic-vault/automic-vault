# Fastly CLI Hardener

`av harden fastly-cli` installs the signed Fastly CLI Isotope and migrates
named static API tokens from Fastly's config into Automic Vault. The config
retains token metadata and the non-secret `@av` marker.

The patched Target accepts managed credentials only for Fastly's official API
endpoint. Token reads, stores, and deletes use fixed Fastly-only operations
through the signed `av` Gate Client. Each operation binds the live Fastly
Target, complete arguments, working directory, token name, endpoint, and
derived Secret Name.

SSO, legacy profiles, alternate API endpoints, and unknown auth fields fail
hardening without changing the file. Raw `--token` or `FASTLY_API_TOKEN`
credentials supplied for an individual invocation remain outside Automic
Vault custody. The Hardened State covers the selected Isotopes tap or
direct-install `fastly` Command; code signing does not establish user intent
or protect a token after the Target receives it.
