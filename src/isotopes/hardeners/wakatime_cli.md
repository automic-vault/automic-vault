# WakaTime CLI

The hardener installs the signed WakaTime CLI Isotope, migrates the global API
key into Automic Vault, and configures WakaTime's native credential helper.
Editor plugins are pointed at the verified Target without storing the key in a
file.

The Isotope accepts the global key only for WakaTime's official API endpoint.
Project-specific keys, alternate API URLs, proxies, custom certificate files,
and disabled TLS verification must be removed before hardening.
