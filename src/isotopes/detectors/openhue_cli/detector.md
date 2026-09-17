# openhue-cli Detector

> ### What we check
>
> - OpenHue config contains a plaintext Hue application key.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/openhue/config.yaml`
> - `~/.openhue/config.yaml`

## Remediation

Run `av harden openhue-cli`. The hardener installs the signed OpenHue CLI
Isotope and migrates the Hue application key into Automic Vault custody while
leaving only bridge metadata and an `@av` marker on disk.

Upstream OpenHue CLI has no credential-helper boundary: its Hue application
key shares a YAML config with non-secret bridge and logging metadata. The
Isotope therefore patches config reads and setup writes to use authenticated
XPC operations. The Detector covers a non-empty `key` scalar in the active
`XDG_CONFIG_HOME/openhue/config.yaml` or `~/.openhue/config.yaml`.

The residual gap is other users' configs, backups, and the inactive config
root when `XDG_CONFIG_HOME` selects the other location. Unsupported YAML is
refused by the hardener rather than silently rewritten.
