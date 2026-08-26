# wakatime-cli Detector

## Trigger Conditions

- WakaTime config contains plaintext API keys.

## Sensitive Files

- `~/.wakatime.cfg`

## Remediation

Run `av harden wakatime-cli`. The hardener installs the signed WakaTime CLI
Isotope, stores the global API key in Automic Vault, configures the native
credential helper, and points editor plugins at the verified Target.

Project-specific API keys and alternate credential destinations are rejected;
remove them manually before hardening.
