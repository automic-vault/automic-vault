# aliyun-cli Detector

## Trigger Conditions

- Alibaba Cloud CLI config contains plaintext credentials.

## Sensitive Files

- `~/.aliyun/config.json`

## Hardening

Run `av harden aliyun-cli` to migrate AccessKey and STS profiles into Automic
Vault custody. The Hardener replaces inline credentials with Alibaba Cloud
CLI's native External credential provider and installs an eligible Isotope as
the gated Target.

OAuth, bearer-token, and private-key profiles remain report-only and are refused
by the Hardener.
