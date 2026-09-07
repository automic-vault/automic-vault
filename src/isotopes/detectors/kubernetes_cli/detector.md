# kubernetes-cli Detector

## Trigger Conditions

- kubeconfig contains plaintext cluster credentials.

## Sensitive Files

- `$KUBECONFIG`
- `~/.kube/config`

## Hardening

Run `av harden kubectl`. The hardener supports one kubeconfig containing inline
bearer tokens or complete inline client certificate/key pairs. It stores each
credential as a Global Value and configures Kubernetes' native `ExecCredential`
protocol to request it from Automic Vault.

Unsupported, ambiguous, or unsafe kubeconfigs fail closed without being rewritten.
