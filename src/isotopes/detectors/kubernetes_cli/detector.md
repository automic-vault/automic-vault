# kubernetes-cli

```sh
cat "$HOME/.kube/config"
```

This prints the file, including any Kubernetes cluster credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - kubeconfig contains plaintext cluster credentials.
>
> #### Sensitive Files
>
> - `$KUBECONFIG`
> - `~/.kube/config`

## Mitigation

Run `av harden kubectl`. The hardener supports one kubeconfig containing inline
bearer tokens or complete inline client certificate/key pairs. It stores each
credential as a Global Value and configures Kubernetes' native `ExecCredential`
protocol to request it from Automic Vault.

Unsupported, ambiguous, or unsafe kubeconfigs fail closed without being rewritten.

See the [hardening reference](../../hardeners/kubectl.md) for setup and coverage.
