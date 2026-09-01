# kubectl Hardener

The kubectl hardener installs the signed, unmodified kubectl Isotope and rewrites one
safe kubeconfig to use Kubernetes' native `ExecCredential` protocol. Supported inline
bearer tokens and client certificate/key pairs move to Automic Vault before the
kubeconfig is replaced atomically.

The migration fails closed for multiple kubeconfig paths, basic authentication,
credential files, auth-provider plugins, pre-existing exec plugins, ambiguous
credentials, unsafe file ownership or permissions, and incomplete certificate pairs.
Clusters must use HTTPS with certificate verification enabled. Every credential
request initially requires approval and is bound to the exact kubeconfig user and
Kubernetes API server.
