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

## GKE and other external credential plugins

Kubeconfigs generated for GKE commonly use `gke-gcloud-auth-plugin` in a user’s
`exec` field. The hardener cannot migrate that route. Its ExecCredential support
is for the exact Automic Vault helper it installs for supported inline
credentials; it does not wrap arbitrary existing plugins.

Keep your existing plugin configuration intact. Do not replace short-lived
plugin authentication with a pasted long-lived token merely to pass hardening.
An unsupported-authentication error means the kubeconfig credentials were not
hardened, even if installation of the signed kubectl Isotope already completed.
The hardener validates the complete rendered kubeconfig before storing any
migrated credentials or rewriting the file. Mixed supported and unsupported
users therefore fail together.
