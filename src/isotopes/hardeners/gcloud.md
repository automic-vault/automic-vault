# gcloud

Installs the signed gcloud Isotope and its pinned Python runtime under
`/opt/av/gcloud`, using `automic-vault/isotopes/gcloud-isotope` as the constrained
release manifest. Doctor verifies the installed runtime; Hardened Tools manages
updates.

Revoke existing upstream sessions before switching, then run `gcloud auth login`
through the Isotope. User OAuth credentials are stored in Automic Vault custody;
access tokens stay in process memory. Installing the Isotope does not remove
credentials left by another gcloud installation or Application Default Credentials.

Every credential read initially requires Approval. The first version supports
ordinary user OAuth in the default Google universe. ADC export, federation,
service-account credentials, impersonation, endpoint overrides, component
installation, alpha/beta commands, and companion tools are unsupported.

See [ADR 0082](https://github.com/automic-vault/automic-vault/blob/main/docs/adr/0082-gcloud-isotope-custody.md).
