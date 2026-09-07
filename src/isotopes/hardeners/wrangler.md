# Wrangler

Installs the signed Wrangler Isotope from `automic-vault/isotopes/wrangler-isotope`
and verifies its complete runtime before placing it under `/opt/av/wrangler`.
The protected runtime is required because ordinary Node processes cannot be
Gate Clients for Wrangler Credentials.

Before switching, use upstream Wrangler to log out of every auth profile. Then
run `av harden wrangler` and `wrangler login`. Login stores the complete OAuth
Credential in Automic Vault; every use requires Approval. Only Global Values
are supported initially. Installation does not migrate existing credentials or
resolve existing Detector Findings. Library consumers do not inherit the
Isotope's credential authority.
