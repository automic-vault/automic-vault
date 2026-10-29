# eMudhra TLS trust paths

Compromised eMudhra intermediate CA keys can be used to impersonate websites.
Some command-line tools use their own CA bundles or embedded roots instead of
Apple's certificate block.

## What we check

On macOS, this Detector checks `/etc/ssl/cert.pem` and common installed trust
sources:

- Homebrew CA bundles under `/opt/homebrew` and `/usr/local`, including OpenSSL
  bundle links and installed `ca-certificates` versions.
- Node, Deno, and Bun binaries under those prefixes, including inactive Homebrew
  versions and Node's shared `libnode` libraries.
- Default Deno and Bun installations in `~/.deno/bin` and `~/.bun/bin`.
- Installed Node versions under nvm, Volta, and fnm's default macOS directories,
  plus Node, Deno, and Bun versions under mise and asdf's default directories.

Findings include the full resolved path. Symlinks to the same file produce one
package Finding. Discovery follows the installation layouts in the Detector
[installation catalog](sources.json); it does not execute installed runtimes or
package managers. Bundle changes trigger a scan; periodic scans cover installed
runtime versions.

For PEM bundles, we match certificate bytes against two SHA-256 fingerprints:

- emSign ECC Root CA - G3: `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`
- AAA Certificate Services: `d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4`

The latter is the alternate trust path for Sectigo's cross-signed intermediates.
These roots are not themselves the compromised intermediate keys.

For runtime binaries, we look for the same certificates in DER or common PEM
encodings, and their exact public-key trust-anchor bytes. Node embeds PEM roots;
Deno's webpki-roots library embeds trust anchors without complete certificates.
An embedded match reports a Hazard: runtime options, custom CA stores, or a
separate blocklist may change effective trust. Presence alone does not establish
that a connection would succeed or that a Compromise occurred.

Unreadable, invalid, oversized, or otherwise uninspectable discovered sources
produce Findings. Discovery limits also produce Findings. File inspection uses
bounded reads and accepts only regular files.

## Mitigation

For `/etc/ssl/cert.pem`, run `av harden emudhra` to preview the change, then
`sudo av harden emudhra` to apply it. See the
[hardening reference](../../hardeners/emudhra.md).

For every other reported path, update the owning CA package or runtime with the
package manager or version manager that installed it. For Homebrew's CA package,
use `brew update`, then `brew upgrade ca-certificates`, then
`brew cleanup ca-certificates`. The Detector also checks older inactive kegs;
cleanup removes those old versions even when the active keg is already current.
Update the reported Node, Deno, or Bun installation separately: updating a CA
bundle cannot replace roots embedded in a binary. Remove obsolete versions you no longer use, restart
processes that use an updated runtime, and scan again.

Automic Vault does not modify these packages. A package update may retain a
reported root while adding a separate mitigation; consult the vendor's advisory
if the Finding persists.

## Coverage limits

Custom installation prefixes, custom version-manager directories, project-local
runtimes, containers, application bundles, compressed binaries, and other CA
encodings may fall outside this check. It does not inspect every executable or
reconstruct effective TLS policy. Safari and Mail use Apple's system trust
handling. A clean Scan is not evidence that all TLS clients are protected.

Sources: [Apple's advisory](https://support.apple.com/en-us/149555),
[Homebrew CA package](https://github.com/Homebrew/homebrew-core/blob/master/Formula/c/ca-certificates.rb),
[Node's embedded roots](https://github.com/nodejs/node/blob/main/src/node_root_certs.h),
[Deno's default root store](https://github.com/denoland/deno/blob/main/ext/tls/lib.rs),
[webpki-roots trust anchors](https://github.com/rustls/webpki-roots/blob/main/webpki-roots/src/lib.rs).
