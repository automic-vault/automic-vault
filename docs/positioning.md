# Automic Vault Product Positioning

Status: authoritative for user-facing messaging

Security claims and canonical terms defer to the [Domain Language](domain-language.md)
and [Architecture](architecture.md).

## Product promise

macOS protects your apps. We protect your command line.

Since Max Howell created Homebrew, Apple has added layers of protection around
Mac apps: Gatekeeper, notarization, malware checks, and permissions for sensitive
data. Automic Vault complements that work for developer credentials and
supported command-line operations.

Command-line tools still often keep credentials in files, environment variables,
or helpers that other code running as you can read. An agent or dependency can
inherit the authority to publish a release or change your cloud infrastructure
without a separate decision about that operation.

Automic Vault builds on macOS code signing, Hardened Runtime, and the Keychain.
We harden supported tools where they are installed and configured, move exposed
credentials into protected custody, and authorize their use. Homebrew has an
Execution Gate for supported package-management operations, too.

You keep using your commands. Automic Vault checks the complete operation before
applying a protected credential, and asks you when policy requires Approval.

## Short copy

**Headline:** macOS protects your apps. We protect your command line.

**Founder line:** Since I created Homebrew, Apple has transformed Mac app
security. I’m bringing that same care to the command line.

**One sentence:** Automic Vault complements macOS security for supported CLI
tools: protected credentials, operation-level authorization, and your usual
commands.

**Supporting line:** Your secrets manager should know what the secrets *do*.
Follow it with GitHub's read, write, and disclosure decisions for one token.

## Voice and order

Lead with respect for Apple's Mac app security and our complementary role in
the command line. Connect the founder's Homebrew history to the credentials and
authority developer tools carry today. Explain the remaining credential and
operation gap, then show the intervention with `av harden gh` and Homebrew's
Read & Update policy. Follow with the runtime demo, Scan or installation path,
and relevant security boundary.

Attribute the first-person founder line to Max Howell without repeating
“creator of Homebrew” beside it. Explain Secrets, Verified Launchers, and
Authorization Gates as the reader encounters them. Keep the fuller model in
the technical documentation.

Apple's security technologies also protect command-line software. Do not claim
that macOS ignores the terminal or that CLI tools have no OS protections. Apple
also documents [Terminal and script protections](https://support.apple.com/guide/security/terminal-and-script-protections-sece3b202c4b/web).
Our gap is protected developer credential use and authorization of supported
operations. “We protect your command line” must appear with that concrete scope;
it does not promise general malware prevention or execution containment.

Tool installation and configuration are our intervention points. Hardeners may
use an Isotope, a wrapper, an upstream credential helper, or a verified vendor
release. Runtime Authorization Gates enforce protected requests after
installation. Packaging itself is not an authority decision, and installing a
package does not make its code trustworthy.

Do not turn package-catalog size into a protection claim. Coverage is per
supported Tool and operation. Do not imply that every Homebrew package, npm
invocation, or process execution runs through Automic Vault. General-purpose
agent sandboxing is outside the product's scope.

## Supporting claims

- Automic Vault protects credentials in custody and controls their application.
- Authorization covers the software identity, Secret Names, Tool, Target,
  command, arguments, and working directory.
- Tool-specific Authorization Gates distinguish read, write, disclosure, and
  elevated credential use.
- Policy can authorize recognized operations. The user handles requests that
  require Approval.
- Optional iPhone Approval and Touch ID Approval move allow actions away from
  agent-controlled pointer and keyboard input.
- An eligible agent write Approval can grant an initial ten active minutes of
  Write Access to one Verified Launcher, Tool-specific Authorization Gate, and
  agent task. A persistent strip shows the grant and lets the user add ten
  minutes, suspend its countdown, or end it; suspension also suspends its
  authority. The user may opt to collapse the strip after five seconds to a
  visible warning tab while the menu-bar shield remains orange.
- Existing developer commands continue to work above the security boundary.
- Scripts inherit their existing execution context's automic authority when no
  capability declaration is present. `capabilities: {}` opts into an empty
  capability ceiling so later gated operations attributable to that live script
  execution require Approval regardless of the calling Launcher.
- A Blessed Script with an explicit `ssh-agent: trusted` Capability for the original SSH credential can
  authenticate through the SSH Agent Gate while its verified execution remains
  in the SSH client's live ancestor chain. The Capability does not restrict SSH
  destinations.
- An explicitly recognized, vendor-signed CLI sealed inside its vendor's app
  may represent that app as a Verified Launcher; unrelated bundled executables
  do not inherit the app's authority.
- When Automic Vault discovers signed helpers while adding an app as a Verified
  Launcher, the user may explicitly associate selected helpers with that app
  after reviewing the cross-gate authority warning. Codex and Claude's exact
  vendor-signed CLIs start selected in that review and still require Approval.
- Claude's helper review also warns that Claude Code disables library validation.
  Its verified association accepts that exception for Claude's existing and new
  Tool-specific gate rules; third-party code loaded into the helper can exercise
  those permissions. Users can disable the association.
- Git can keep its ordinary commit workflow while the GPG Signing Gate
  authorizes private-key use and may select an alternate credential for exact
  Verified Launchers.

- The optional SSH agent authorizes each authentication signature using the
  requested credential’s own Default Policy and Verified Launcher rules. Separate
  keys can carry separate authority. SSH clients receive signatures, never the
  private key. Key names do not enforce destination-specific restrictions.

## Claim boundaries

User-facing copy must preserve these limits:

- Code signing establishes software identity and integrity, not intent.
- App Launcher verification covers the exact executable that represents the
  Launcher, not every unrelated resource shipped in the containing app.
- After Secret Application, the Target controls the Secret in its memory,
  helpers, child processes, and output.
- Automic Vault does not contain root or kernel compromise, prevent arbitrary
  local destruction, or intercept every process execution.
- A Project Directory selects a Project Value. It does not establish identity
  or grant authority.
- A Codex task ID or Claude Code session ID is a forgeable narrowing label, not
  identity or a security boundary. The Verified Launcher remains the identity
  boundary for a Temporary Access Grant.
- Temporary Access Grants do not cover the Direct Secret Gate, Secret mutation,
  Elevated Secret Application, Secret Disclosure, or Unknown operations.
- An explicit empty script capability ceiling also blocks matching Temporary
  Access Grants; it is not an execution sandbox and does not constrain ungated
  commands.
- Secret Disclosure remains available as an explicit, more powerful Secret Use.
- Execution control belongs to the same Developer Authority model even when an
  operation uses no Secret.

Do not claim that Automic Vault keeps every Secret invisible to its Target,
sandboxes the whole system, or makes verified software trustworthy.

## Architectural proof

- [ADR 0010](adr/0010-no-ungated-secret-retrieval.md) prohibits Gate Clients
  from retrieving a Secret by Secret Name alone.
- [Authorization Gates and Policies](adr/0002-authorization-gates-and-policies.md)
  bind policy to recognized operations and their characteristics.
- [Local Execution Boundary](adr/0001-local-execution-boundary.md) keeps
  enforcement on the Mac where the operation runs.
