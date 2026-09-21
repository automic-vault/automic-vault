# Automic Vault Product Positioning

Status: authoritative for user-facing messaging

Security claims and canonical terms defer to the [Domain Language](domain-language.md)
and [Architecture](architecture.md).

## Product promise

CLI security is broken. The packaging layer is where we fix it.

You install a CLI to do a job. Its credentials often sit in files, environment
variables, or helpers that other code running as you can read. An agent running
that CLI inherits access you may never have meant to give it.

Automic Vault hardens supported tools where they are installed and configured.
We move exposed credentials into protected storage and reconfigure, wrap, or
patch the tools to request authorization when they use them. Homebrew has an
Execution Gate for supported package-management operations, too.

You keep using your commands. Automic Vault checks the complete operation before
applying a protected credential, and asks you when policy requires Approval.

## Short copy

**Headline:** CLI security is broken. The packaging layer is where we fix it.

**Founder line:** I created Homebrew. Now I’m fixing what happens when agents use it.

**One sentence:** Automic Vault hardens supported CLI tools on macOS, moves
exposed credentials into the Keychain, and gates their use while you keep your
usual commands.

**Supporting line:** Give your agent Read Only access to GitHub. Approve its
writes. Require a separate decision to reveal the token.

## Voice and order

Write as the developers fixing a specific problem in the command-line toolchain.
Explain the exposed credential or uncontrolled operation, show the intervention,
and give a command that demonstrates it. Use plain, opinionated language.

Lead with packaging and tool hardening. Follow with an operation example, a
Scan or installation path, and the relevant security boundary. Explain Secrets,
Verified Launchers, and Authorization Gates as the reader encounters them.
Keep the fuller model in the technical documentation.

“The packaging layer is where we fix it” describes our intervention through tool
installation and configuration. Hardeners may use an Isotope, a wrapper, an
upstream credential helper, or a verified vendor release. Runtime Authorization
Gates enforce protected requests after installation. Packaging itself is not an
authority decision, and installing a package does not make its code trustworthy.

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
- A Blessed Script with an explicit `ssh-agent: trusted` Capability can
  authenticate through the SSH Agent Gate while its verified execution remains
  in the SSH client's live ancestor chain. The Capability does not restrict SSH
  destinations.
- An explicitly recognized, vendor-signed CLI sealed inside its vendor's app
  may represent that app as a Verified Launcher; unrelated bundled executables
  do not inherit the app's authority.
- When Automic Vault discovers signed helpers while adding an app as a Verified
  Launcher, the user may explicitly associate selected helpers with that app
  after reviewing the cross-gate authority warning.
- Git can keep its ordinary commit workflow while the GPG Signing Gate
  authorizes private-key use and may select an alternate credential for exact
  Verified Launchers.

- The optional SSH agent authorizes each authentication signature using one
  credential shared across Verified Launchers. SSH clients receive signatures,
  never the private key. Destination-specific restrictions are not provided.

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
