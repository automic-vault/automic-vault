# Automic Vault Product Positioning

Status: authoritative for user-facing messaging

Security claims and canonical terms defer to the [Domain Language](domain-language.md)
and [Architecture](architecture.md).

## Product promise

Automic Vault applies a developer credential after policy or the user allows the
complete operation requested by verified software.

A retrieval-based secrets manager decides whether an identity may receive a
stored secret. Automic Vault authorizes the complete operation at the point
where software uses a developer credential. It considers the Verified Launcher,
Gate Client, Target, command, arguments, working directory, requested Secret
Names, and policy. Automic Vault asks the user when policy requires Approval.

## Short copy

**Headline:** Your secrets manager should know what the secrets *do*.

**One sentence:** Automic Vault checks the Tool, Verified Launcher, Target,
command, arguments, working directory, and Secret Names before applying a
developer credential.

**Contrast:** Retrieval-based managers decide who can receive a named secret.
Automic Vault decides whether a complete operation may use it.

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
- An explicitly recognized, vendor-signed CLI sealed inside its vendor's app
  may represent that app as a Verified Launcher; unrelated bundled executables
  do not inherit the app's authority.
- When Automic Vault discovers signed helpers while adding an app as a Verified
  Launcher, the user may explicitly associate selected helpers with that app
  after reviewing the cross-gate authority warning.
- Git can keep its ordinary commit workflow while the GPG Signing Gate
  authorizes private-key use and may select an alternate credential for exact
  Verified Launchers.

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
