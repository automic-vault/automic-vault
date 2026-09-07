# ADR 0032: Route Secret Application with positive command catalogs

Status: accepted

## Context

An environment wrapper that requests its protected Secret for every invocation
unnecessarily exposes that Secret to local inspection commands and arbitrary
scripts. Treating unrecognized invocations as Unknown at the Secret Gate still
creates a Secret Application request and lets one Approval expose the Secret.

## Decision

Every environment-wrapper Isotope must positively enumerate the Tool
invocations that may legitimately use each protected Secret. Only those
invocations may request Secret Application. Every other invocation executes
with that Secret removed from its environment and does not enter an
Authorization Gate.

Each catalog is based on a named upstream release or commit and includes exact
commands, documented aliases, and relevant global options. The review must
distinguish operations that consume an existing credential from operations that
establish, replace, remove, or inspect authentication. Empty invocations,
help/version forms, local-only commands, unknown or future commands, arbitrary
scripts, and passthrough forms remain tokenless unless the upstream behavior
shows that they may consume the protected Secret. Parsing fails tokenless when
arguments are malformed or cannot be represented safely.

When the Tool receives an explicit alternative credential, the wrapper must not
also request the protected Secret. Tool-specific configuration inspection may
establish that an alternative credential exists, but it must not print, copy,
or transmit credential values.

Positive Secret routing happens before Runtime Authorization. The Tool-specific
policy still classifies every routed operation by its reviewed effects. A routed
operation whose effects remain uncertain is Unknown and requires Approval.
Tokenless execution grants no authority and does not replace an Execution Gate.

Each environment-wrapper change includes focused regression coverage for:

- empty, help, version, local-only, unknown, and future command forms;
- every reviewed credential-consuming command family and documented alias;
- leading global options, option values that resemble commands, and `--`
  passthrough;
- arbitrary script or plugin entry points exposed by the Tool;
- explicit alternative credentials and configuration profiles when supported;
- malformed and non-UTF-8 arguments; and
- unchanged Gate Client and Target identity and integrity requirements.

The Rust routing tests and macOS policy tests must agree on the reviewed command
surface. A pull request records the upstream version or commit used for the
review. Changes to credential-independent execution authorization belong in a
separate Execution Gate decision.

Users may make an explicit `av inject` request when an unsupported operation
really needs a protected Secret; that request remains subject to the Direct
Secret Gate.

## Consequences

Future Tool commands fail authentication rather than silently gaining a
protected credential. Each positive catalog must be reviewed when upstream adds
or changes credential-consuming commands. Unknown Secret Application still
cannot be automically authorized under ADR 0002 because tokenless routing occurs
before a Secret Use request exists.
