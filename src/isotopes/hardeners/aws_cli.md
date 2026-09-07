## What It Does

`av harden aws` moves the default AWS access key pair out of
`~/.aws/credentials` and into the macOS login keychain. It downloads AWS's
official macOS installer package, verifies it, extracts its payload without
running the installer or its scripts, and installs it under `/opt/av/aws`.
`/usr/local/bin/aws` remains a one-line Automic Vault launcher.

Automic Vault uses the official release instead of Homebrew's formula because
AWS signs and notarizes that complete distribution, ships a native universal
executable with Hardened Runtime, and publishes it directly. Homebrew rebuilds
AWS CLI around a separately managed Python runtime and can lag the official
release, adding independently mutable components to the credential-bearing
Target.

The launcher registers its official-release generation, exact AWS arguments,
selected profile, process ID, process start time, and a snapshot of the AWS
config with the menu app before replacing itself with
`/opt/av/aws/current/aws`. The AWS CLI receives a minimal config containing
Automic Vault's `credential_process`; that helper only works as an immediate
child of the registered, still-running AWS process.

Credential-free metadata invocations (`aws --version`, `aws help`, and
`aws <service> [operation] help`) skip Secret Use and run with an empty AWS
configuration and a fixed system executable path.

The menu app implements STS `GetSessionToken` and `AssumeRole` directly. It
caches resulting credentials only for the lifetime of that registered AWS
process. Nothing is written to disk and credentials are not shared between AWS
invocations.

## How It Protects You

The real AWS CLI runs with an empty home, no shared credentials file, disabled
instance metadata, no pager, and a generated config held in an unlinked file
descriptor. Ambient AWS credentials, credential processes, SSO/login state,
web identity, container credentials, plugins, aliases, and pager hooks are not
available inside the credential-bearing process.

The Hardener verifies all of the following before activation:

- HTTPS-only download from AWS's version-specific release URL, with no redirects;
- an exact match between the requested changelog version and signed package version;
- Apple trust, AWS's Developer ID Installer team, notarization, and timestamp;
- the `com.amazon.aws.cli2` package identity and bounded payload size/count;
- every native payload component's Amazon Developer ID Application signature,
  secure timestamp, and Hardened Runtime;
- absence of dangerous runtime exceptions;
- regular-file/directory-only extraction, single-link files, and safe paths;
- an atomic, root-owned, non-user-writable, versioned installation plus a
  complete content manifest.

The helper then verifies all of the following before returning credentials:

- its immediate parent has the registered PID and process start time;
- the parent is the signed native executable from the approved official
  release;
- the live parent arguments exactly match the approved snapshot.

Previously hardened Homebrew installations continue to use their interpreter
binding until re-hardened. The helper negotiates that legacy protocol only when
the exact legacy launcher is still installed. Once the official launcher
replaces it, Homebrew generation registration and credential retrieval fail
closed.

Normal commands receive temporary credentials. AWS does not permit non-MFA
`GetSessionToken` credentials to call IAM or most STS operations, so a base
profile without MFA or a role receives the original long-lived keys for those
operations. The approval window warns that this is Elevated Secret Application.
Write Access still prompts, while Full Access may automically authorize the
recognized operation.

## Supported Profiles

Automic Vault intentionally supports one narrow profile model:

- the imported `default` keys;
- `region`;
- `mfa_serial`, entered in Automic Vault's own prompt;
- role profiles using `role_arn` and `source_profile`, ultimately rooted at
  `default`.

`mfa_process`, SSO, web identity, `credential_process`, `credential_source`,
independent named static keys, incomplete roles, and source-profile cycles fail
closed with a precise error.

## Caveats

- This assumes `/opt/av/aws`, `/usr/local/bin/av`, and `/usr/local/bin/aws`.
- `/usr/local/bin` must precede other AWS installations in `PATH`; an absolute
  call to another AWS CLI bypasses the wrapper but cannot use Automic Vault's
  generation-bound credential helper.
- `av harden aws` verifies the running app and installed CLI, then requests
  elevation to copy and reverify the package, extract it without scripts,
  protect and atomically activate the release, and replace `/usr/local/bin/aws`.
- `av doctor aws` checks AWS's official v2 changelog and versioned macOS package
  availability, then directs you back to the Hardener when a newer downloadable
  release is available.
- The AWS process can use any credential it receives for the lifetime and IAM
  scope of that credential. Automic Vault confines issuance to the approved
  invocation; it cannot harden the upstream AWS CLI process itself.

## Hardener Migration Notes

`av doctor aws` recognizes both the exact previously released `aws-vault`
launcher and the native-helper Homebrew launcher as requiring re-hardening.
Modified launchers remain invalid rather than being treated as an upgrade.
`av harden aws` preserves existing Keychain credentials and gate policy,
supports idempotent re-hardening, and refuses a signed release downgrade.
