# Detection and Tool Hardening

Run a Scan, apply the relevant Hardener, then verify its intervention:

```sh
$ av scan
$ av harden gh
$ av doctor gh
```

A Detector reports a supported Exposure or Hazard without changing the
environment, requesting Secrets, or invoking a configured credential helper.
Each Finding includes a mitigation. A clean Scan means no supported Detector
found an issue; it cannot certify the environment as secure.

A Hardener moves a supported Tool into its declared Hardened State by migrating
credentials, changing configuration, or installing an Isotope or wrapper.
Doctor checks the installed protection, including identity, ownership,
permissions, dependencies, and command resolution. Scan evaluates your
configuration; Doctor verifies Automic Vault's intervention.

To inspect the installed version's coverage:

```sh
$ av detectors --json
$ av hardeners --json
```

Wrappers and PATH stubs mediate the command path they occupy. They cannot
intercept every execution. A direct invocation of the underlying executable
should lack the vault-managed Secret, but ambient credential providers can
still authorize it. Keep the rest of the environment's credential paths closed.

## AWS

AWS hardening removes the default long-lived key pair from
`~/.aws/credentials` and installs a native credential helper:

```sh
$ av harden aws
$ aws sts get-caller-identity
```

Each invocation registers its arguments, profile, process identity, and config.
The helper gives normal commands short-lived STS credentials. Automic Vault
shows an Elevated Secret Application warning when an operation requires the
original reusable keys. It installs and verifies AWS's signed CLI under
`/opt/av/aws`; credential providers outside the supported profile model fail
closed.

## Docker

Docker hardening migrates registry credentials out of ambient helper access:

```sh
$ av harden docker
$ docker pull registry.example/acme/image
```

The Secret Gate verifies the live vendor-signed Docker process, ancestry,
arguments, runtime posture, and requested registry. Docker's helper protocol
returns a usable token to the authorized Docker process. A compromised Target
can leak that token.

## Rescind Unneeded Terminal Permissions

For an agent used through a CLI, the terminal app is often the macOS TCC
boundary. Agents, dependencies, plug-ins, and scripts launched by that terminal
may inherit capabilities you granted it. Automic Vault does not replace these
macOS protections.

> [!IMPORTANT]
> Open **System Settings → Privacy & Security** and turn off every permission
> your terminal or agent harness does not need. Review the whole list,
> especially **Full Disk Access**, **App Management**, and **Files & Folders**.
> Re-enable an individual permission only when the work requires it.

If some work needs broad macOS permissions, use one terminal app for
that work and a different, locked-down terminal app for agents and untrusted
project code. Another window, profile, or copy of the same app is not a separate
TCC identity.

See Apple's [Privacy & Security settings](https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac)
for the permissions macOS currently exposes.

See the [Domain Language](domain-language.md) and [Architecture](architecture.md)
for the authoritative terms and security boundaries.
