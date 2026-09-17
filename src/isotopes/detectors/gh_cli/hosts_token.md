# GitHub CLI

```sh
gh auth token
```

With an unprotected `gh` login, this command prints your GitHub token. An agent,
dependency, or script running as you can invoke it too, then use the token with
its existing permissions.

Storing the token in Keychain does not necessarily prevent extraction. If its
access list permits `/usr/bin/security` to read it without confirmation,
software can retrieve it directly:

```sh
/usr/bin/security find-generic-password -s 'gh:github.com' -w
```

These examples print real credentials. Automic Vault does not run them during
a Scan.

> ### What we check
>
> - **Plaintext token storage.** A non-empty `oauth_token` entry in a GitHub CLI
>   `hosts.yml` file. Software with access to that file can copy the token.
>   We check `$GH_CONFIG_DIR/hosts.yml` when configured. Otherwise, we check
>   `~/.config/gh/hosts.yml` and `$XDG_CONFIG_HOME/gh/hosts.yml` when applicable.
> - **Keychain access.** A `gh:<host>` Keychain item whose access list permits
>   `/usr/bin/security` to read the credential. We inspect access rules without
>   extracting the token.
>
> Automic Vault reports these conditions through separate Detectors. A finding
> identifies an exposure, not evidence that someone has stolen or used your
> token. No findings means these checks found neither condition; it does not
> establish that every credential-use path is protected.

## Mitigation

```sh
av harden gh
```

Automic Vault installs its signed `gh` Isotope and migrates supported credentials
from `hosts.yml` and legacy GitHub CLI Keychain items into Automic Vault custody.

Authenticated operations then pass through the GitHub CLI Secret Gate. You
choose the default Access Level and exceptions for individual Verified Launchers.

| Access Level | Operations it can authorize |
|---|---|
| Read Only | Recognized reads, including `gh api` GET requests |
| Local Write | Also cloning, checking out, and downloading into local files |
| Write Access | Also recognized remote writes |
| Full Access | Also recognized Secret Disclosure |

Printing a token with `gh auth token` or `gh auth status --show-token` is
**Secret Disclosure**. It requires Approval under Read Only, Local Write, and
Write Access. Unknown commands and unclassifiable argument forms require
Approval at every Access Level.

See the [hardening reference](../../hardeners/gh_cli.md) for setup and coverage.

---

## Git integration

Git can use `gh auth git-credential` as its credential helper. The hardened
helper requests the credential through Automic Vault; the gate treats this
command family as Secret Disclosure.

Git's SSH authentication and GPG signing have separate controls.

## Health and updates

```sh
av doctor gh
```

Doctor checks the installed protection and reports available Isotope updates.
Installation uses the Automic Vault Homebrew tap when Homebrew is available,
or a verified direct installation otherwise. For a direct installation, rerun
`av harden gh` to update.

Once an authorized operation receives a token, `gh` controls that token in its
memory. Hardening governs its release; it cannot guarantee that a compromised
Target keeps it confidential.
