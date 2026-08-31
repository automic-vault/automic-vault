# git-credential-fill Detector

## Trigger Conditions

- The effective GitHub helper chain contains an ambient credential helper.
- Git config delegates GitHub credentials to an untrusted `gh auth
  git-credential` helper.
- `osxkeychain` is effective and Keychain metadata confirms an Internet password
  for `github.com`.
- A signed Automic Vault `gh` helper is configured without first resetting
  inherited helpers.
- Git cannot safely resolve the effective helper configuration.

A GitHub helper is not a Finding when an empty helper first resets inherited
helpers and every effective helper is an absolute path to the signed Automic
Vault `gh` Isotope. That helper requests the token through the `gh` Secret Gate
instead of making it ambient authority.

The Detector resolves includes and configuration precedence with
`/usr/bin/git config`. It never runs `git credential fill` or invokes a
configured helper.

## Sensitive Files

- `~/.gitconfig`
- `$XDG_CONFIG_HOME/git/config`
- `~/.config/git/config`
- Included Git config files reported by `git config --show-origin`
- GitHub Internet-password metadata in the macOS Keychain

## Mitigation

For an ambient or untrusted helper, remove the affected configuration and any
matching cached credential, then move GitHub remotes to SSH. A signed Automic
Vault `gh` Isotope may remain when it is the complete effective helper chain.

## Confirm the Finding

Inspect the fully expanded helper configuration without invoking a helper:

```sh
git config --includes --show-origin --get-regexp \
  '^credential\..*\.helper$|^credential\.helper$'
security find-internet-password -s github.com -r htps
```

The first command shows helper values and their source files. The second prints
metadata only; it does not request the password value. `av doctor gh` verifies
whether an absolute `gh` helper is the signed Isotope.

To exercise the credential path explicitly, a user may run:

```sh
printf 'protocol=https\nhost=github.com\n\n' | git credential fill
```

That command is not part of Scan. It invokes configured helpers, may request
Automic Vault Approval, and may print a usable credential. Do not paste its
output into an issue or chat.

Review the configured helpers and verify the Isotope with:

```sh
av doctor gh
```

## Remove GitHub HTTPS Credential Access

Reject GitHub's cached credential:

```sh
printf 'protocol=https\nhost=github.com\n\n' | git credential reject
```

Remove a GitHub CLI helper from global config:

```sh
git config --global --unset-all credential.https://github.com.helper
```

If Git still returns a password, open the affected config:

```sh
git config --global --edit
```

Delete untrusted helper lines that provide GitHub HTTPS credentials, including:

```gitconfig
[credential "https://github.com"]
  helper = !gh auth git-credential
```

Keychain Access may also contain a Git or GitHub Internet password. Search for
`github.com` and remove the item used by Git.

## Move GitHub Remotes to SSH

Create a passphrase-protected key if needed, then add its passphrase to the
macOS Keychain:

```sh
ssh-keygen -t ed25519 -C "$(git config --global user.email)"
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
```

Configure the Apple SSH agent:

```sshconfig
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  AddKeysToAgent yes
  UseKeychain yes
```

Set `~/.ssh/config` to mode `0600`:

```sh
chmod 600 ~/.ssh/config
```

Add `~/.ssh/id_ed25519.pub` to your GitHub account, then convert the current
checkout:

```sh
git remote set-url origin "$(git remote get-url origin |
  sed -E 's#https://github.com/#git@github.com:#')"
```

## Verify

```sh
ssh -T git@github.com
git fetch
git push --dry-run
git config --includes --show-origin --get-regexp \
  '^credential\..*\.helper$|^credential\.helper$'
av scan
```

An SSH-only setup has no effective GitHub HTTPS helper. A hardened HTTPS setup
has one reset followed only by the signed Automic Vault `gh` Isotope.

## Caveats

This detector inspects helper configuration for `github.com`. It reports an
arbitrary configured helper as a Hazard even when that helper currently has no
cached credential. `osxkeychain` is reported only when password-item metadata
for `github.com` exists. Secret values are never requested.

The signed-Isotope exception fails closed. Relative helper commands, a missing
reset, other effective helpers, an invalid signature, or inspection failure
remain Findings. Includes are resolved through Git's configuration plumbing.
