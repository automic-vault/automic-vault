# Securing Git on macOS

Use SSH transport with a passphrase-protected key stored in the macOS Keychain.

> [!IMPORTANT]
> If Git can fetch or push over HTTPS without prompting a human, some credential
> helper can probably return a plaintext token to `git credential fill`.
> That is convenient. It is also ambient authority unless the helper is the
> signed Automic Vault `gh` Isotope and the `gh` Secret Gate authorizes each
> request.

`av scan` reports Git configurations that can expose credentials to ordinary
same-user processes, including agent subprocesses.

Detected hazards:

- `~/.git-credentials`
- global `credential.helper = store --file ...` paths
- an effective ambient GitHub credential helper, including `osxkeychain` when
  Keychain metadata confirms a matching Internet password
- Git config that delegates GitHub credentials to an untrusted `gh auth
  git-credential` helper
- Git config that enables `git-credential-oauth`
- plaintext `oauthClientSecret` values in Git config

The Git helper Detector resolves includes and precedence through Git's
configuration-only plumbing. It does not invoke credential helpers or request
Secret Application. File-backed findings include the origin path and line.


The fix is not merely "use a better HTTPS credential helper". On macOS, if Git
can ask an ordinary helper for an HTTPS token non-interactively, an agent
command can ask too. The signed Automic Vault `gh` Isotope is different because
the `gh` Secret Gate evaluates the request before applying the token.

Use SSH.

## Gate GPG Commit Signing

Automic Vault can also gate use of the private key that signs Git commits and
tags. Open **Settings → GPG Signing**, export the private key from GnuPG as
instructed there, and select **Configure Git**. Git then invokes the `av-gpg`
Command inside the signed app bundle. `av-gpg` forwards the payload to
`av gpg-sign` at the GPG Signing Gate; it never receives the private key.

The settings also support an alternate GPG Signing Credential for an exact
list of Verified Launchers. This is useful for agents: agent-authored commits
can use a visibly different key from human-authored commits. The list is bound
to designated requirements rather than app names or paths, and changing it
requires Approval.

The signing Target necessarily handles the private key in memory while it
creates the signature. Automic Vault controls its application and zeroizes
transient input buffers; it does not claim that a compromised Target cannot
inspect its own memory.

## Check Git Credential Configuration

Start with the boring check:

```sh
$ av scan
╭─ system exposure audit
│
◆ 1 finding requires attention
│
└─ 1. git
│  severity HIGH
│  homepage https://git-scm.com/
│
│  problem
│  Git credential store contains plaintext credentials
│
│  solution
│  Run `rm /Users/you/.git-credentials` or edit it to remove the
│  credential; then use SSH remotes.
│
│  affected files
│  • /Users/you/.git-credentials:1
│
│  read more
│  https://github.com/automic-vault/automic-vault/main/docs/securing-git.md
│
╰─ scan complete
```

Inspect the effective configuration without invoking a helper:

```sh
$ git config --includes --show-origin --get-regexp \
    '^credential\..*\.helper$|^credential\.helper$'
file:/Applications/Xcode.app/.../gitconfig credential.helper osxkeychain
file:/Users/you/.gitconfig credential.https://github.com.helper
file:/Users/you/.gitconfig credential.https://github.com.helper !/usr/local/bin/gh auth git-credential
```

The empty helper resets the inherited `osxkeychain` entry. The remaining
absolute `gh` helper is accepted only when it carries the Automic Vault Isotope
signature.

You can also inspect GitHub Internet-password metadata without retrieving its
value:

```sh
$ security find-internet-password -s github.com -r htps
```

An explicit `git credential fill` test invokes the configured helper. It may
request Automic Vault Approval and print a usable credential, so `av scan`
never performs it. Do not paste its output anywhere.

Also check for plaintext credential-store files:

```sh
$ test -f ~/.git-credentials && sed -n '1,3p' ~/.git-credentials
https://user:token@example.com/repo.git
# ^^ bad: plaintext token on disk
```

## The Safe Target State

The target state on macOS:

- repository remotes use SSH URLs, eg. `git@github.com:user/repo.git`
- your SSH private key has a real passphrase
- macOS stores that passphrase in the Keychain after you enter it once
- Git either has no useful HTTPS token available through `git credential fill`,
  or its complete effective GitHub helper chain is the signed Automic Vault
  `gh` Isotope behind the `gh` Secret Gate
- no `credential.helper = store` plaintext files contain tokens

This is the practical boundary:

- the SSH private key file is encrypted at rest by its passphrase
- the passphrase is mediated by the macOS Keychain
- Git does not need an HTTPS token
- agent shell commands cannot ask Git for an HTTPS token and get one back

No magic. Just fewer plaintext secrets lying around.

## Create A Passphrase-Protected SSH Key

If you already have a passphrase-protected SSH key, skip to adding it to the
Keychain.

```sh
$ ssh-keygen -t ed25519 -C "$(git config --global user.email)"
Generating public/private ed25519 key pair.
Enter file in which to save the key (/Users/you/.ssh/id_ed25519):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
```

Do not use an empty passphrase.

> [!NOTE]
> An unencrypted SSH private key is just another plaintext secret. Different
> file, same problem.

Lock the file permissions down:

```sh
$ chmod 700 ~/.ssh
$ chmod 600 ~/.ssh/id_ed25519
$ chmod 644 ~/.ssh/id_ed25519.pub
```

## Store The SSH Passphrase In The macOS Keychain

Add the key to the Apple SSH agent and store the passphrase in Keychain:

```sh
$ ssh-add --apple-use-keychain ~/.ssh/id_ed25519
Enter passphrase for /Users/you/.ssh/id_ed25519:
Identity added: /Users/you/.ssh/id_ed25519
```

Teach SSH to use the Keychain:

```sh
$ mkdir -p ~/.ssh
$ chmod 700 ~/.ssh
$ cat >> ~/.ssh/config <<'EOF'
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  AddKeysToAgent yes
  UseKeychain yes
EOF
$ chmod 600 ~/.ssh/config
```

For GitLab:

```sshconfig
Host gitlab.com
  HostName gitlab.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  AddKeysToAgent yes
  UseKeychain yes
```

## Add The Public Key To Your Git Host

Copy the public key:

```sh
$ pbcopy < ~/.ssh/id_ed25519.pub
```

Add it to your Git host:

- GitHub: Settings -> SSH and GPG keys -> New SSH key
- GitLab: Preferences -> SSH Keys
- Bitbucket: Personal settings -> SSH keys

Then test it:

```sh
$ ssh -T git@github.com
Hi USERNAME! You've successfully authenticated, but GitHub does not provide shell access.
```

For GitLab:

```sh
$ ssh -T git@gitlab.com
Welcome to GitLab, @USERNAME!
```

The first connection may ask you to trust the host key. That is normal. The
passphrase prompt should happen once, then Keychain should handle future use.

## Convert Existing Checkouts To SSH

Check the current remote:

```sh
$ git remote -v
origin  https://github.com/user/repo.git (fetch)
origin  https://github.com/user/repo.git (push)
```

Switch GitHub HTTPS remotes to SSH:

```sh
$ git remote set-url origin "$(git remote get-url origin | sed -E 's#https://github.com/#git@github.com:#')"
```

Check it:

```sh
$ git remote -v
origin  git@github.com:user/repo.git (fetch)
origin  git@github.com:user/repo.git (push)
```

For GitLab:

```sh
$ git remote set-url origin "$(git remote get-url origin | sed -E 's#https://gitlab.com/#git@gitlab.com:#')"
```

For one-off remotes, set the URL explicitly:

```sh
$ git remote set-url origin git@github.com:user/repo.git
```

Now test normal Git:

```sh
$ git fetch
$ git push --dry-run
```

## Remove HTTPS Token Exposure

Once SSH works, remove the HTTPS credentials. This will probably break HTTPS
pushes and pulls. Good. That is the point.

Reject the GitHub credential from Git's helper chain:

```sh
$ printf 'protocol=https\nhost=github.com\n\n' | git credential reject
```

Verify it is gone:

```sh
$ printf 'protocol=https\nhost=github.com\n\n' | git credential fill
```

There should be no `password=` line.

If it still returns a password, open Keychain Access:

1. Search for `github.com`.
2. Delete Git or GitHub Internet password items used by Git.
3. Run the `git credential fill` check again.

Remove plaintext credential-store files if they exist:

```sh
$ rm -i ~/.git-credentials
```

Check for configured plaintext stores:

```sh
$ git config --global --get-all credential.helper
store --file ~/.custom-git-credentials
```

If you see `store`, remove it:

```sh
$ git config --global --unset-all credential.helper
```

If you need to remove one specific helper and keep another, edit the config:

```sh
$ git config --global --edit
```

Delete lines like:

```gitconfig
[credential]
  helper = store
  helper = store --file ~/.custom-git-credentials
```

Then delete the custom store file after confirming it contains only Git
credentials you no longer need:

```sh
$ rm -i ~/.custom-git-credentials
```

## Secure `gh auth git-credential`

The GitHub CLI can act as a Git credential helper:

```gitconfig
[credential "https://github.com"]
  helper = !gh auth git-credential
```

With upstream or unsigned `gh`, that lets Git ask `gh` for a token and lets any
same-user command ask Git for the same token.

`av harden gh` installs a signed `gh` Isotope that requests the token through
the `gh` Secret Gate. `gh auth setup-git` configures an absolute helper path and
an empty helper value that resets inherited helpers. `av scan` accepts that
configuration only when the absolute executable has the Automic Vault Isotope
signature and it is the complete effective GitHub helper chain. Verify it with:

```sh
$ av doctor gh
```

If `gh` is not hardened, or your remotes use SSH and do not need the helper,
remove it:

```sh
$ git config --global --unset-all credential.https://github.com.helper
```

If that does not remove it, edit the file:

```sh
$ git config --global --edit
```

Delete the `helper = !gh auth git-credential` line.

Then verify the effective helper configuration:

```sh
$ git config --includes --show-origin --get-regexp \
    '^credential\..*\.helper$|^credential\.helper$'
$ av scan
```

An SSH-only setup has no effective GitHub HTTPS helper. A hardened HTTPS setup
has one reset followed only by the signed Automic Vault `gh` Isotope.

## Remove `git-credential-oauth` Exposure

`git-credential-oauth` may appear as:

```gitconfig
[credential]
  helper = oauth -device
  oauthClientSecret = ...
```

Remove it if you want the SSH-only state:

```sh
$ git config --global --unset-all credential.helper
$ git config --global --unset-all credential.oauthClientSecret
```

If the config is more complex:

```sh
$ git config --global --edit
```

Delete the OAuth helper and any plaintext `oauthClientSecret`.

## Verify Everything

Run the scanner:

```sh
$ av scan
╭─ system exposure audit
│
◇ No problems found
│
╰─ vault sealed
```

Check the effective helper configuration:

```sh
$ git config --includes --show-origin --get-regexp \
    '^credential\..*\.helper$|^credential\.helper$'
```

There should be no ambient GitHub helper. The signed Automic Vault `gh` Isotope
may remain after an empty reset.

Check remotes:

```sh
$ git remote -v
origin  git@github.com:user/repo.git (fetch)
origin  git@github.com:user/repo.git (push)
```

Check SSH authentication:

```sh
$ ssh -T git@github.com
Hi USERNAME! You've successfully authenticated, but GitHub does not provide shell access.
```

Check real Git operations:

```sh
$ git fetch
$ git push --dry-run
```

Check that no plaintext store helper remains globally:

```sh
$ git config --global --get-all credential.helper
```

No output is ideal for SSH-only Git.

## Caveats

SSH with a Keychain-stored passphrase does not mean "no secrets exist". It means
Git no longer needs an HTTPS token that can be returned as plaintext by
`git credential fill`.

After the SSH key is unlocked, your login session can use it through the SSH
agent. That is still ambient authority. It is just a better macOS boundary than
leaving GitHub tokens in files or helper APIs.

If you use multiple Git hosts, repeat the SSH setup and credential cleanup per
host.

If your company requires HTTPS Git credentials, you cannot reach the SSH-only
state. Your best option is to limit token scope and lifetime, then keep agent
work away from shells that can call `git credential fill`.

For the rest:

- [GitHub: Connecting to GitHub with SSH][github-ssh]

[github-ssh]: https://docs.github.com/en/authentication/connecting-to-github-with-ssh
