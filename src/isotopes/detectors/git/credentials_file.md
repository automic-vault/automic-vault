# git-credentials-file Detector

> ### What we check
>
> - Git credential store contains plaintext credentials.
> - Git config enables a plaintext Git credential-store file.
>
> #### Sensitive Files
>
> - `~/.git-credentials`
> - `~/.gitconfig`
> - `$XDG_CONFIG_HOME/git/config`
> - `~/.config/git/config`
> - `credential-store files referenced by global Git config`

## Mitigation

Remove credentials from the reported files, disable Git's plaintext `store`
helper, and move repository remotes to SSH.

## Inspect the Reported Store

`av scan` reports the credential file and line without printing its contents.
Git's store format places credentials in URLs such as:

```text
https://user:token@example.com/repo.git
```

Do not paste the reported file into an issue or chat. It contains usable
credentials.

List configured global helpers:

```sh
git config --global --get-all credential.helper
```

Plaintext stores appear as `store` or `store --file PATH`.

## Remove Plaintext Credentials

After SSH works, delete the default store:

```sh
rm -i ~/.git-credentials
```

For a custom store, remove the `helper = store` line from the affected Git
config:

```sh
git config --global --edit
```

Then delete the reported store file after confirming that it contains only Git
credentials you no longer need:

```sh
rm -i ~/.custom-git-credentials
```

This command removes every global helper and suits an SSH-only setup:

```sh
git config --global --unset-all credential.helper
```

Edit the config by hand if you need to retain another helper. Revoke or rotate
the deleted tokens at their Git hosts.

## Move Remotes to SSH

Create a passphrase-protected key if needed, then store its passphrase in the
macOS Keychain:

```sh
ssh-keygen -t ed25519 -C "$(git config --global user.email)"
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
```

Configure `~/.ssh/config`:

```sshconfig
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  AddKeysToAgent yes
  UseKeychain yes
```

Set that config to mode `0600`, add the public key to your Git host, and convert
the checkout:

```sh
git remote set-url origin "$(git remote get-url origin |
  sed -E 's#https://github.com/#git@github.com:#')"
```

For another host, set a URL such as `git@gitlab.com:OWNER/REPO.git`.

## Verify

```sh
test ! -e ~/.git-credentials
git config --global --get-all credential.helper
git remote -v
git fetch
git push --dry-run
av scan
```

An SSH-only setup has no `store` helper and no HTTPS credential files.

## Caveats

An encrypted SSH key still grants access through the SSH agent after you unlock
it. The passphrase protects the private key at rest, while removing the Git
store prevents same-user processes from reading reusable tokens from plaintext
files.
