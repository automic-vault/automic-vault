# git-credential-oauth

```sh
git config --global --get credential.oauthClientSecret
```

If your global Git config contains an OAuth client secret, this prints it.
Software running as you can also invoke a configured OAuth credential helper.
The Detector inspects configuration without executing the helper.

> ### What we check
>
> - Git config enables git-credential-oauth as an ambient credential helper.
> - Git config contains a plaintext OAuth client secret.
>
> #### Sensitive Files
>
> - `~/.gitconfig`
> - `$XDG_CONFIG_HOME/git/config`
> - `~/.config/git/config`

## Mitigation

Remove the OAuth helper and any plaintext `oauthClientSecret` from the affected
Git config, revoke a real client secret, and move repository remotes to SSH.

Automic Vault does not change Git helper order. git-credential-oauth is a
credential helper rather than an application-owned secret store, and rewriting
the helper chain could break other Git authentication.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).

---

## Remove the OAuth Helper

Open the affected config at the line reported by `av scan`:

```sh
git config --global --edit
```

Remove the OAuth helper and any plaintext client secret. A typical unsafe
configuration looks like this:

```gitconfig
[credential]
  helper = oauth -device
  oauthClientSecret = ...
```

For a simple global config, these commands remove all global helpers and the
client secret:

```sh
git config --global --unset-all credential.helper
git config --global --unset-all credential.oauthClientSecret
```

The first command removes every global credential helper. Edit the config by
hand when you need to retain another helper.

Treat a real `oauthClientSecret` as exposed. Revoke or rotate it in the OAuth
provider's application settings after removing it from Git config.

## Use SSH Instead

Create an Ed25519 key with a non-empty passphrase if you do not have one:

```sh
ssh-keygen -t ed25519 -C "$(git config --global user.email)"
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
```

Add this to `~/.ssh/config` and set the file to mode `0600`:

```sshconfig
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  AddKeysToAgent yes
  UseKeychain yes
```

Add the public key to your Git host, then replace each HTTPS remote:

```sh
git remote set-url origin git@github.com:OWNER/REPO.git
```

Use `git@gitlab.com:OWNER/REPO.git` for GitLab.

## Verify

```sh
git config --global --get-all credential.helper
git config --global --get-regexp '^credential\.oauthClientSecret$' >/dev/null &&
  echo 'oauthClientSecret remains configured'
git remote -v
git fetch
git push --dry-run
av scan
```

The first command and the client-secret check should print nothing in an
SSH-only setup.

## Caveats

This detector does not inspect OAuth refresh-token caches or repository-local
Git config. Companies that require HTTPS Git credentials cannot use the
SSH-only setup. Limit token scope and lifetime in that environment, and keep
agent-run shells away from the credential helper.
