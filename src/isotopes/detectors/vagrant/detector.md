# vagrant

```sh
cat "$HOME/.vagrant.d/data/vagrant_login_token"
```

This prints the file, including any Vagrant Cloud tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Vagrant Cloud token file contains a plaintext token.
>
> #### Sensitive Files
>
> - `$VAGRANT_HOME/data/vagrant_login_token`
> - `~/.vagrant.d/data/vagrant_login_token`

## Mitigation

```sh
av harden vagrant
```
