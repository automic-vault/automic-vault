# vagrant Detector

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
