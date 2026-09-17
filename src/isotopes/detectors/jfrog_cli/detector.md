# jfrog-cli

```sh
cat "$HOME/.jfrog/jfrog-cli.conf.v6"
```

This prints the file, including any JFrog credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - JFrog CLI config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.jfrog/jfrog-cli.conf.v6`

## Mitigation

```sh
av harden jfrog-cli
```
