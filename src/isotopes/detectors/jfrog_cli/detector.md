# jfrog-cli Detector

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
