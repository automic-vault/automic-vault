# circleci

```sh
cat "$HOME/.circleci/cli.yml"
```

This prints the file, including any CircleCI API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - CircleCI config contains an API token.
>
> #### Sensitive Files
>
> - `~/.circleci/cli.yml`

## Mitigation

```sh
av harden circleci
```
