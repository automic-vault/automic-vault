# wsk

```sh
cat "$HOME/.wskprops"
```

This prints the file, including any OpenWhisk AUTH keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - OpenWhisk CLI properties contain a plaintext AUTH key.
>
> #### Sensitive Files
>
> - `~/.wskprops`

## Mitigation

```sh
av harden wsk
```
