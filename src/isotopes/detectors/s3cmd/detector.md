# s3cmd

It is trivial for anything on your computer to exfiltrate s3cmd’s secret:

```sh
cat "$HOME/.s3cfg"
```

This prints the file, including any S3 access credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - s3cmd config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.s3cfg`

## Mitigation

```sh
av harden s3cmd
```
