# s3cmd Detector

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
