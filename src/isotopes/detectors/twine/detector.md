# twine Detector

> ### What we check
>
> - Twine config contains plaintext package index credentials.
>
> #### Sensitive Files
>
> - `~/.pypirc`

## Mitigation

```sh
av harden twine
```
