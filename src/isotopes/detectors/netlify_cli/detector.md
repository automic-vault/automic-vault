# netlify-cli Detector

> ### What we check
>
> - Netlify CLI config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/Library/Preferences/netlify/config.json`
> - `~/.netlify/config.json`

## Mitigation

```sh
av harden netlify-cli
```
