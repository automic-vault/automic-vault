# netlify-cli

```sh
cat "$HOME/Library/Preferences/netlify/config.json"
```

This prints the file, including any Netlify credentials it contains. Software
running as you with read access can copy the same material.

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
