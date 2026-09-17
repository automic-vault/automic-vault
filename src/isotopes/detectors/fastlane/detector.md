# fastlane

It is trivial for anything on your computer to exfiltrate fastlane’s secret:

```sh
cat "$HOME/.fastlane/spaceship/ACCOUNT/cookie"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any Spaceship session cookies it contains. Software running as
you with read access can copy the same material.

> ### What we check
>
> - fastlane Spaceship session cookie is stored in plaintext.
>
> #### Sensitive Files
>
> - `~/.fastlane/spaceship/**`
> - `~/.spaceship/**`

## Mitigation

fastlane stores Apple account passwords in the system keychain where possible,
but Spaceship session cookies can still live in plaintext files. This detector
reports those files without changing fastlane's auth flow.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
