# fastlane Detector

> ### What we check
>
> - fastlane Spaceship session cookie is stored in plaintext.
>
> #### Sensitive Files
>
> - `~/.fastlane/spaceship/**`
> - `~/.spaceship/**`

## Why This is not Yet Hardened

fastlane stores Apple account passwords in the system keychain where possible,
but Spaceship session cookies can still live in plaintext files. This detector
reports those files without changing fastlane's auth flow.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
