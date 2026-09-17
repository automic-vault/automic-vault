# sudo

Without Touch ID configured for sudo, you may need to type your account
password into a terminal prompt. A forged prompt or misplaced keyboard focus
can expose that password. This check concerns the authentication setup rather
than a stored token.

> ### What we check
>
> - sudo is not configured to offer Touch ID through `pam_tid.so`.
>
> #### Sensitive Files
>
> - `/etc/pam.d/sudo`
> - `/etc/pam.d/sudo_local`

## Mitigation

```sh
av harden sudo
```

See the [hardening reference](../../hardeners/sudo.md) for setup and coverage.

---

## Recommended Further Action

You should set `Defaults timestamp_timeout=0` in `/etc/sudoers` or
`/etc/sudoers.d/*` to disable the grace period.

> We cannot check this for you because the file can only be read as root.

## Detailed Discussion

### Touch ID

We strongly suggest enabling Touch ID for sudo (where biometrics are available)

> Rationale 1: if you are conditioned to type your password whenever prompted it
> is trivial for malware to phish your password.

> Rationale 2: a timing attack could snatch keyboard focus just before you type
> your password

> Rational 3: if you are conditioned to type your password whenever prompted it
> is not as uncommon as you would hope for you to accidentally type it into the
> wrong field where it may be logged or captured by malware.

### `sudo` has non-zero timeout

`sudo` having a grace period is a convenience feature that allows agents or
malware to perform `sudo` operations without having to re-authenticate.

Agents would likely do it non maliciously, but you still shouldn't give them
the opportunity to “let’s try escalating that with `sudo`” and it works without
your consent.
