# gh-cli-keychain-access Detector

## Trigger Conditions

- The access-control list for a `gh:<host>` Keychain item authorizes
  `/usr/bin/security` to read its secret non-interactively.

The official macOS `gh` executable is Developer ID signed, but its upstream
Keychain integration delegates credential reads to `/usr/bin/security`. The
signature does not restrict retrieval to `gh` when `/usr/bin/security` is in
the item's access list.

Confirm the finding in a private terminal:

```sh
/usr/bin/security find-generic-password -s gh:<host> -w
```

`gh` also provides an independent Secret Disclosure command:

```sh
gh auth token
```

Both commands print a live token to standard output. Do not paste their output
into an issue report.

## Mitigation

```sh
av harden gh
```
