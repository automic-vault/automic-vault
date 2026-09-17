# sqlcmd

```sh
cat "$HOME/.sqlcmd/sqlconfig"
```

This prints the file, including any database passwords it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - sqlcmd sqlconfig contains stored passwords.
>
> #### Sensitive Files
>
> - `~/.sqlcmd/sqlconfig`

## Mitigation

Run `av harden sqlcmd` to install the reviewed, signed sqlcmd Isotope and move
supported basic-auth passwords into Automic Vault custody. The default
sqlconfig retains only user, context, endpoint, and `@av` marker metadata.

The Gate binds Secret Application to the verified sqlcmd Target, selected user
profile, endpoint, and complete command. Credential creation and deletion use
separate approved mutations. Custom sqlconfig paths, unsupported
authentication, malformed markers, and missing Secret Values fail closed.

Legacy flags, environment passwords, certificates, and credentials supplied
outside the default modern sqlconfig remain outside this Hardener's coverage.

See the [hardening reference](../../hardeners/sqlcmd.md) for setup and coverage.
