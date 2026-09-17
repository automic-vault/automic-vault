# supabase

It is trivial for anything on your computer to exfiltrate supabase’s secret:

```sh
cat "$HOME/.supabase/access-token"
```

This prints the file, including any Supabase access tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Supabase CLI fallback access-token file exists and is not empty.
>
> #### Sensitive Files
>
> - `$SUPABASE_HOME/access-token`
> - `~/.supabase/access-token`

## Mitigation

```sh
av harden supabase
```

See the [hardening reference](../../hardeners/supabase.md) for setup and coverage.
