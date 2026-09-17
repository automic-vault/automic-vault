# supabase Detector

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
