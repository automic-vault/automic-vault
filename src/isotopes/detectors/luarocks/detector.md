# luarocks

It is trivial for anything on your computer to exfiltrate luarocks’s secret:

```sh
cat "$HOME/.config/luarocks/upload_config.lua"
```

This prints the file, including any LuaRocks upload API keys it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - LuaRocks upload config contains a plaintext API key.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/luarocks/upload_config.lua`
> - `~/.config/luarocks/upload_config.lua`
> - `~/.luarocks/upload_config.lua`

## Mitigation

```sh
av harden luarocks
```
