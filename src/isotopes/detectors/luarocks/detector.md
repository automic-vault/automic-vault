# luarocks Detector

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
