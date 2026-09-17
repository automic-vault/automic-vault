# huggingface-cli

```sh
cat "$HOME/.cache/huggingface/token"
```

This prints the file, including any Hugging Face tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Hugging Face token file contains a plaintext token.
>
> #### Sensitive Files
>
> - `~/.cache/huggingface/token`

## Mitigation

```sh
av harden huggingface-cli
```
