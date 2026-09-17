# huggingface-cli Detector

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
