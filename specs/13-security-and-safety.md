# 13 — Security & Safety

- Never write parsed private keys to output.
- When analyzing keys, report algorithm/size only; do not expose key material.
- Default to verifying server certificates; `--insecure` must be explicit.
- Respect connection timeouts and cancellation contexts.
- Do not perform aggressive renegotiation or downgrade attacks.
