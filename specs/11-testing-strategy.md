# 11 — Testing Strategy

- **Unit tests** for registry lookups, certificate parsing, policy evaluation.
- **Integration tests** against:
  - `badssl.com` endpoints for TLS version/cipher suites.
  - Local `crypto/tls` test server with generated RSA/ECDSA/ML-DSA certs.
  - Cloudflare/Google endpoints that advertise X25519Kyber768.
- **Golden file tests** for JSON output.
- **Fuzz tests** for PEM parsing.
- **CI matrix** across Go 1.22+.
