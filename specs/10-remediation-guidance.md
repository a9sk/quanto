# 10 — Remediation Guidance

For each finding the tool MUST provide concise remediation text:

| Finding | Remediation |
|---------|-------------|
| RSA certificate | Replace with ML-DSA or hybrid certificate; use ML-KEM for key exchange. |
| ECDSA certificate | Replace with ML-DSA or hybrid certificate. |
| DH/ECDH key exchange | Prefer TLS 1.3 with X25519Kyber768Draft00 / ML-KEM-768+. |
| AES-128 cipher | Upgrade to AES-256-GCM or ChaCha20-Poly1305 (note: ChaCha20-Poly1305 has ~256-bit security). |
| SHA-256 certificate signature | Re-issue with SHA-384/SHA-512 or migrate to PQ signature. |
| TLS 1.2 or lower | Enable TLS 1.3; PQ key exchange is only practical in TLS 1.3 ecosystem today. |
| Anonymous/NULL ciphers | Disable immediately. |
