# 00 — Overview

Build a Go CLI/library that inspects TLS/SSL endpoints and certificates to assess their **quantum-readiness** — i.e., whether they rely on cryptographic primitives that are vulnerable to cryptanalytically-relevant quantum computers (CRQCs) or whether they already support post-quantum (PQ) algorithms.

The analyzer must:

- Scan remote TLS endpoints (host:port, URLs, IP:port) and local PEM files (certificates, chains, private keys).
- Detect classical asymmetric primitives at risk from Shor’s algorithm (RSA, finite-field DH, ECDH/ECDSA over NIST/Brainpool curves, EdDSA not considered PQ-safe).
- Detect symmetric/hash primitives whose quantum security margins are halved by Grover’s algorithm (AES-128, SHA-256, HMAC-SHA256) and flag them as requiring upgrade to AES-256/SHA-384+.
- Identify negotiated cipher suites, TLS versions, signature algorithms, key exchange groups, and certificate signatures.
- Report compliance posture against a quantum-readiness policy (classical-only, transitional, quantum-resistant).
- Return machine-readable JSON and human-readable tabular/text output.
