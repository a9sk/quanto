# 09 — Built-in Policies

## 9.1 `default`

- No hard failures; reports inventory and findings only.

## 9.2 `transitional-2026`

- TLS 1.3 required.
- AES-128 allowed only with hybrid PQ KEM.
- RSA/ECDSA certificates allowed but flagged for migration.
- No export/anon/MD5/SHA-1.

## 9.3 `nist-quantum-ready-2030`

- TLS 1.3 required.
- Key exchange MUST be PQ or hybrid PQ.
- Signatures SHOULD be ML-DSA/SLH-DSA or hybrid; ECDSA/RSA rejected.
- Symmetric: AES-256 or equivalent.
- Hashes: SHA-384/512 or SHA3-384/512.

## 9.4 `cnsa-2.0`

- Align with NSA CNSA 2.0 timeline.
- RSA/ECDSA/DH/ECDH forbidden by 2030 for software/firmware signing; 2033 for general use.
- AES-256, SHA-384/512, ML-KEM/ML-DSA required.
