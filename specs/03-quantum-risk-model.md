# 03 — Quantum Risk Model

## 3.1 Asymmetric primitives

| Primitive | Quantum Status | Rationale |
|-----------|----------------|-----------|
| RSA (any key size) | **Vulnerable** | Shor’s algorithm factors efficiently. |
| Finite-field DH/DSA | **Vulnerable** | Shor’s algorithm solves DLP efficiently. |
| ECDH/ECDSA (P-256, P-384, P-521, Brainpool, secp256k1) | **Vulnerable** | Shor’s algorithm solves ECDLP efficiently. |
| Ed25519 / Ed448 | **Vulnerable** | Based on ECDLP over Curve25519/Ed448. |
| X25519 / X448 | **Vulnerable** | ECDLP-based. |
| ML-KEM / Kyber | **Quantum-resistant** | Lattice-based KEM (NIST FIPS 203). |
| ML-DSA / Dilithium | **Quantum-resistant** | Lattice-based signature (NIST FIPS 204). |
| SLH-DSA / SPHINCS+ | **Quantum-resistant** | Hash-based signature (NIST FIPS 205). |
| Falcon | **Quantum-resistant** | Lattice-based signature (NIST PQC alternate). |
| XMSS / LMS | **Quantum-resistant** | Stateful hash-based signatures (RFC 8391 / NIST SP 800-208). |
| XMSS^MT / HSS | **Quantum-resistant** | Multi-tree variants. |

## 3.2 Symmetric & hash primitives

| Primitive | Quantum Status | Guidance |
|-----------|----------------|----------|
| AES-128, SEED, CAMELLIA-128 | **Reduced margin** | Grover reduces 128-bit security to ~64-bit. Recommend AES-256. |
| AES-256, CAMELLIA-256 | **Quantum-resistant** | Sufficient margin against Grover. |
| SHA-1, SHA-256, SHA3-256, HMAC-SHA256 | **Reduced margin** | Recommend SHA-384/SHA-512/SHA3-384+. |
| SHA-384, SHA-512, SHA3-512, BLAKE2b-512 | **Quantum-resistant** | Sufficient margin. |
| SHAKE256 | **Quantum-resistant** | Extendable-output function with configurable strength. |
| MD5, SHA-0 | **Broken classically** | Reject unconditionally. |
