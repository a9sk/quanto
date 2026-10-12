# Quantum Risk Model

This document explains how Quanto classifies cryptographic primitives with respect to quantum computers.

## Asymmetric cryptography and Shor's algorithm

Shor's algorithm solves the integer factorization and discrete logarithm problems in polynomial time on a sufficiently large quantum computer. This breaks:

- **RSA** — based on integer factorization.
- **Finite-field Diffie-Hellman (DH) and DSA** — based on the discrete logarithm problem.
- **Elliptic-curve cryptography (ECDH, ECDSA, Ed25519, Ed448, X25519, X448)** — based on the elliptic-curve discrete logarithm problem.

Quanto marks all of these as **vulnerable** regardless of key size.

## Post-quantum asymmetric algorithms

The following are considered **quantum-resistant** today:

- **ML-KEM** (Kyber) — lattice-based key encapsulation mechanism (NIST FIPS 203).
- **ML-DSA** (Dilithium) — lattice-based digital signature (NIST FIPS 204).
- **SLH-DSA** (SPHINCS+) — hash-based digital signature (NIST FIPS 205).
- **Falcon** — lattice-based signature (NIST PQC alternate).
- **XMSS / LMS** — stateful hash-based signatures (RFC 8391 / NIST SP 800-208).

## Hybrid schemes

Hybrid key exchange (e.g., X25519Kyber768Draft00, SecP256r1MLKEM768) combines a classical algorithm with a post-quantum KEM. These are classified as **transitional**: they protect today against passive harvest-now/decrypt-later attacks, but are not fully quantum-resistant because the classical component remains vulnerable.

## Symmetric cryptography and Grover's algorithm

Grover's search algorithm halves the effective security of symmetric ciphers and hash functions:

- **AES-128** — effective security drops from 128 bits to ~64 bits. Classified as **reduced margin**.
- **AES-256** — effective security remains ~128 bits. Classified as **quantum-resistant**.
- **SHA-256 / SHA3-256 / HMAC-SHA256** — effective security drops to ~128 bits. Classified as **reduced margin**.
- **SHA-384 / SHA-512 / SHA3-384 / SHA3-512 / BLAKE2b-512** — sufficient margin. Classified as **quantum-resistant**.

## Hash-based signatures

Hash-based signatures (SLH-DSA, XMSS, LMS) derive security entirely from the properties of the hash function used. With SHA-256 they are reduced margin; with SHA-512/SHAKE256 they are quantum-resistant.

## Readiness levels

| Level | Meaning |
|-------|---------|
| Vulnerable | Relies on a primitive broken by Shor's algorithm or classically insecure. |
| Reduced | Symmetric/hash primitive whose quantum security margin is halved by Grover. |
| Transitional | Hybrid scheme or endpoint with mixed classical/PQ support. |
| Quantum-resistant | Uses primitives not known to be broken by quantum algorithms. |
| Unknown | Algorithm not recognized by the registry. |

## Policy implications

- A `transitional` policy permits reduced-margin and transitional primitives.
- A `required` policy permits only quantum-resistant primitives (with transitional schemes often rejected for pure-PQ deployments).
