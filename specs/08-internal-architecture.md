# 08 — Internal Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI                                  │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                     App Layer                                │
│  (scan command, cert command, policy command, output render) │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                   Analyzer Library                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Scanner    │  │   CertParser │  │ PolicyEngine │       │
│  │  (network)   │  │   (crypto)   │  │  (rules)     │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                     Registry                                 │
│  (algorithm metadata: name, family, quantum status, OIDs,    │
│   IANA code points, Go constants)                            │
└─────────────────────────────────────────────────────────────┘
```

## 8.1 Registry

Maintain a central registry of cryptographic primitives:

- TLS cipher suites (IANA registry + OpenSSL names).
- Signature algorithms (TLS 1.3 extension values + X.509 OIDs).
- Named groups (IANA + draft/experimental groups like X25519Kyber768).
- Public key algorithms and curves.

Each entry maps to:

```go
type Algorithm struct {
    Name          string
    Family        string // RSA, DH, ECDH, ECDSA, EdDSA, ML-KEM, ML-DSA, AES, SHA, etc.
    Type          string // kex, signature, cipher, hash, kdf
    QuantumStatus QuantumStatus
    Reference     string // RFC / NIST standard
    OIDs          []asn1.ObjectIdentifier
    CodePoints    []uint16
    Aliases       []string
}
```

## 8.2 Scanner

- Use `crypto/tls` for handshake inspection.
- Use `tls.Config.GetConfigForClient` / custom `tls.Config` to request specific cipher suites and groups for probing.
- For TLS 1.3, collect `ConnectionState` fields: `Version`, `CipherSuite`, `NegotiatedProtocol`, `ServerName`, `PeerCertificates`, `VerifiedChains`, `SignedCertificateTimestamps`.
- For supported algorithms, perform a client hello with broad extensions and parse the server hello response; do not rely solely on first handshake.

## 8.3 Certificate Analyzer

- Map `x509.SignatureAlgorithm` and `x509.PublicKeyAlgorithm` to registry entries.
- Handle unknown algorithms gracefully (report `unknown` with raw OID).
- Detect weak hashes (MD5, SHA-1) independently of signature family.
- Support explicit curve detection for ECDSA/ECDH.

## 8.4 Policy Engine

- Load policy from YAML/JSON into `Policy` struct.
- Evaluate each observed primitive against:
  - `min_tls_version`
  - `allowed/forbidden_cipher_suites`
  - `allowed/forbidden_key_exchange`
  - `allowed/forbidden_signature_algorithms`
  - `allowed/forbidden_public_key_algorithms`
  - `allowed/forbidden_hashes`
  - `quantum_readiness` level
- Produce `PolicyResult` with per-check status and aggregated result.
