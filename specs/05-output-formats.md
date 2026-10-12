# 05 — Output Formats

## 5.1 Human-readable (default)

```
Target:       example.com:443
TLS Version:  1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
KEM:          X25519Kyber768Draft00
Certificate:  ECDSA-secp256r1-with-SHA256
Quantum readiness: TRANSITIONAL

Issues:
  [WARN] Certificate signature uses ECDSA (vulnerable to Shor's algorithm).
  [WARN] Leaf public key is ECDSA P-256 (vulnerable to Shor's algorithm).
  [OK]   Negotiated key exchange uses hybrid PQ KEM (X25519Kyber768Draft00).

Policy: nist-quantum-ready-2030
Result: FAIL (2 warnings treated as failure)
```

## 5.2 JSON

```json
{
  "target": "example.com:443",
  "scan_time": "2026-10-06T12:00:00Z",
  "tls": {
    "version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "key_exchange": {
      "name": "X25519Kyber768Draft00",
      "quantum_status": "quantum-resistant"
    },
    "server_signature_algorithms": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
    "supported_groups": ["X25519Kyber768Draft00", "secp256r1"]
  },
  "certificates": [
    {
      "subject": "CN=example.com",
      "issuer": "CN=Example CA",
      "signature_algorithm": "ECDSA-SHA256",
      "public_key_algorithm": "ECDSA",
      "public_key_size": 256,
      "curve": "P-256",
      "quantum_status": "vulnerable"
    }
  ],
  "findings": [
    {
      "severity": "high",
      "category": "certificate-signature",
      "description": "Certificate chain relies on ECDSA signature",
      "quantum_risk": "Shor's algorithm breaks ECDLP",
      "remediation": "Re-issue with ML-DSA or hybrid certificate when available."
    }
  ],
  "policy": {
    "name": "nist-quantum-ready-2030",
    "result": "fail",
    "failed_checks": 2
  },
  "summary": {
    "overall_readiness": "transitional",
    "vulnerable_primitives": ["ECDSA P-256"],
    "quantum_resistant_primitives": ["AES-256-GCM", "X25519Kyber768Draft00"]
  }
}
```

## 5.3 SARIF / CI integration (future)

Define a SARIF output adapter so the tool can be used in CI/CD pipelines. (Out of scope for v1, but design the internal model to support it.)
