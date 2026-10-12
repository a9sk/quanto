# 04 — Functional Requirements

## 4.1 Endpoint Scanning

```
quanto scan example.com:443
quanto scan https://example.com
quanto scan 192.0.2.10:8443 --sni=example.com
```

The scanner MUST:

1. Resolve and dial the target with a configurable timeout (default 10s).
2. Perform TLS handshake(s) to collect:
   - Negotiated TLS version.
   - Negotiated cipher suite.
   - Server certificate chain.
   - Supported signature algorithms (TLS 1.3 `signature_algorithms` extension).
   - Supported groups/key exchange groups (TLS 1.3 `supported_groups` extension).
   - ALPN / SNI information.
3. Optionally probe supported cipher suites with multiple handshakes (hello-based scan, not full MITM).
4. Support STARTTLS protocols: SMTP, IMAP, POP3, FTP, XMPP, LDAP.
5. Support client certificate authentication when `--client-cert` and `--client-key` are provided.
6. Honor `--insecure` to skip certificate chain validation for inspection-only mode.

## 4.2 Certificate / PEM Analysis

```
quanto cert server.pem
quanto cert --chain chain.pem --key key.pem
```

The analyzer MUST:

1. Parse X.509 v3 certificates and certificate chains.
2. Extract:
   - Signature algorithm (OID and friendly name).
   - Subject public key algorithm, size, and parameters (RSA modulus size, EC curve, DH parameters).
   - Validity dates.
   - Key usage / extended key usage.
   - Subject / issuer names.
3. Parse PKCS#1, PKCS#8, SEC1 private keys to identify key algorithm and size.
4. Support PEM and DER encodings.
5. Reject encrypted keys unless `--password` is supplied.

## 4.3 Policy Engine

Define a policy as YAML/JSON:

```yaml
name: nist-quantum-ready-2030
version: "1.0"
quantum_readiness: required   # none | transitional | required
min_tls_version: "1.3"
allowed_cipher_suites:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256   # transitional only
allowed_key_exchange:
  - ML-KEM-768
  - ML-KEM-1024
  - X25519Kyber768Draft00
allowed_signature_algorithms:
  - ML-DSA-65
  - ML-DSA-87
  - ECDSA-with-SHA384   # transitional only, with deprecation date
forbidden_algorithms:
  - RSA
  - DSA
  - ECDSA
  - ECDH
  - DH
  - TLS_RSA_WITH_AES_128_GCM_SHA256
```

Engine behavior:

- Compare every observed primitive against policy allow/forbid lists.
- Return `PASS`, `FAIL`, or `WARNING` per check.
- Support a built-in default policy aligned with current NIST/CNSA 2.0 guidance.
- Allow user-supplied policy files.
