# 01 — Goals & Non-Goals

## Goals

- Accurate cryptographic inventory of TLS endpoints and PEM artifacts.
- Clear quantum-risk classification per primitive.
- Actionable remediation guidance.
- Usable as both CLI and Go library.
- Extensible policy engine for future algorithm lists (NIST PQC standards, hybrid KEMs).

## Non-Goals

- Not a generic vulnerability scanner (no heartbleed/BEAST/POODLE checks beyond what affects quantum posture).
- Not a performance benchmark tool.
- Not a penetration-testing tool; no active exploitation.
