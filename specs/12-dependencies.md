# 12 — Dependencies

Preferred standard library first:

- `crypto/tls`, `crypto/x509`, `crypto/x509/pkix`, `encoding/pem`
- `net`, `context`, `time`, `encoding/json`, `encoding/asn1`

Allowed external dependencies (pin versions in `go.mod`):

- `gopkg.in/yaml.v3` for policy files.
- Test-only: `github.com/fortuna/go-tester` or `github.com/google/go-cmp`.

Avoid heavy TLS probing libraries; keep implementation self-contained.
