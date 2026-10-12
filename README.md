# quanto: quantum-ready TLS/SSL analyzer

> **quanto** is a Go CLI and library that inspects TLS/SSL endpoints and X.509 certificates to assess their **quantum-readiness**, whether they rely on cryptographic primitives that are vulnerable to cryptanalytically-relevant quantum computers (CRQCs) or already support post-quantum algorithms.

---

### use as a library

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/a9sk/quanto/pkg/model"
    "github.com/a9sk/quanto/pkg/scanner"
)

func main() {
    s := scanner.New(model.ScannerConfig{
        Timeout:            10 * time.Second,
        InsecureSkipVerify: true,
    })

    result, err := s.AnalyzeEndpoint(context.Background(), "example.com:443")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Readiness: %s\n", result.Summary.OverallReadiness)
    for _, f := range result.Findings {
        fmt.Printf("[%s] %s: %s\n", f.Severity, f.Category, f.Description)
    }
}
```
---

- [specs/](specs/): detailed implementation specifications (used as prompt).
- [docs/quantum-risk-model.md](docs/quantum-risk-model.md): quantum risk classification rationale.
