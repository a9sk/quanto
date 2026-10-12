# 07 — Go Library API

```go
package quanto

// Scanner performs endpoint analysis.
type Scanner struct {
    Timeout       time.Duration
    InsecureSkipVerify bool
    SNI           string
    StartTLS      string
    ClientCert    tls.Certificate
    RootCAs       *x509.CertPool
}

// ScanResult is the cryptographic inventory + findings.
type ScanResult struct {
    Target        string
    ScanTime      time.Time
    TLS           TLSInfo
    Certificates  []CertificateInfo
    Findings      []Finding
    PolicyResult  PolicyResult
}

type TLSInfo struct {
    Version              string
    CipherSuite          string
    KeyExchange          PrimitiveInfo
    ServerSigAlgs        []string
    SupportedGroups      []string
    ALPN                 string
}

type CertificateInfo struct {
    Subject              string
    Issuer               string
    SignatureAlgorithm   string
    PublicKeyAlgorithm   string
    PublicKeySize        int
    Curve                string
    QuantumStatus        QuantumStatus
    NotBefore, NotAfter  time.Time
}

type QuantumStatus string

const (
    QuantumVulnerable  QuantumStatus = "vulnerable"
    QuantumReduced     QuantumStatus = "reduced"
    QuantumTransitional QuantumStatus = "transitional"
    QuantumResistant   QuantumStatus = "quantum-resistant"
    QuantumUnknown     QuantumStatus = "unknown"
)

type Finding struct {
    Severity      string // critical, high, medium, low, info
    Category      string // tls-version, cipher-suite, certificate-signature, public-key, key-exchange, hash, etc.
    Description   string
    QuantumRisk   string
    Remediation   string
}

// AnalyzeEndpoint performs a network scan.
func (s *Scanner) AnalyzeEndpoint(ctx context.Context, target string) (*ScanResult, error)

// AnalyzeCertificate analyzes an in-memory certificate or chain.
func AnalyzeCertificate(chain []*x509.Certificate, key crypto.PrivateKey) (*CertResult, error)

// AnalyzePEM parses PEM bytes and dispatches to cert/key analyzers.
func AnalyzePEM(data []byte, password string) (*PEMResult, error)
```
