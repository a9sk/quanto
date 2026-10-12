package model

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// QuantumStatus classifies an algorithm's resistance to quantum attacks.
type QuantumStatus string

const (
	QuantumVulnerable   QuantumStatus = "vulnerable"
	QuantumReduced      QuantumStatus = "reduced"
	QuantumTransitional QuantumStatus = "transitional"
	QuantumResistant    QuantumStatus = "quantum-resistant"
	QuantumUnknown      QuantumStatus = "unknown"
)

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Algorithm describes a cryptographic primitive and its quantum posture.
type Algorithm struct {
	Name          string        `json:"name" yaml:"name"`
	Family        string        `json:"family" yaml:"family"`
	Type          string        `json:"type" yaml:"type"`
	QuantumStatus QuantumStatus `json:"quantum_status" yaml:"quantum_status"`
	Reference     string        `json:"reference,omitempty" yaml:"reference,omitempty"`
	OIDs          []string      `json:"oids,omitempty" yaml:"oids,omitempty"`
	CodePoints    []uint16      `json:"code_points,omitempty" yaml:"code_points,omitempty"`
	Aliases       []string      `json:"aliases,omitempty" yaml:"aliases,omitempty"`
}

// PrimitiveInfo is the resolved metadata for an observed primitive.
type PrimitiveInfo struct {
	Name          string        `json:"name" yaml:"name"`
	Family        string        `json:"family" yaml:"family"`
	QuantumStatus QuantumStatus `json:"quantum_status" yaml:"quantum_status"`
}

// TLSInfo captures negotiated and advertised TLS parameters.
type TLSInfo struct {
	Version         string        `json:"version" yaml:"version"`
	CipherSuite     string        `json:"cipher_suite" yaml:"cipher_suite"`
	KeyExchange     PrimitiveInfo `json:"key_exchange" yaml:"key_exchange"`
	ServerSigAlgs   []string      `json:"server_signature_algorithms,omitempty" yaml:"server_signature_algorithms,omitempty"`
	SupportedGroups []string      `json:"supported_groups,omitempty" yaml:"supported_groups,omitempty"`
	ALPN            string        `json:"alpn,omitempty" yaml:"alpn,omitempty"`
	SNI             string        `json:"sni,omitempty" yaml:"sni,omitempty"`
}

// CertificateInfo captures the quantum-relevant fields of an X.509 certificate.
type CertificateInfo struct {
	Subject            string        `json:"subject" yaml:"subject"`
	Issuer             string        `json:"issuer" yaml:"issuer"`
	SerialNumber       string        `json:"serial_number" yaml:"serial_number"`
	SignatureAlgorithm string        `json:"signature_algorithm" yaml:"signature_algorithm"`
	PublicKeyAlgorithm string        `json:"public_key_algorithm" yaml:"public_key_algorithm"`
	PublicKeySize      int           `json:"public_key_size" yaml:"public_key_size"`
	Curve              string        `json:"curve,omitempty" yaml:"curve,omitempty"`
	QuantumStatus      QuantumStatus `json:"quantum_status" yaml:"quantum_status"`
	NotBefore          time.Time     `json:"not_before" yaml:"not_before"`
	NotAfter           time.Time     `json:"not_after" yaml:"not_after"`
	IsCA               bool          `json:"is_ca" yaml:"is_ca"`
	KeyUsage           []string      `json:"key_usage,omitempty" yaml:"key_usage,omitempty"`
	ExtKeyUsage        []string      `json:"ext_key_usage,omitempty" yaml:"ext_key_usage,omitempty"`
}

// Finding represents a single quantum-readiness issue.
type Finding struct {
	Severity    Severity `json:"severity" yaml:"severity"`
	Category    string   `json:"category" yaml:"category"`
	Description string   `json:"description" yaml:"description"`
	QuantumRisk string   `json:"quantum_risk" yaml:"quantum_risk"`
	Remediation string   `json:"remediation" yaml:"remediation"`
}

// PolicyResult is the outcome of applying a policy to a scan result.
type PolicyResult struct {
	Name          string       `json:"name" yaml:"name"`
	Result        PolicyStatus `json:"result" yaml:"result"`
	FailedChecks  int          `json:"failed_checks" yaml:"failed_checks"`
	WarningChecks int          `json:"warning_checks" yaml:"warning_checks"`
	PassedChecks  int          `json:"passed_checks" yaml:"passed_checks"`
	Checks        []Check      `json:"checks,omitempty" yaml:"checks,omitempty"`
}

// PolicyStatus is the aggregated policy verdict.
type PolicyStatus string

const (
	PolicyPass    PolicyStatus = "pass"
	PolicyFail    PolicyStatus = "fail"
	PolicyWarning PolicyStatus = "warning"
)

// Check is a single policy evaluation.
type Check struct {
	Name     string       `json:"name" yaml:"name"`
	Status   PolicyStatus `json:"status" yaml:"status"`
	Message  string       `json:"message" yaml:"message"`
	Severity Severity     `json:"severity" yaml:"severity"`
}

// Summary provides a high-level readiness summary.
type Summary struct {
	OverallReadiness           string   `json:"overall_readiness" yaml:"overall_readiness"`
	VulnerablePrimitives       []string `json:"vulnerable_primitives,omitempty" yaml:"vulnerable_primitives,omitempty"`
	ReducedMarginPrimitives    []string `json:"reduced_margin_primitives,omitempty" yaml:"reduced_margin_primitives,omitempty"`
	QuantumResistantPrimitives []string `json:"quantum_resistant_primitives,omitempty" yaml:"quantum_resistant_primitives,omitempty"`
}

// ScanResult is the top-level result of analyzing an endpoint.
type ScanResult struct {
	Target          string              `json:"target" yaml:"target"`
	ScanTime        time.Time           `json:"scan_time" yaml:"scan_time"`
	TLS             TLSInfo             `json:"tls" yaml:"tls"`
	Certificates    []CertificateInfo   `json:"certificates" yaml:"certificates"`
	RawCertificates []*x509.Certificate `json:"-" yaml:"-"`
	Findings        []Finding           `json:"findings" yaml:"findings"`
	PolicyResult    PolicyResult        `json:"policy" yaml:"policy"`
	Summary         Summary             `json:"summary" yaml:"summary"`
}

// CertResult is the top-level result of analyzing certificates/keys.
type CertResult struct {
	Certificates []CertificateInfo `json:"certificates" yaml:"certificates"`
	KeyInfo      *KeyInfo          `json:"key_info,omitempty" yaml:"key_info,omitempty"`
	Findings     []Finding         `json:"findings" yaml:"findings"`
	PolicyResult PolicyResult      `json:"policy" yaml:"policy"`
	Summary      Summary           `json:"summary" yaml:"summary"`
}

// KeyInfo holds metadata about a parsed private key.
type KeyInfo struct {
	Algorithm     string        `json:"algorithm" yaml:"algorithm"`
	Size          int           `json:"size" yaml:"size"`
	Curve         string        `json:"curve,omitempty" yaml:"curve,omitempty"`
	QuantumStatus QuantumStatus `json:"quantum_status" yaml:"quantum_status"`
}

// PEMResult is the result of parsing an arbitrary PEM bundle.
type PEMResult struct {
	Certificates []CertificateInfo `json:"certificates" yaml:"certificates"`
	Keys         []KeyInfo         `json:"keys" yaml:"keys"`
	Findings     []Finding         `json:"findings" yaml:"findings"`
}

// Policy defines a quantum-readiness policy.
type Policy struct {
	Name             string   `json:"name" yaml:"name"`
	Version          string   `json:"version" yaml:"version"`
	QuantumReadiness string   `json:"quantum_readiness" yaml:"quantum_readiness"`
	MinTLSVersion    string   `json:"min_tls_version,omitempty" yaml:"min_tls_version,omitempty"`
	AllowedCiphers   []string `json:"allowed_cipher_suites,omitempty" yaml:"allowed_cipher_suites,omitempty"`
	ForbiddenCiphers []string `json:"forbidden_cipher_suites,omitempty" yaml:"forbidden_cipher_suites,omitempty"`
	AllowedKEX       []string `json:"allowed_key_exchange,omitempty" yaml:"allowed_key_exchange,omitempty"`
	ForbiddenKEX     []string `json:"forbidden_key_exchange,omitempty" yaml:"forbidden_key_exchange,omitempty"`
	AllowedSigs      []string `json:"allowed_signature_algorithms,omitempty" yaml:"allowed_signature_algorithms,omitempty"`
	ForbiddenSigs    []string `json:"forbidden_signature_algorithms,omitempty" yaml:"forbidden_signature_algorithms,omitempty"`
	AllowedPK        []string `json:"allowed_public_key_algorithms,omitempty" yaml:"allowed_public_key_algorithms,omitempty"`
	ForbiddenPK      []string `json:"forbidden_public_key_algorithms,omitempty" yaml:"forbidden_public_key_algorithms,omitempty"`
	AllowedHashes    []string `json:"allowed_hashes,omitempty" yaml:"allowed_hashes,omitempty"`
	ForbiddenHashes  []string `json:"forbidden_hashes,omitempty" yaml:"forbidden_hashes,omitempty"`
}

// ScannerConfig holds options for endpoint scanning.
type ScannerConfig struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
	SNI                string
	StartTLS           string
	ClientCert         *tls.Certificate
	RootCAs            *x509.CertPool
}

// CryptoMaterial wraps certificates and a private key for analysis.
type CryptoMaterial struct {
	Chain []*x509.Certificate
	Key   crypto.PrivateKey
}
