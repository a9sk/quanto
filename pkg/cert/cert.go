package cert

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/a9sk/quanto/pkg/model"
	"github.com/a9sk/quanto/pkg/registry"
)

// Analyzer analyzes cryptographic material.
type Analyzer struct {
	registry *registry.Registry
}

// New creates a new certificate analyzer using the default registry.
func New() *Analyzer {
	return &Analyzer{registry: registry.New()}
}

// NewWithRegistry creates an analyzer with a custom registry.
func NewWithRegistry(r *registry.Registry) *Analyzer {
	return &Analyzer{registry: r}
}

// AnalyzeCertificate analyzes an in-memory certificate chain and optional key.
func (a *Analyzer) AnalyzeCertificate(chain []*x509.Certificate, key crypto.PrivateKey) (*model.CertResult, error) {
	result := &model.CertResult{
		Certificates: make([]model.CertificateInfo, 0, len(chain)),
		Findings:     []model.Finding{},
	}

	for _, cert := range chain {
		info := a.certificateInfo(cert)
		result.Certificates = append(result.Certificates, info)
	}

	if key != nil {
		ki, err := a.keyInfo(key)
		if err != nil {
			return nil, fmt.Errorf("analyzing key: %w", err)
		}
		result.KeyInfo = ki
	}

	a.generateFindings(result)
	return result, nil
}

// AnalyzePEM parses PEM data and dispatches to the appropriate analyzer.
func (a *Analyzer) AnalyzePEM(data []byte, password string) (*model.PEMResult, error) {
	result := &model.PEMResult{
		Certificates: []model.CertificateInfo{},
		Keys:         []model.KeyInfo{},
		Findings:     []model.Finding{},
	}

	var blocks []*pem.Block
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		data = rest
	}

	if len(blocks) == 0 {
		return nil, fmt.Errorf("no PEM blocks found")
	}

	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate: %w", err)
			}
			result.Certificates = append(result.Certificates, a.certificateInfo(cert))
		case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY":
			key, err := parsePrivateKey(block.Bytes, password)
			if err != nil {
				return nil, fmt.Errorf("parsing private key: %w", err)
			}
			ki, err := a.keyInfo(key)
			if err != nil {
				return nil, fmt.Errorf("analyzing key: %w", err)
			}
			result.Keys = append(result.Keys, *ki)
		default:
			// Ignore unknown PEM types.
		}
	}

	// Convert to CertResult to reuse finding generation.
	certResult := &model.CertResult{
		Certificates: result.Certificates,
		Findings:     []model.Finding{},
	}
	if len(result.Keys) > 0 {
		certResult.KeyInfo = &result.Keys[0]
	}
	a.generateFindings(certResult)
	result.Findings = certResult.Findings

	return result, nil
}

func parsePrivateKey(der []byte, password string) (crypto.PrivateKey, error) {
	// Try unencrypted parse first.
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported or encrypted private key format")
}

func (a *Analyzer) certificateInfo(cert *x509.Certificate) model.CertificateInfo {
	info := model.CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsCA:               cert.IsCA,
		KeyUsage:           keyUsageNames(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageNames(cert.ExtKeyUsage),
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyAlgorithm = "RSA"
		info.PublicKeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyAlgorithm = "ECDSA"
		info.PublicKeySize = pub.Curve.Params().BitSize
		info.Curve = curveName(pub.Curve)
	case ed25519.PublicKey:
		info.PublicKeyAlgorithm = "Ed25519"
		info.PublicKeySize = 256
	case *dsa.PublicKey:
		info.PublicKeyAlgorithm = "DSA"
		info.PublicKeySize = pub.P.BitLen()
	default:
		info.PublicKeyAlgorithm = fmt.Sprintf("Unknown(%T)", cert.PublicKey)
	}

	// Determine overall quantum status based on public key and signature.
	info.QuantumStatus = a.worstCertificateStatus(cert, info)

	return info
}

func (a *Analyzer) worstCertificateStatus(cert *x509.Certificate, info model.CertificateInfo) model.QuantumStatus {
	statuses := []model.QuantumStatus{}

	// Public key status.
	if alg, ok := a.registry.LookupByName(info.PublicKeyAlgorithm); ok {
		statuses = append(statuses, alg.QuantumStatus)
	}
	if info.Curve != "" {
		if alg, ok := a.registry.LookupByName(info.Curve); ok {
			statuses = append(statuses, alg.QuantumStatus)
		}
	}

	// Signature algorithm status.
	sigName := signatureAlgorithmName(cert.SignatureAlgorithm)
	if alg, ok := a.registry.LookupByName(sigName); ok {
		statuses = append(statuses, alg.QuantumStatus)
	}

	// Hash used in signature.
	hashName := hashFromSignatureAlgorithm(cert.SignatureAlgorithm)
	if hashName != "" {
		if alg, ok := a.registry.LookupByName(hashName); ok {
			statuses = append(statuses, alg.QuantumStatus)
		}
	}

	return worstStatus(statuses)
}

func (a *Analyzer) keyInfo(key crypto.PrivateKey) (*model.KeyInfo, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &model.KeyInfo{
			Algorithm:     "RSA",
			Size:          k.N.BitLen(),
			QuantumStatus: model.QuantumVulnerable,
		}, nil
	case *ecdsa.PrivateKey:
		return &model.KeyInfo{
			Algorithm:     "ECDSA",
			Size:          k.Curve.Params().BitSize,
			Curve:         curveName(k.Curve),
			QuantumStatus: model.QuantumVulnerable,
		}, nil
	case ed25519.PrivateKey:
		return &model.KeyInfo{
			Algorithm:     "Ed25519",
			Size:          256,
			QuantumStatus: model.QuantumVulnerable,
		}, nil
	case *dsa.PrivateKey:
		return &model.KeyInfo{
			Algorithm:     "DSA",
			Size:          k.P.BitLen(),
			QuantumStatus: model.QuantumVulnerable,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

func (a *Analyzer) generateFindings(r *model.CertResult) {
	findings := []model.Finding{}

	for _, cert := range r.Certificates {
		// Public key finding.
		if status := cert.QuantumStatus; status == model.QuantumVulnerable {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityHigh,
				Category:    "public-key",
				Description: fmt.Sprintf("Certificate '%s' uses %s public key", cert.Subject, cert.PublicKeyAlgorithm),
				QuantumRisk: "Shor's algorithm solves the underlying hard problem in polynomial time",
				Remediation: remediationForPublicKey(cert.PublicKeyAlgorithm),
			})
		}

		// Signature algorithm finding.
		sigName := signatureAlgorithmNameFromString(cert.SignatureAlgorithm)
		if alg, ok := a.registry.LookupByName(sigName); ok && alg.QuantumStatus == model.QuantumVulnerable {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityHigh,
				Category:    "certificate-signature",
				Description: fmt.Sprintf("Certificate '%s' is signed with %s", cert.Subject, cert.SignatureAlgorithm),
				QuantumRisk: "Shor's algorithm breaks the signature scheme",
				Remediation: "Re-issue with ML-DSA, SLH-DSA, or a hybrid certificate when available.",
			})
		}

		// Weak hash finding.
		hashName := hashFromSignatureAlgorithmString(cert.SignatureAlgorithm)
		if hashName == "MD5" || hashName == "SHA-1" {
			findings = append(findings, model.Finding{
				Severity:    model.SeverityCritical,
				Category:    "hash",
				Description: fmt.Sprintf("Certificate '%s' uses weak hash %s in its signature", cert.Subject, hashName),
				QuantumRisk: fmt.Sprintf("%s is broken classically and quantum computers further reduce security", hashName),
				Remediation: "Re-issue with SHA-384/SHA-512 or migrate to a post-quantum signature.",
			})
		}
	}

	if r.KeyInfo != nil && r.KeyInfo.QuantumStatus == model.QuantumVulnerable {
		findings = append(findings, model.Finding{
			Severity:    model.SeverityHigh,
			Category:    "private-key",
			Description: fmt.Sprintf("Private key uses %s", r.KeyInfo.Algorithm),
			QuantumRisk: "Shor's algorithm can recover the private key from the public key",
			Remediation: remediationForPublicKey(r.KeyInfo.Algorithm),
		})
	}

	r.Findings = findings
}

func remediationForPublicKey(alg string) string {
	switch {
	case strings.EqualFold(alg, "RSA"):
		return "Replace with ML-DSA or a hybrid certificate; use ML-KEM for key exchange."
	case strings.EqualFold(alg, "ECDSA") || strings.EqualFold(alg, "ECDH"):
		return "Replace with ML-DSA or a hybrid certificate."
	case strings.EqualFold(alg, "Ed25519"):
		return "Replace with ML-DSA/SLH-DSA for long-term quantum resistance."
	default:
		return "Migrate to a NIST-approved post-quantum algorithm."
	}
}

func signatureAlgorithmName(alg x509.SignatureAlgorithm) string {
	return signatureAlgorithmNameFromString(alg.String())
}

func signatureAlgorithmNameFromString(s string) string {
	upper := strings.ToUpper(s)
	for _, name := range []string{"RSA-PSS", "RSA", "ECDSA", "DSA", "Ed25519", "Ed448"} {
		if strings.Contains(upper, name) {
			return name
		}
	}
	return s
}

func hashFromSignatureAlgorithm(alg x509.SignatureAlgorithm) string {
	return hashFromSignatureAlgorithmString(alg.String())
}

func hashFromSignatureAlgorithmString(s string) string {
	upper := strings.ToUpper(s)
	for _, name := range []string{"MD5", "SHA-1", "SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512"} {
		if strings.Contains(upper, name) {
			return normalizeHashName(name)
		}
	}
	return ""
}

func normalizeHashName(name string) string {
	switch name {
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	}
	return name
}

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return curve.Params().Name
	}
}

func worstStatus(statuses []model.QuantumStatus) model.QuantumStatus {
	if len(statuses) == 0 {
		return model.QuantumUnknown
	}
	order := []model.QuantumStatus{
		model.QuantumVulnerable,
		model.QuantumReduced,
		model.QuantumTransitional,
		model.QuantumResistant,
		model.QuantumUnknown,
	}
	for _, s := range order {
		for _, st := range statuses {
			if st == s {
				return s
			}
		}
	}
	return model.QuantumUnknown
}

func keyUsageNames(usage x509.KeyUsage) []string {
	var names []string
	m := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	for _, u := range m {
		if usage&u.flag != 0 {
			names = append(names, u.name)
		}
	}
	return names
}

func extKeyUsageNames(usages []x509.ExtKeyUsage) []string {
	names := make([]string, 0, len(usages))
	for _, u := range usages {
		names = append(names, extKeyUsageName(u))
	}
	return names
}

func extKeyUsageName(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeServerGatedCrypto"
	default:
		return fmt.Sprintf("ExtKeyUsage(%d)", u)
	}
}
