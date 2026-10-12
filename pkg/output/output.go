package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/a9sk/quanto/pkg/model"
	"gopkg.in/yaml.v3"
)

// Format is an output format identifier.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// Renderer renders a ScanResult to a writer.
type Renderer struct {
	format Format
	w      io.Writer
}

// NewRenderer creates a renderer for the given format.
func NewRenderer(format string, w io.Writer) (*Renderer, error) {
	f := Format(strings.ToLower(format))
	switch f {
	case FormatText, FormatJSON, FormatYAML:
		return &Renderer{format: f, w: w}, nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

// RenderScan writes a ScanResult in the configured format.
func (r *Renderer) RenderScan(result *model.ScanResult) error {
	switch r.format {
	case FormatJSON:
		enc := json.NewEncoder(r.w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case FormatYAML:
		return yaml.NewEncoder(r.w).Encode(result)
	case FormatText:
		return r.renderScanText(result)
	default:
		return fmt.Errorf("unknown format")
	}
}

// RenderCert writes a CertResult in the configured format.
func (r *Renderer) RenderCert(result *model.CertResult) error {
	switch r.format {
	case FormatJSON:
		enc := json.NewEncoder(r.w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case FormatYAML:
		return yaml.NewEncoder(r.w).Encode(result)
	case FormatText:
		return r.renderCertText(result)
	default:
		return fmt.Errorf("unknown format")
	}
}

func (r *Renderer) renderScanText(result *model.ScanResult) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "Target:       %s\n", result.Target)
	fmt.Fprintf(b, "Scan Time:    %s\n", result.ScanTime.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(b, "TLS Version:  %s\n", result.TLS.Version)
	fmt.Fprintf(b, "Cipher Suite: %s\n", result.TLS.CipherSuite)
	if result.TLS.KeyExchange.Name != "" {
		fmt.Fprintf(b, "Key Exchange: %s (%s)\n", result.TLS.KeyExchange.Name, result.TLS.KeyExchange.QuantumStatus)
	}
	if result.TLS.ALPN != "" {
		fmt.Fprintf(b, "ALPN:         %s\n", result.TLS.ALPN)
	}
	if result.TLS.SNI != "" {
		fmt.Fprintf(b, "SNI:          %s\n", result.TLS.SNI)
	}
	if len(result.TLS.SupportedGroups) > 0 {
		fmt.Fprintf(b, "TLS 1.3 Supported Groups: %s\n", strings.Join(result.TLS.SupportedGroups, ", "))
	}
	fmt.Fprintf(b, "\nCertificates:\n")
	for _, cert := range result.Certificates {
		fmt.Fprintf(b, "  Subject:     %s\n", cert.Subject)
		fmt.Fprintf(b, "  Issuer:      %s\n", cert.Issuer)
		fmt.Fprintf(b, "  Algorithm:   %s (%s)\n", cert.PublicKeyAlgorithm, cert.QuantumStatus)
		fmt.Fprintf(b, "  Signature:   %s\n", cert.SignatureAlgorithm)
		fmt.Fprintf(b, "  Valid:       %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	}

	fmt.Fprintf(b, "\nIssues:\n")
	if len(result.Findings) == 0 {
		fmt.Fprintln(b, "  None")
	}
	for _, f := range result.Findings {
		fmt.Fprintf(b, "  [%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.Category, f.Description)
		fmt.Fprintf(b, "       Risk: %s\n", f.QuantumRisk)
		fmt.Fprintf(b, "       Fix:  %s\n", f.Remediation)
	}

	fmt.Fprintf(b, "\nSummary:\n")
	fmt.Fprintf(b, "  Overall readiness: %s\n", result.Summary.OverallReadiness)
	if len(result.Summary.VulnerablePrimitives) > 0 {
		fmt.Fprintf(b, "  Vulnerable:        %s\n", strings.Join(result.Summary.VulnerablePrimitives, ", "))
	}
	if len(result.Summary.ReducedMarginPrimitives) > 0 {
		fmt.Fprintf(b, "  Reduced margin:    %s\n", strings.Join(result.Summary.ReducedMarginPrimitives, ", "))
	}
	if len(result.Summary.QuantumResistantPrimitives) > 0 {
		fmt.Fprintf(b, "  Quantum-resistant: %s\n", strings.Join(result.Summary.QuantumResistantPrimitives, ", "))
	}

	fmt.Fprintf(b, "\nPolicy: %s\n", result.PolicyResult.Name)
	fmt.Fprintf(b, "Result: %s (passed=%d, failed=%d, warnings=%d)\n",
		result.PolicyResult.Result, result.PolicyResult.PassedChecks,
		result.PolicyResult.FailedChecks, result.PolicyResult.WarningChecks)

	_, err := io.WriteString(r.w, b.String())
	return err
}

func (r *Renderer) renderCertText(result *model.CertResult) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "Certificate Analysis\n\n")
	for _, cert := range result.Certificates {
		fmt.Fprintf(b, "Subject:   %s\n", cert.Subject)
		fmt.Fprintf(b, "Issuer:    %s\n", cert.Issuer)
		fmt.Fprintf(b, "Algorithm: %s (%s)\n", cert.PublicKeyAlgorithm, cert.QuantumStatus)
		fmt.Fprintf(b, "Signature: %s\n", cert.SignatureAlgorithm)
		fmt.Fprintf(b, "Valid:     %s to %s\n\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	}
	if result.KeyInfo != nil {
		fmt.Fprintf(b, "Private Key:\n")
		fmt.Fprintf(b, "  Algorithm: %s\n", result.KeyInfo.Algorithm)
		fmt.Fprintf(b, "  Size:      %d bits\n", result.KeyInfo.Size)
		fmt.Fprintf(b, "  Status:    %s\n\n", result.KeyInfo.QuantumStatus)
	}
	fmt.Fprintf(b, "Issues:\n")
	if len(result.Findings) == 0 {
		fmt.Fprintln(b, "  None")
	}
	for _, f := range result.Findings {
		fmt.Fprintf(b, "  [%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.Category, f.Description)
		fmt.Fprintf(b, "       Risk: %s\n", f.QuantumRisk)
		fmt.Fprintf(b, "       Fix:  %s\n", f.Remediation)
	}
	fmt.Fprintf(b, "\nPolicy: %s\n", result.PolicyResult.Name)
	fmt.Fprintf(b, "Result: %s (passed=%d, failed=%d, warnings=%d)\n",
		result.PolicyResult.Result, result.PolicyResult.PassedChecks,
		result.PolicyResult.FailedChecks, result.PolicyResult.WarningChecks)

	_, err := io.WriteString(r.w, b.String())
	return err
}
