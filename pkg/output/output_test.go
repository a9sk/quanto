package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/a9sk/quanto/pkg/model"
)

func sampleScanResult() *model.ScanResult {
	return &model.ScanResult{
		Target:   "example.com:443",
		ScanTime: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		TLS: model.TLSInfo{
			Version:     "TLSv1.3",
			CipherSuite: "TLS_AES_256_GCM_SHA384",
			KeyExchange: model.PrimitiveInfo{Name: "X25519Kyber768Draft00", QuantumStatus: model.QuantumTransitional},
		},
		Certificates: []model.CertificateInfo{
			{
				Subject:            "CN=example.com",
				Issuer:             "CN=Test CA",
				SignatureAlgorithm: "ECDSA-SHA256",
				PublicKeyAlgorithm: "ECDSA",
				Curve:              "P-256",
				QuantumStatus:      model.QuantumVulnerable,
			},
		},
		Findings: []model.Finding{
			{
				Severity:    model.SeverityHigh,
				Category:    "public-key",
				Description: "Certificate uses ECDSA",
				QuantumRisk: "Shor's algorithm",
				Remediation: "Migrate to ML-DSA",
			},
		},
		PolicyResult: model.PolicyResult{Name: "default", Result: model.PolicyPass},
		Summary: model.Summary{
			OverallReadiness:     string(model.QuantumTransitional),
			VulnerablePrimitives: []string{"ECDSA P-256"},
		},
	}
}

func TestRenderScanJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	r, err := NewRenderer("json", buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RenderScan(sampleScanResult()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"target": "example.com:443"`) {
		t.Errorf("JSON output missing target: %s", buf.String())
	}
}

func TestRenderScanText(t *testing.T) {
	buf := &bytes.Buffer{}
	r, err := NewRenderer("text", buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RenderScan(sampleScanResult()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Target:") {
		t.Errorf("text output missing Target header: %s", out)
	}
	if !strings.Contains(out, "ECDSA") {
		t.Error("text output missing ECDSA mention")
	}
}

func TestRenderScanYAML(t *testing.T) {
	buf := &bytes.Buffer{}
	r, err := NewRenderer("yaml", buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RenderScan(sampleScanResult()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "target: example.com:443") {
		t.Errorf("YAML output missing target: %s", buf.String())
	}
}

func TestUnsupportedFormat(t *testing.T) {
	_, err := NewRenderer("xml", &bytes.Buffer{})
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}
