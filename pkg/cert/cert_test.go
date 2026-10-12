package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/a9sk/quanto/pkg/model"
)

func generateTestCert(t *testing.T, signer interface{}, pub interface{}, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

func TestAnalyzeCertificate_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateTestCert(t, key, &key.PublicKey, x509.SHA256WithRSA)

	a := New()
	result, err := a.AnalyzeCertificate([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(result.Certificates))
	}
	info := result.Certificates[0]
	if info.PublicKeyAlgorithm != "RSA" || info.PublicKeySize != 2048 {
		t.Errorf("unexpected public key: %s %d", info.PublicKeyAlgorithm, info.PublicKeySize)
	}
	if info.QuantumStatus != model.QuantumVulnerable {
		t.Errorf("expected vulnerable, got %s", info.QuantumStatus)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected findings for RSA certificate")
	}
}

func TestAnalyzeCertificate_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateTestCert(t, key, &key.PublicKey, x509.ECDSAWithSHA256)

	a := New()
	result, err := a.AnalyzeCertificate([]*x509.Certificate{cert}, nil)
	if err != nil {
		t.Fatal(err)
	}

	info := result.Certificates[0]
	if info.Curve != "P-256" {
		t.Errorf("expected P-256, got %s", info.Curve)
	}
	if info.QuantumStatus != model.QuantumVulnerable {
		t.Errorf("expected vulnerable, got %s", info.QuantumStatus)
	}
}

func TestAnalyzeCertificate_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateTestCert(t, priv, priv.Public(), x509.PureEd25519)

	a := New()
	result, err := a.AnalyzeCertificate([]*x509.Certificate{cert}, priv)
	if err != nil {
		t.Fatal(err)
	}

	if result.Certificates[0].PublicKeyAlgorithm != "Ed25519" {
		t.Errorf("unexpected algorithm: %s", result.Certificates[0].PublicKeyAlgorithm)
	}
	if result.KeyInfo == nil || result.KeyInfo.Algorithm != "Ed25519" {
		t.Error("expected Ed25519 key info")
	}
}

func TestAnalyzePEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateTestCert(t, key, &key.PublicKey, x509.SHA256WithRSA)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	a := New()
	result, err := a.AnalyzePEM(append(certPEM, keyPEM...), "")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Certificates) != 1 || len(result.Keys) != 1 {
		t.Fatalf("expected 1 cert and 1 key, got %d certs and %d keys", len(result.Certificates), len(result.Keys))
	}
}

func TestWorstStatus(t *testing.T) {
	cases := []struct {
		input    []model.QuantumStatus
		expected model.QuantumStatus
	}{
		{[]model.QuantumStatus{model.QuantumResistant, model.QuantumVulnerable}, model.QuantumVulnerable},
		{[]model.QuantumStatus{model.QuantumReduced, model.QuantumResistant}, model.QuantumReduced},
		{[]model.QuantumStatus{}, model.QuantumUnknown},
	}
	for _, tc := range cases {
		got := worstStatus(tc.input)
		if got != tc.expected {
			t.Errorf("worstStatus(%v) = %s, want %s", tc.input, got, tc.expected)
		}
	}
}
