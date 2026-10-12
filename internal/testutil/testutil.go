package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// GenerateRSAKeyCert generates an RSA key and self-signed certificate for tests.
func GenerateRSAKeyCert(t *testing.T, bits int) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateCert(t, key, &key.PublicKey, x509.SHA256WithRSA)
	return key, cert, certPEM(cert)
}

// GenerateECDSAKeyCert generates an ECDSA key and self-signed certificate for tests.
func GenerateECDSAKeyCert(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateCert(t, key, &key.PublicKey, x509.ECDSAWithSHA256)
	return key, cert, certPEM(cert)
}

func generateCert(t *testing.T, signer interface{}, pub interface{}, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// MustMarshalPrivateKeyPEM returns a PEM encoding of a private key.
func MustMarshalPrivateKeyPEM(t *testing.T, key interface{}) []byte {
	t.Helper()
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	default:
		t.Fatalf("unsupported key type %T", key)
		return nil
	}
}
