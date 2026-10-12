package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/a9sk/quanto/pkg/model"
	"github.com/a9sk/quanto/pkg/policy"
	"github.com/a9sk/quanto/pkg/scanner"
)

func generateTestCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, cert
}

func startLocalTLSServer(t *testing.T) (string, func()) {
	t.Helper()
	keyPair, _ := generateTestCert(t)

	config := &tls.Config{
		Certificates:       []tls.Certificate{keyPair},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		listener.Close()
		<-done
	}
}

func TestIntegration_EndToEnd(t *testing.T) {
	addr, cleanup := startLocalTLSServer(t)
	defer cleanup()

	s := scanner.New(model.ScannerConfig{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
	})

	result, err := s.AnalyzeEndpoint(context.Background(), addr)
	if err != nil {
		t.Fatalf("analyze endpoint: %v", err)
	}

	p, err := policy.LoadByName("transitional-2026")
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.New()
	result.PolicyResult = eng.EvaluateScan(result, p)

	if result.TLS.Version != "TLSv1.3" {
		t.Errorf("expected TLSv1.3, got %s", result.TLS.Version)
	}
	if len(result.Certificates) == 0 {
		t.Fatal("expected certificates")
	}
	if result.PolicyResult.Result == "" {
		t.Error("expected policy result")
	}
}
