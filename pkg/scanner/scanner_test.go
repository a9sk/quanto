package scanner

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
)

func generateServerCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
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
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, cert
}

func startTestServer(t *testing.T) (string, func()) {
	t.Helper()
	cert, _ := generateServerCert(t)
	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
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

func TestAnalyzeEndpoint_TLS13(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	s := New(model.ScannerConfig{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: true,
	})

	result, err := s.AnalyzeEndpoint(context.Background(), addr)
	if err != nil {
		t.Fatalf("analyze endpoint: %v", err)
	}

	if result.TLS.Version != "TLSv1.3" {
		t.Errorf("expected TLSv1.3, got %s", result.TLS.Version)
	}
	if result.TLS.CipherSuite == "" {
		t.Error("expected negotiated cipher suite")
	}
	if result.TLS.KeyExchange.Name == "" {
		t.Error("expected key exchange to be probed")
	}
	if len(result.TLS.SupportedGroups) == 0 {
		t.Error("expected supported groups to be discovered")
	}
	if len(result.Certificates) == 0 {
		t.Error("expected certificates")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for ECDSA certificate")
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		target      string
	overrideSNI string
	wantHost    string
	wantPort    string
	wantSNI     string
	wantErr     bool
	}{
		{"example.com:443", "", "example.com", "443", "example.com", false},
		{"example.com", "", "example.com", "443", "example.com", false},
		{"https://example.com/path", "", "example.com", "443", "example.com", false},
		{"https://example.com:8443", "alt.com", "example.com", "8443", "alt.com", false},
	}

	for _, tc := range cases {
		host, port, sni, err := parseTarget(tc.target, tc.overrideSNI)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseTarget(%q) error = %v, wantErr %v", tc.target, err, tc.wantErr)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort || sni != tc.wantSNI {
			t.Errorf("parseTarget(%q) = %s,%s,%s, want %s,%s,%s",
				tc.target, host, port, sni, tc.wantHost, tc.wantPort, tc.wantSNI)
		}
	}
}

func TestTlsVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLSv1.0",
		tls.VersionTLS13: "TLSv1.3",
		0x9999:           "UnknownTLS_0x9999",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(0x%04x) = %s, want %s", v, got, want)
		}
	}
}
