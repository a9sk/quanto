package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/a9sk/quanto/pkg/cert"
	"github.com/a9sk/quanto/pkg/model"
	"github.com/a9sk/quanto/pkg/registry"
)

// Scanner performs endpoint analysis.
type Scanner struct {
	registry *registry.Registry
	config   model.ScannerConfig
}

// New creates a scanner with the provided configuration.
func New(config model.ScannerConfig) *Scanner {
	return &Scanner{
		registry: registry.New(),
		config:   config,
	}
}

// NewWithRegistry creates a scanner with a custom registry.
func NewWithRegistry(config model.ScannerConfig, r *registry.Registry) *Scanner {
	return &Scanner{
		registry: r,
		config:   config,
	}
}

// AnalyzeEndpoint scans a TLS endpoint and returns the analysis result.
func (s *Scanner) AnalyzeEndpoint(ctx context.Context, target string) (*model.ScanResult, error) {
	host, port, sni, err := parseTarget(target, s.config.SNI)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(host, port)
	result := &model.ScanResult{
		Target:   target,
		ScanTime: time.Now().UTC(),
		TLS:      model.TLSInfo{SNI: sni},
	}

	if s.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.config.Timeout)
		defer cancel()
	}

	dialer := &net.Dialer{}
	if s.config.StartTLS != "" {
		conn, err := s.dialStartTLS(ctx, dialer, addr, sni)
		if err != nil {
			return nil, fmt.Errorf("starttls %s: %w", s.config.StartTLS, err)
		}
		defer conn.Close()
		if err := s.handshake(ctx, conn, result); err != nil {
			return nil, err
		}
	} else {
		tlsConfig := s.tlsConfig(sni)
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("tls dial: %w", err)
		}
		defer conn.Close()
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		if err := s.populateResult(conn, result); err != nil {
			return nil, err
		}

		// For TLS 1.3, Go does not expose the negotiated group. Probe it.
		if result.TLS.Version == "TLSv1.3" {
			_ = s.probeKeyExchange(ctx, dialer, addr, sni, result)
		}
	}

	// Analyze certificates.
	ca := cert.NewWithRegistry(s.registry)
	certResult, err := ca.AnalyzeCertificate(result.RawCertificates, nil)
	if err != nil {
		return nil, fmt.Errorf("analyzing certificates: %w", err)
	}
	result.Certificates = certResult.Certificates
	result.Findings = append(result.Findings, certResult.Findings...)

	// Add TLS-specific findings.
	result.Findings = append(result.Findings, s.tlsFindings(result)...)

	// Populate summary.
	result.Summary = s.buildSummary(result)

	return result, nil
}

func (s *Scanner) tlsConfig(sni string) *tls.Config {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.config.InsecureSkipVerify,
		RootCAs:            s.config.RootCAs,
	}
	if s.config.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*s.config.ClientCert}
	}
	return cfg
}

func (s *Scanner) handshake(ctx context.Context, conn net.Conn, result *model.ScanResult) error {
	tlsConn := tls.Client(conn, s.tlsConfig(result.TLS.SNI))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	return s.populateResult(tlsConn, result)
}

func (s *Scanner) populateResult(conn *tls.Conn, result *model.ScanResult) error {
	state := conn.ConnectionState()
	result.TLS.Version = tlsVersionName(state.Version)
	result.TLS.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.TLS.ALPN = state.NegotiatedProtocol

	result.TLS.KeyExchange = s.inferKeyExchange(state.Version, result.TLS.CipherSuite)

	// Store raw certs for cert analyzer to pick up.
	result.RawCertificates = state.PeerCertificates
	return nil
}

type groupProbe struct {
	name string
	id   tls.CurveID
}

// tls13GroupProbes lists groups to test, ordered from most to least quantum-ready.
// Code points for PQ/hybrid groups are the current draft/experimental values.
// Go 1.22 does not implement these KEMs natively, so probes for them will typically
// fail; the classical groups are then tested as a fallback.
var tls13GroupProbes = []groupProbe{
	{"X25519Kyber768Draft00", 0x6399},
	{"SecP256r1MLKEM768", 0x11EB},
	{"X25519", tls.X25519},
	{"P-256", tls.CurveP256},
	{"P-384", tls.CurveP384},
	{"P-521", tls.CurveP521},
}

// probeKeyExchange performs active TLS 1.3 handshakes with a single group at a time
// to discover which groups the server accepts. The first accepted group is reported
// as the inferred negotiated key exchange, and all accepted groups are recorded in
// TLSInfo.SupportedGroups.
func (s *Scanner) probeKeyExchange(ctx context.Context, dialer *net.Dialer, addr, sni string, result *model.ScanResult) error {
	perProbeTimeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < perProbeTimeout {
			perProbeTimeout = remaining
		}
	}

	var supported []string
	var negotiated model.PrimitiveInfo

	for _, g := range tls13GroupProbes {
		if ctx.Err() != nil {
			break
		}

		probeCtx, cancel := context.WithTimeout(ctx, perProbeTimeout)

		cfg := s.tlsConfig(sni)
		cfg.MinVersion = tls.VersionTLS13
		cfg.MaxVersion = tls.VersionTLS13
		cfg.CipherSuites = nil
		cfg.CurvePreferences = []tls.CurveID{g.id}

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err != nil {
			cancel()
			continue
		}
		if err := conn.HandshakeContext(probeCtx); err != nil {
			conn.Close()
			cancel()
			continue
		}
		conn.Close()
		cancel()

		supported = append(supported, g.name)
		if negotiated.Name == "" {
			negotiated = s.registry.PrimitiveInfo(g.name)
		}
	}

	result.TLS.SupportedGroups = supported
	if negotiated.Name != "" {
		result.TLS.KeyExchange = negotiated
	}
	return nil
}

func (s *Scanner) tlsFindings(r *model.ScanResult) []model.Finding {
	findings := []model.Finding{}

	// TLS version.
	if r.TLS.Version != "" {
		if alg, ok := s.registry.LookupByName(r.TLS.Version); ok {
			switch alg.QuantumStatus {
			case model.QuantumVulnerable:
				findings = append(findings, model.Finding{
					Severity:    model.SeverityHigh,
					Category:    "tls-version",
					Description: fmt.Sprintf("Negotiated TLS version is %s", r.TLS.Version),
					QuantumRisk: "Older TLS versions rely on classical key exchange and do not support post-quantum KEMs",
					Remediation: "Enable TLS 1.3; it is required for practical post-quantum key exchange.",
				})
			case model.QuantumResistant:
				findings = append(findings, model.Finding{
					Severity:    model.SeverityInfo,
					Category:    "tls-version",
					Description: fmt.Sprintf("Negotiated TLS version is %s", r.TLS.Version),
					QuantumRisk: "TLS 1.3 supports modern key exchange mechanisms",
					Remediation: "Ensure the cipher suite and key exchange group are also quantum-resistant.",
				})
			}
		}
	}

	// Cipher suite.
	if r.TLS.CipherSuite != "" {
		if alg, ok := s.registry.LookupByName(r.TLS.CipherSuite); ok {
			switch alg.QuantumStatus {
			case model.QuantumReduced:
				findings = append(findings, model.Finding{
					Severity:    model.SeverityMedium,
					Category:    "cipher-suite",
					Description: fmt.Sprintf("Negotiated cipher suite is %s", r.TLS.CipherSuite),
					QuantumRisk: "Grover's algorithm halves the effective security of the symmetric component",
					Remediation: "Prefer TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256.",
				})
			case model.QuantumVulnerable:
				findings = append(findings, model.Finding{
					Severity:    model.SeverityHigh,
					Category:    "cipher-suite",
					Description: fmt.Sprintf("Negotiated cipher suite is %s", r.TLS.CipherSuite),
					QuantumRisk: "Cipher suite relies on broken or classically weak primitives",
					Remediation: "Disable weak ciphers and use TLS 1.3 AEAD cipher suites.",
				})
			}
		}
	}

	// Key exchange.
	if r.TLS.KeyExchange.Name != "" {
		switch r.TLS.KeyExchange.QuantumStatus {
		case model.QuantumVulnerable:
			findings = append(findings, model.Finding{
				Severity:    model.SeverityHigh,
				Category:    "key-exchange",
				Description: fmt.Sprintf("Key exchange uses %s", r.TLS.KeyExchange.Name),
				QuantumRisk: "Shor's algorithm breaks the underlying key agreement",
				Remediation: "Configure a post-quantum or hybrid KEM such as X25519Kyber768 or ML-KEM-768.",
			})
		case model.QuantumTransitional:
			findings = append(findings, model.Finding{
				Severity:    model.SeverityLow,
				Category:    "key-exchange",
				Description: fmt.Sprintf("Key exchange uses hybrid %s", r.TLS.KeyExchange.Name),
				QuantumRisk: "Hybrid schemes retain a classical component that will be deprecated",
				Remediation: "Plan migration to pure ML-KEM when ecosystem support permits.",
			})
		case model.QuantumResistant:
			findings = append(findings, model.Finding{
				Severity:    model.SeverityInfo,
				Category:    "key-exchange",
				Description: fmt.Sprintf("Key exchange uses %s", r.TLS.KeyExchange.Name),
				QuantumRisk: "Key exchange is considered post-quantum secure",
				Remediation: "None.",
			})
		case model.QuantumUnknown:
			findings = append(findings, model.Finding{
				Severity:    model.SeverityMedium,
				Category:    "key-exchange",
				Description: fmt.Sprintf("Key exchange could not be determined (%s)", r.TLS.KeyExchange.Name),
				QuantumRisk: "Unable to verify whether the negotiated key exchange is post-quantum",
				Remediation: "Inspect server configuration directly or use a TLS client that exposes the negotiated group.",
			})
		}
	}

	return findings
}

func (s *Scanner) buildSummary(r *model.ScanResult) model.Summary {
	summary := model.Summary{
		OverallReadiness:           string(model.QuantumResistant),
		VulnerablePrimitives:       []string{},
		ReducedMarginPrimitives:    []string{},
		QuantumResistantPrimitives: []string{},
	}

	add := func(name string, status model.QuantumStatus) {
		switch status {
		case model.QuantumVulnerable:
			summary.VulnerablePrimitives = append(summary.VulnerablePrimitives, name)
		case model.QuantumReduced:
			summary.ReducedMarginPrimitives = append(summary.ReducedMarginPrimitives, name)
		case model.QuantumResistant, model.QuantumTransitional:
			summary.QuantumResistantPrimitives = append(summary.QuantumResistantPrimitives, name)
		}
	}

	if r.TLS.Version != "" {
		if alg, ok := s.registry.LookupByName(r.TLS.Version); ok {
			add(r.TLS.Version, alg.QuantumStatus)
		}
	}
	if r.TLS.CipherSuite != "" {
		if alg, ok := s.registry.LookupByName(r.TLS.CipherSuite); ok {
			add(r.TLS.CipherSuite, alg.QuantumStatus)
		}
	}
	if r.TLS.KeyExchange.Name != "" {
		add(r.TLS.KeyExchange.Name, r.TLS.KeyExchange.QuantumStatus)
	}
	for _, cert := range r.Certificates {
		if cert.PublicKeyAlgorithm != "" {
			add(cert.PublicKeyAlgorithm, cert.QuantumStatus)
		}
	}

	// Overall readiness is the worst status observed.
	statuses := []model.QuantumStatus{}
	if len(summary.VulnerablePrimitives) > 0 {
		statuses = append(statuses, model.QuantumVulnerable)
	}
	if len(summary.ReducedMarginPrimitives) > 0 {
		statuses = append(statuses, model.QuantumReduced)
	}
	if len(summary.QuantumResistantPrimitives) > 0 {
		statuses = append(statuses, model.QuantumResistant)
	}
	if len(statuses) > 0 {
		summary.OverallReadiness = string(worstStatus(statuses))
	}

	return summary
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

func (s *Scanner) inferKeyExchange(tlsVersion uint16, cipherSuite string) model.PrimitiveInfo {
	if tlsVersion == tls.VersionTLS13 {
		// Go's crypto/tls does not expose the negotiated key exchange group in
		// ConnectionState for TLS 1.3. Report it as not directly observable.
		return model.PrimitiveInfo{
			Name:          "TLSv1.3 key exchange (group not exposed by Go crypto/tls)",
			Family:        "unknown",
			QuantumStatus: model.QuantumUnknown,
		}
	}

	// For TLS 1.2 and earlier, infer from the cipher suite name.
	upper := strings.ToUpper(cipherSuite)
	switch {
	case strings.Contains(upper, "ECDHE"):
		return s.registry.PrimitiveInfo("ECDH")
	case strings.Contains(upper, "DHE") || strings.Contains(upper, "DH_"):
		return s.registry.PrimitiveInfo("DH")
	case strings.Contains(upper, "RSA"):
		return s.registry.PrimitiveInfo("RSA")
	case strings.Contains(upper, "ECDH"):
		return s.registry.PrimitiveInfo("ECDH")
	}

	return model.PrimitiveInfo{
		Name:          "unknown",
		Family:        "unknown",
		QuantumStatus: model.QuantumUnknown,
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("UnknownTLS_0x%04X", version)
	}
}

func parseTarget(target, overrideSNI string) (host, port, sni string, err error) {
	// If target looks like a URL, parse it.
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", "", "", fmt.Errorf("parsing target URL: %w", err)
		}
		host = u.Hostname()
		port = u.Port()
		if port == "" {
			port = "443"
		}
		if overrideSNI != "" {
			sni = overrideSNI
		} else {
			sni = host
		}
		return host, port, sni, nil
	}

	// host:port form.
	host, port, err = net.SplitHostPort(target)
	if err != nil {
		// Try as host with default 443.
		host = target
		port = "443"
	}
	if overrideSNI != "" {
		sni = overrideSNI
	} else {
		sni = host
	}
	return host, port, sni, nil
}

func (s *Scanner) dialStartTLS(ctx context.Context, dialer *net.Dialer, addr, sni string) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(s.config.StartTLS) {
	case "smtp":
		if err := startTLSSMTP(conn); err != nil {
			conn.Close()
			return nil, err
		}
	case "imap":
		if err := startTLSIMAP(conn); err != nil {
			conn.Close()
			return nil, err
		}
	case "pop3":
		if err := startTLSPOP3(conn); err != nil {
			conn.Close()
			return nil, err
		}
	case "ftp":
		if err := startTLSFTP(conn); err != nil {
			conn.Close()
			return nil, err
		}
	case "xmpp":
		if err := startTLSXMPP(conn, sni); err != nil {
			conn.Close()
			return nil, err
		}
	case "ldap":
		if err := startTLSLDAP(conn); err != nil {
			conn.Close()
			return nil, err
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported STARTTLS protocol: %s", s.config.StartTLS)
	}

	return conn, nil
}

func startTLSSMTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "EHLO quanto\r\n"); err != nil {
		return err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if len(line) < 4 {
			continue
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "220 ") {
		return fmt.Errorf("SMTP STARTTLS rejected: %s", strings.TrimSpace(line))
	}
	return nil
}

func startTLSIMAP(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "A1 STARTTLS\r\n"); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "A1 OK") {
		return fmt.Errorf("IMAP STARTTLS rejected: %s", strings.TrimSpace(line))
	}
	return nil
}

func startTLSPOP3(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("POP3 STLS rejected: %s", strings.TrimSpace(line))
	}
	return nil
}

func startTLSFTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "234 ") {
		return fmt.Errorf("FTP AUTH TLS rejected: %s", strings.TrimSpace(line))
	}
	return nil
}

func startTLSXMPP(conn net.Conn, domain string) error {
	reader := bufio.NewReader(conn)
	fmt.Fprintf(conn, "<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>\r\n", domain)
	// Read until features.
	for {
		line, err := reader.ReadString('>')
		if err != nil {
			return err
		}
		if strings.Contains(line, "<starttls") {
			break
		}
	}
	if _, err := fmt.Fprintf(conn, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n"); err != nil {
		return err
	}
	line, err := reader.ReadString('>')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "proceed") {
		return fmt.Errorf("XMPP STARTTLS rejected")
	}
	return nil
}

func startTLSLDAP(conn net.Conn) error {
	// LDAPv3 ExtendedReq for StartTLS: OID 1.3.6.1.4.1.1466.20037
	req := buildLDAPStartTLSRequest()
	if _, err := conn.Write(req); err != nil {
		return err
	}
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}
	return nil
}

// Minimal BER-encoded LDAP StartTLS extended request.
func buildLDAPStartTLSRequest() []byte {
	oid := "1.3.6.1.4.1.1466.20037"
	// MessageID = 1
	msgID := []byte{0x02, 0x01, 0x01}
	// Extended request name (OID)
	oidBytes := []byte(oid)
	name := append([]byte{0x04, byte(len(oidBytes))}, oidBytes...)
	extReq := append([]byte{0x80 | 0x17, byte(len(name))}, name...)         // APPLICATION 23
	protocolOp := append([]byte{0x80 | 0x17, byte(len(extReq))}, extReq...) // ExtendedReq
	body := append(msgID, protocolOp...)
	return append([]byte{0x30, byte(len(body))}, body...)
}
