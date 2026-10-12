package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/a9sk/quanto/pkg/cert"
	"github.com/a9sk/quanto/pkg/model"
	"github.com/a9sk/quanto/pkg/output"
	"github.com/a9sk/quanto/pkg/policy"
	"github.com/a9sk/quanto/pkg/scanner"
)

var (
	version   = "dev"
	gitCommit = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		if err := scanCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "cert":
		if err := certCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "policy":
		if err := policyCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		versionCmd()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Quanto, Quantum-readiness TLS/SSL analyzer

Usage:
  quanto <command> [flags]

Commands:
  scan <target>      Scan a TLS endpoint
  cert <file>        Analyze a certificate, chain, or key file
  policy <subcmd>    Manage policies (list, show)
  version            Show version and supported algorithms

Global flags:
  -o, --output text|json|yaml   Output format (default: text)
  -p, --policy <file|name>      Policy to apply (default: default)
  -t, --timeout <duration>      Connection timeout (default: 10s)
  -v, --verbose                 Include supported algorithms and extensions
  --insecure                    Skip certificate validation
  --sni <name>                  Override SNI
  --starttls <protocol>         Use STARTTLS (smtp, imap, pop3, ftp, xmpp, ldap)
  --client-cert <file>          Client certificate (PEM)
  --client-key <file>           Client private key (PEM)
  --ca-file <file>              Custom CA bundle`)
}

type globalFlags struct {
	output     string
	policyName string
	timeout    time.Duration
	verbose    bool
	insecure   bool
	sni        string
	startTLS   string
	clientCert string
	clientKey  string
	caFile     string
}

func parseGlobalFlags(args []string) (*globalFlags, []string, error) {
	// allow flags to appear before or after positional arguments.
	flags, positional := reorderArgs(args)

	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	g := &globalFlags{}
	fs.StringVar(&g.output, "o", "text", "Output format: text|json|yaml")
	fs.StringVar(&g.output, "output", "text", "Output format: text|json|yaml")
	fs.StringVar(&g.policyName, "p", "default", "Policy name or file")
	fs.StringVar(&g.policyName, "policy", "default", "Policy name or file")
	fs.DurationVar(&g.timeout, "t", 10*time.Second, "Connection timeout")
	fs.DurationVar(&g.timeout, "timeout", 10*time.Second, "Connection timeout")
	fs.BoolVar(&g.verbose, "v", false, "Verbose output")
	fs.BoolVar(&g.verbose, "verbose", false, "Verbose output")
	fs.BoolVar(&g.insecure, "insecure", false, "Skip certificate validation")
	fs.StringVar(&g.sni, "sni", "", "Override SNI")
	fs.StringVar(&g.startTLS, "starttls", "", "STARTTLS protocol")
	fs.StringVar(&g.clientCert, "client-cert", "", "Client certificate file")
	fs.StringVar(&g.clientKey, "client-key", "", "Client private key file")
	fs.StringVar(&g.caFile, "ca-file", "", "Custom CA bundle")
	if err := fs.Parse(flags); err != nil {
		return nil, nil, err
	}
	return g, append(fs.Args(), positional...), nil
}

// reorderArgs extracts flags and their values from args and returns them first,
// followed by positional arguments. This lets users write either
//
//	quanto scan --insecure example.com
//
// or
//
//	quanto scan example.com --insecure
func reorderArgs(args []string) (flags []string, positional []string) {
	boolFlags := map[string]bool{
		"-v": true, "--verbose": true,
		"--insecure": true,
	}
	valueFlags := map[string]bool{
		"-o": true, "--output": true,
		"-p": true, "--policy": true,
		"-t": true, "--timeout": true,
		"--sni":         true,
		"--starttls":    true,
		"--client-cert": true,
		"--client-key":  true,
		"--ca-file":     true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				flags = append(flags, arg)
				continue
			}
			if boolFlags[arg] {
				flags = append(flags, arg)
				continue
			}
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, arg, args[i+1])
				i++
				continue
			}
			// unknown flag: keep with flags and let flag package report it.
			flags = append(flags, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	return flags, positional
}

func loadPolicy(name string) (*model.Policy, error) {
	if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".json") {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("reading policy file: %w", err)
		}
		return policy.Load(data)
	}
	return policy.LoadByName(name)
}

func loadClientCert(certFile, keyFile string) (*tls.Certificate, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("both --client-cert and --client-key are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client cert: %w", err)
	}
	return &cert, nil
}

func loadRootCAs(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA certificates")
	}
	return pool, nil
}

func scanCmd(args []string) error {
	g, remaining, err := parseGlobalFlags(args)
	if err != nil {
		return err
	}
	if len(remaining) != 1 {
		return fmt.Errorf("usage: quanto scan <target>")
	}
	target := remaining[0]

	clientCert, err := loadClientCert(g.clientCert, g.clientKey)
	if err != nil {
		return err
	}
	rootCAs, err := loadRootCAs(g.caFile)
	if err != nil {
		return err
	}

	cfg := model.ScannerConfig{
		Timeout:            g.timeout,
		InsecureSkipVerify: g.insecure,
		SNI:                g.sni,
		StartTLS:           g.startTLS,
		ClientCert:         clientCert,
		RootCAs:            rootCAs,
	}

	s := scanner.New(cfg)
	ctx := context.Background()
	result, err := s.AnalyzeEndpoint(ctx, target)
	if err != nil {
		return err
	}

	p, err := loadPolicy(g.policyName)
	if err != nil {
		return err
	}
	eng := policy.New()
	result.PolicyResult = eng.EvaluateScan(result, p)

	renderer, err := output.NewRenderer(g.output, os.Stdout)
	if err != nil {
		return err
	}
	return renderer.RenderScan(result)
}

func certCmd(args []string) error {
	g, remaining, err := parseGlobalFlags(args)
	if err != nil {
		return err
	}
	if len(remaining) != 1 {
		return fmt.Errorf("usage: quanto cert <file>")
	}
	path := remaining[0]

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	ca := cert.New()
	result, err := ca.AnalyzePEM(data, "")
	if err != nil {
		return fmt.Errorf("analyzing PEM: %w", err)
	}

	p, err := loadPolicy(g.policyName)
	if err != nil {
		return err
	}
	eng := policy.New()
	certResult := &model.CertResult{
		Certificates: result.Certificates,
		Findings:     result.Findings,
	}
	if len(result.Keys) > 0 {
		certResult.KeyInfo = &result.Keys[0]
	}
	certResult.PolicyResult = eng.EvaluateCert(certResult, p)

	renderer, err := output.NewRenderer(g.output, os.Stdout)
	if err != nil {
		return err
	}
	return renderer.RenderCert(certResult)
}

func policyCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: quanto policy <list|show>")
	}
	switch args[0] {
	case "list":
		names, err := policy.ListBuiltIn()
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: quanto policy show <name>")
		}
		p, err := policy.LoadByName(args[1])
		if err != nil {
			return err
		}
		data, err := policy.ToYAML(p)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	default:
		return fmt.Errorf("unknown policy subcommand: %s", args[0])
	}
}

func versionCmd() {
	fmt.Printf("Quanto version %s (commit %s)\n", version, gitCommit)
	fmt.Println("Supported algorithms: see docs/quantum-risk-model.md")
}
