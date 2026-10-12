package policy

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/a9sk/quanto/pkg/model"
	"github.com/a9sk/quanto/pkg/registry"
	"gopkg.in/yaml.v3"
)

//go:embed policies/*.yaml
var policiesFS embed.FS

// Engine evaluates policies.
type Engine struct {
	registry *registry.Registry
}

// New creates a policy engine with the default registry.
func New() *Engine {
	return &Engine{registry: registry.New()}
}

// NewWithRegistry creates a policy engine with a custom registry.
func NewWithRegistry(r *registry.Registry) *Engine {
	return &Engine{registry: r}
}

// Load loads a policy from YAML or JSON bytes.
func Load(data []byte) (*model.Policy, error) {
	var p model.Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshaling policy: %w", err)
	}
	return &p, nil
}

// LoadFile loads a policy from a file path.
func LoadFile(path string) (*model.Policy, error) {
	data, err := policiesFS.ReadFile(filepath.ToSlash(path))
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Load(data)
}

// LoadByName loads a built-in policy by name.
func LoadByName(name string) (*model.Policy, error) {
	return LoadFile(fmt.Sprintf("policies/%s.yaml", name))
}

// EvaluateScan evaluates a scan result against a policy.
func (e *Engine) EvaluateScan(result *model.ScanResult, policy *model.Policy) model.PolicyResult {
	checks := []model.Check{}

	// TLS version check.
	if policy.MinTLSVersion != "" {
		checks = append(checks, e.checkTLSVersion(result.TLS.Version, policy.MinTLSVersion))
	}

	// Cipher suite check.
	if result.TLS.CipherSuite != "" {
		checks = append(checks, e.checkList("cipher-suite", result.TLS.CipherSuite,
			policy.AllowedCiphers, policy.ForbiddenCiphers))
	}

	// Key exchange check.
	if result.TLS.KeyExchange.Name != "" {
		checks = append(checks, e.checkList("key-exchange", result.TLS.KeyExchange.Name,
			policy.AllowedKEX, policy.ForbiddenKEX))
	}

	// Certificate checks.
	for _, cert := range result.Certificates {
		checks = append(checks, e.checkList("certificate-signature", cert.SignatureAlgorithm,
			policy.AllowedSigs, policy.ForbiddenSigs))
		checks = append(checks, e.checkList("public-key-algorithm", cert.PublicKeyAlgorithm,
			policy.AllowedPK, policy.ForbiddenPK))
	}

	// Quantum readiness level.
	checks = append(checks, e.checkQuantumReadiness(result, policy.QuantumReadiness))

	return aggregateResult(policy.Name, checks)
}

// EvaluateCert evaluates a certificate result against a policy.
func (e *Engine) EvaluateCert(result *model.CertResult, policy *model.Policy) model.PolicyResult {
	checks := []model.Check{}

	for _, cert := range result.Certificates {
		checks = append(checks, e.checkList("certificate-signature", cert.SignatureAlgorithm,
			policy.AllowedSigs, policy.ForbiddenSigs))
		checks = append(checks, e.checkList("public-key-algorithm", cert.PublicKeyAlgorithm,
			policy.AllowedPK, policy.ForbiddenPK))
	}

	if result.KeyInfo != nil {
		checks = append(checks, e.checkList("private-key-algorithm", result.KeyInfo.Algorithm,
			policy.AllowedPK, policy.ForbiddenPK))
	}

	checks = append(checks, e.checkQuantumReadinessCert(result, policy.QuantumReadiness))

	return aggregateResult(policy.Name, checks)
}

func (e *Engine) checkTLSVersion(observed, required string) model.Check {
	obs := tlsVersionRank(observed)
	req := tlsVersionRank(required)
	if obs == 0 || req == 0 {
		return model.Check{
			Name:     "tls-version",
			Status:   model.PolicyWarning,
			Message:  fmt.Sprintf("Unable to compare TLS version %s against required %s", observed, required),
			Severity: model.SeverityLow,
		}
	}
	if obs >= req {
		return model.Check{
			Name:     "tls-version",
			Status:   model.PolicyPass,
			Message:  fmt.Sprintf("TLS version %s meets minimum %s", observed, required),
			Severity: model.SeverityInfo,
		}
	}
	return model.Check{
		Name:     "tls-version",
		Status:   model.PolicyFail,
		Message:  fmt.Sprintf("TLS version %s is below required minimum %s", observed, required),
		Severity: model.SeverityHigh,
	}
}

func (e *Engine) checkList(category, value string, allowed, forbidden []string) model.Check {
	lowerVal := strings.ToLower(value)

	if len(forbidden) > 0 {
		for _, f := range forbidden {
			if matchesPattern(lowerVal, strings.ToLower(f)) {
				return model.Check{
					Name:     category,
					Status:   model.PolicyFail,
					Message:  fmt.Sprintf("%s uses forbidden algorithm %s", category, value),
					Severity: model.SeverityHigh,
				}
			}
		}
	}

	if len(allowed) > 0 {
		for _, a := range allowed {
			if matchesPattern(lowerVal, strings.ToLower(a)) {
				return model.Check{
					Name:     category,
					Status:   model.PolicyPass,
					Message:  fmt.Sprintf("%s algorithm %s is allowed", category, value),
					Severity: model.SeverityInfo,
				}
			}
		}
		return model.Check{
			Name:     category,
			Status:   model.PolicyFail,
			Message:  fmt.Sprintf("%s algorithm %s is not in the allow list", category, value),
			Severity: model.SeverityHigh,
		}
	}

	return model.Check{
		Name:     category,
		Status:   model.PolicyPass,
		Message:  fmt.Sprintf("%s algorithm %s passes policy (no restrictions)", category, value),
		Severity: model.SeverityInfo,
	}
}

func (e *Engine) checkQuantumReadiness(result *model.ScanResult, level string) model.Check {
	switch strings.ToLower(level) {
	case "required":
		if result.Summary.OverallReadiness == string(model.QuantumResistant) {
			return model.Check{
				Name:     "quantum-readiness",
				Status:   model.PolicyPass,
				Message:  "Overall readiness is quantum-resistant",
				Severity: model.SeverityInfo,
			}
		}
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyFail,
			Message:  fmt.Sprintf("Overall readiness is %s, quantum-resistant required", result.Summary.OverallReadiness),
			Severity: model.SeverityHigh,
		}
	case "transitional":
		if result.Summary.OverallReadiness == string(model.QuantumResistant) ||
			result.Summary.OverallReadiness == string(model.QuantumTransitional) {
			return model.Check{
				Name:     "quantum-readiness",
				Status:   model.PolicyPass,
				Message:  fmt.Sprintf("Overall readiness %s meets transitional policy", result.Summary.OverallReadiness),
				Severity: model.SeverityInfo,
			}
		}
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyFail,
			Message:  fmt.Sprintf("Overall readiness %s does not meet transitional policy", result.Summary.OverallReadiness),
			Severity: model.SeverityHigh,
		}
	case "none", "":
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyPass,
			Message:  "Quantum readiness checks disabled",
			Severity: model.SeverityInfo,
		}
	default:
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyWarning,
			Message:  fmt.Sprintf("Unknown quantum_readiness level: %s", level),
			Severity: model.SeverityLow,
		}
	}
}

func (e *Engine) checkQuantumReadinessCert(result *model.CertResult, level string) model.Check {
	worst := model.QuantumResistant
	for _, c := range result.Certificates {
		if c.QuantumStatus == model.QuantumVulnerable {
			worst = model.QuantumVulnerable
			break
		}
		if c.QuantumStatus == model.QuantumReduced && worst != model.QuantumVulnerable {
			worst = model.QuantumReduced
		}
	}

	switch strings.ToLower(level) {
	case "required":
		if worst == model.QuantumResistant {
			return model.Check{
				Name:     "quantum-readiness",
				Status:   model.PolicyPass,
				Message:  "Certificate material is quantum-resistant",
				Severity: model.SeverityInfo,
			}
		}
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyFail,
			Message:  fmt.Sprintf("Certificate material is %s, quantum-resistant required", worst),
			Severity: model.SeverityHigh,
		}
	case "transitional":
		if worst == model.QuantumResistant || worst == model.QuantumReduced {
			return model.Check{
				Name:     "quantum-readiness",
				Status:   model.PolicyPass,
				Message:  fmt.Sprintf("Certificate material %s meets transitional policy", worst),
				Severity: model.SeverityInfo,
			}
		}
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyFail,
			Message:  "Certificate material is vulnerable, transitional policy not met",
			Severity: model.SeverityHigh,
		}
	default:
		return model.Check{
			Name:     "quantum-readiness",
			Status:   model.PolicyPass,
			Message:  "Quantum readiness checks disabled",
			Severity: model.SeverityInfo,
		}
	}
}

func aggregateResult(name string, checks []model.Check) model.PolicyResult {
	result := model.PolicyResult{Name: name, Result: model.PolicyPass}
	for _, c := range checks {
		switch c.Status {
		case model.PolicyPass:
			result.PassedChecks++
		case model.PolicyFail:
			result.FailedChecks++
			result.Result = model.PolicyFail
		case model.PolicyWarning:
			result.WarningChecks++
			if result.Result == model.PolicyPass {
				result.Result = model.PolicyWarning
			}
		}
	}
	result.Checks = checks
	return result
}

func matchesPattern(value, pattern string) bool {
	if pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(value, strings.TrimSuffix(pattern, "*")) {
		return true
	}
	return false
}

func tlsVersionRank(version string) int {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "sslv3":
		return 1
	case "tlsv1.0", "tls1.0", "1.0":
		return 2
	case "tlsv1.1", "tls1.1", "1.1":
		return 3
	case "tlsv1.2", "tls1.2", "1.2":
		return 4
	case "tlsv1.3", "tls1.3", "1.3":
		return 5
	default:
		return 0
	}
}

// ListBuiltIn returns the names of built-in policies.
func ListBuiltIn() ([]string, error) {
	entries, err := policiesFS.ReadDir("policies")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return names, nil
}

// ToYAML serializes a policy to YAML.
func ToYAML(p *model.Policy) ([]byte, error) {
	return yaml.Marshal(p)
}

// ToJSON serializes a policy to JSON.
func ToJSON(p *model.Policy) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// JSON helpers for future use.
func toJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
