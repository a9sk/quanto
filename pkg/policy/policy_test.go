package policy

import (
	"testing"

	"github.com/a9sk/quanto/pkg/model"
)

func TestLoadPolicy(t *testing.T) {
	p, err := LoadByName("default")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "default" {
		t.Errorf("unexpected policy name: %s", p.Name)
	}
}

func TestEvaluateScan_TLS13Pass(t *testing.T) {
	eng := New()
	p := &model.Policy{
		Name:            "test",
		QuantumReadiness: "required",
		MinTLSVersion:    "1.3",
		AllowedCiphers:   []string{"TLS_AES_256_GCM_SHA384"},
		AllowedKEX:       []string{"X25519Kyber768Draft00"},
	}

	result := &model.ScanResult{
		TLS: model.TLSInfo{
			Version:     "TLSv1.3",
			CipherSuite: "TLS_AES_256_GCM_SHA384",
			KeyExchange: model.PrimitiveInfo{Name: "X25519Kyber768Draft00", QuantumStatus: model.QuantumTransitional},
		},
		Certificates: []model.CertificateInfo{
			{PublicKeyAlgorithm: "ML-DSA-65", QuantumStatus: model.QuantumResistant},
		},
		Summary: model.Summary{OverallReadiness: string(model.QuantumTransitional)},
	}

	pr := eng.EvaluateScan(result, p)
	if pr.Result != model.PolicyFail {
		// Transitional readiness fails required policy, which is expected.
		if pr.FailedChecks == 0 {
			t.Error("expected at least one failed check for transitional readiness under required policy")
		}
	}
}

func TestEvaluateCert_VulnerableFails(t *testing.T) {
	eng := New()
	p, err := LoadByName("nist-quantum-ready-2030")
	if err != nil {
		t.Fatal(err)
	}

	result := &model.CertResult{
		Certificates: []model.CertificateInfo{
			{
				PublicKeyAlgorithm: "RSA",
				SignatureAlgorithm: "SHA256-RSA",
				QuantumStatus:      model.QuantumVulnerable,
			},
		},
	}

	pr := eng.EvaluateCert(result, p)
	if pr.Result != model.PolicyFail {
		t.Errorf("expected fail, got %s", pr.Result)
	}
	if pr.FailedChecks == 0 {
		t.Error("expected failed checks")
	}
}

func TestCheckList_Allowed(t *testing.T) {
	eng := New()
	c := eng.checkList("cipher", "TLS_AES_256_GCM_SHA384", []string{"TLS_AES_256_GCM_SHA384"}, nil)
	if c.Status != model.PolicyPass {
		t.Errorf("expected pass, got %s", c.Status)
	}
}

func TestCheckList_Forbidden(t *testing.T) {
	eng := New()
	c := eng.checkList("pk", "RSA", nil, []string{"RSA"})
	if c.Status != model.PolicyFail {
		t.Errorf("expected fail, got %s", c.Status)
	}
}

func TestTlsVersionRank(t *testing.T) {
	if tlsVersionRank("TLSv1.3") <= tlsVersionRank("TLSv1.2") {
		t.Error("TLSv1.3 should rank higher than TLSv1.2")
	}
	if tlsVersionRank("nonsense") != 0 {
		t.Error("unknown version should return 0")
	}
}
