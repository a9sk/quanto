package registry

import (
	"testing"

	"github.com/a9sk/quanto/pkg/model"
)

func TestLookupByName(t *testing.T) {
	r := New()

	cases := []struct {
		name   string
		status model.QuantumStatus
	}{
		{"RSA", model.QuantumVulnerable},
		{"rsa", model.QuantumVulnerable},
		{"ECDSA", model.QuantumVulnerable},
		{"ML-KEM-768", model.QuantumResistant},
		{"ML-DSA-65", model.QuantumResistant},
		{"AES-256-GCM", model.QuantumResistant},
		{"AES-128-GCM", model.QuantumReduced},
		{"TLS_AES_256_GCM_SHA384", model.QuantumResistant},
		{"TLSv1.3", model.QuantumResistant},
	}

	for _, tc := range cases {
		alg, ok := r.LookupByName(tc.name)
		if !ok {
			t.Errorf("expected to find %s", tc.name)
			continue
		}
		if alg.QuantumStatus != tc.status {
			t.Errorf("%s: expected status %s, got %s", tc.name, tc.status, alg.QuantumStatus)
		}
	}
}

func TestLookupByCodePoint(t *testing.T) {
	r := New()

	alg, ok := r.LookupByCodePoint(0x1302) // TLS_AES_256_GCM_SHA384
	if !ok {
		t.Fatal("expected to find TLS_AES_256_GCM_SHA384 by code point")
	}
	if alg.Name != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("unexpected algorithm: %s", alg.Name)
	}
}

func TestRegisterCustom(t *testing.T) {
	r := New()
	r.Register(model.Algorithm{
		Name:          "Custom-PQ",
		Family:        "custom",
		Type:          "kex",
		QuantumStatus: model.QuantumResistant,
		Aliases:       []string{"custom"},
	})

	alg, ok := r.LookupByName("custom")
	if !ok || alg.Name != "Custom-PQ" {
		t.Error("expected to find custom algorithm by alias")
	}
}
