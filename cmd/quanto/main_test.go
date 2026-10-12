package main

import (
	"strings"
	"testing"
)

func TestParseGlobalFlags(t *testing.T) {
	g, remaining, err := parseGlobalFlags([]string{"-o", "json", "--policy", "nist-quantum-ready-2030", "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	if g.output != "json" {
		t.Errorf("output: expected json, got %s", g.output)
	}
	if g.policyName != "nist-quantum-ready-2030" {
		t.Errorf("policy: expected nist-quantum-ready-2030, got %s", g.policyName)
	}
	if len(remaining) != 1 || remaining[0] != "example.com:443" {
		t.Errorf("remaining args unexpected: %v", remaining)
	}
}

func TestLoadPolicy_BuiltIn(t *testing.T) {
	p, err := loadPolicy("default")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "default" {
		t.Errorf("unexpected policy: %s", p.Name)
	}
}

func TestLoadPolicy_File(t *testing.T) {
	p, err := loadPolicy("../../pkg/policy/policies/transitional-2026.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Name, "transitional") {
		t.Errorf("unexpected policy: %s", p.Name)
	}
}
