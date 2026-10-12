package registry

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/a9sk/quanto/pkg/model"
)

// Registry is a thread-safe catalog of cryptographic algorithms.
type Registry struct {
	mu          sync.RWMutex
	byName      map[string]model.Algorithm
	byOID       map[string]model.Algorithm
	byCodePoint map[uint16]model.Algorithm
}

// New creates a registry preloaded with built-in algorithm definitions.
func New() *Registry {
	r := &Registry{
		byName:      make(map[string]model.Algorithm),
		byOID:       make(map[string]model.Algorithm),
		byCodePoint: make(map[uint16]model.Algorithm),
	}
	r.loadDefaults()
	return r
}

// Register adds an algorithm to the registry.
func (r *Registry) Register(a model.Algorithm) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.byName[strings.ToLower(a.Name)] = a
	for _, alias := range a.Aliases {
		r.byName[strings.ToLower(alias)] = a
	}
	for _, oid := range a.OIDs {
		r.byOID[normalizeOID(oid)] = a
	}
	for _, cp := range a.CodePoints {
		r.byCodePoint[cp] = a
	}
}

// LookupByName returns an algorithm by name or alias.
func (r *Registry) LookupByName(name string) (model.Algorithm, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byName[strings.ToLower(name)]
	return a, ok
}

// LookupByOID returns an algorithm by dotted OID string.
func (r *Registry) LookupByOID(oid string) (model.Algorithm, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byOID[normalizeOID(oid)]
	return a, ok
}

// LookupByCodePoint returns an algorithm by TLS code point.
func (r *Registry) LookupByCodePoint(cp uint16) (model.Algorithm, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byCodePoint[cp]
	return a, ok
}

// LookupCipherSuite resolves a TLS cipher suite ID to an Algorithm.
func (r *Registry) LookupCipherSuite(id uint16) (model.Algorithm, bool) {
	return r.LookupByCodePoint(id)
}

// LookupSignatureScheme resolves a TLS 1.3 signature scheme.
func (r *Registry) LookupSignatureScheme(scheme tls.SignatureScheme) (model.Algorithm, bool) {
	return r.LookupByCodePoint(uint16(scheme))
}

// LookupGroup resolves a TLS named group.
func (r *Registry) LookupGroup(group tls.CurveID) (model.Algorithm, bool) {
	return r.LookupByCodePoint(uint16(group))
}

// PrimitiveInfo returns a reduced view of an algorithm.
func (r *Registry) PrimitiveInfo(name string) model.PrimitiveInfo {
	a, ok := r.LookupByName(name)
	if !ok {
		return model.PrimitiveInfo{Name: name, Family: "unknown", QuantumStatus: model.QuantumUnknown}
	}
	return model.PrimitiveInfo{
		Name:          a.Name,
		Family:        a.Family,
		QuantumStatus: a.QuantumStatus,
	}
}

// All returns all registered algorithms.
func (r *Registry) All() []model.Algorithm {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Algorithm, 0, len(r.byName))
	seen := make(map[string]struct{})
	for _, a := range r.byName {
		if _, ok := seen[a.Name]; ok {
			continue
		}
		seen[a.Name] = struct{}{}
		out = append(out, a)
	}
	return out
}

func normalizeOID(oid string) string {
	return strings.TrimSpace(strings.ToLower(oid))
}

func codePoints(nums ...uint16) []uint16 { return nums }

func oids(oids ...string) []string { return oids }

func aliases(names ...string) []string { return names }

// Default global registry instance.
var defaultRegistry = New()

// LookupByName uses the default registry.
func LookupByName(name string) (model.Algorithm, bool) { return defaultRegistry.LookupByName(name) }

// LookupByOID uses the default registry.
func LookupByOID(oid string) (model.Algorithm, bool) { return defaultRegistry.LookupByOID(oid) }

// LookupByCodePoint uses the default registry.
func LookupByCodePoint(cp uint16) (model.Algorithm, bool) {
	return defaultRegistry.LookupByCodePoint(cp)
}

// PrimitiveInfo uses the default registry.
func PrimitiveInfo(name string) model.PrimitiveInfo { return defaultRegistry.PrimitiveInfo(name) }

func mustParseCipherName(id uint16) string {
	s := tls.CipherSuiteName(id)
	if s == fmt.Sprintf("0x%04X", id) {
		return fmt.Sprintf("UnknownCipherSuite_0x%04X", id)
	}
	return s
}

func mustParseSignatureSchemeName(id uint16) string {
	name := tls.SignatureScheme(id).String()
	if name == fmt.Sprintf("0x%04x", id) {
		return fmt.Sprintf("UnknownSignatureScheme_0x%04x", id)
	}
	return name
}

func mustParseCurveName(id uint16) string {
	name := tls.CurveID(id).String()
	if name == fmt.Sprintf("CurveID(%d)", id) {
		return fmt.Sprintf("UnknownGroup_0x%04x", id)
	}
	return name
}
