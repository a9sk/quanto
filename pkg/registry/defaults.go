package registry

import (
	"crypto/tls"

	"github.com/a9sk/quanto/pkg/model"
)

func (r *Registry) loadDefaults() {
	// Asymmetric key exchange
	r.Register(model.Algorithm{
		Name: "RSA", Family: "RSA", Type: "kex",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC8017",
		Aliases:       aliases("rsaEncryption"),
	})
	r.Register(model.Algorithm{
		Name: "DH", Family: "DH", Type: "kex",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC2631",
		Aliases:       aliases("Diffie-Hellman", "finite-field-dh", "DHE"),
	})
	r.Register(model.Algorithm{
		Name: "ECDH", Family: "ECDH", Type: "kex",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC4492",
		Aliases:       aliases("ECDHE"),
	})
	r.Register(model.Algorithm{
		Name: "X25519", Family: "ECDH", Type: "kex",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC7748",
		Aliases:       aliases("x25519"),
	})
	r.Register(model.Algorithm{
		Name: "X448", Family: "ECDH", Type: "kex",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC7748",
	})
	r.Register(model.Algorithm{
		Name: "ML-KEM-512", Family: "ML-KEM", Type: "kex",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 203",
		Aliases:       aliases("Kyber512"),
	})
	r.Register(model.Algorithm{
		Name: "ML-KEM-768", Family: "ML-KEM", Type: "kex",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 203",
		Aliases:       aliases("Kyber768"),
	})
	r.Register(model.Algorithm{
		Name: "ML-KEM-1024", Family: "ML-KEM", Type: "kex",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 203",
		Aliases:       aliases("Kyber1024"),
	})
	r.Register(model.Algorithm{
		Name: "X25519Kyber768Draft00", Family: "hybrid", Type: "kex",
		QuantumStatus: model.QuantumTransitional,
		Reference:     "draft-tls-westerbaan-xyber768d00-03",
		CodePoints:    codePoints(0x6399),
		Aliases:       aliases("X25519Kyber768"),
	})
	r.Register(model.Algorithm{
		Name: "SecP256r1MLKEM768", Family: "hybrid", Type: "kex",
		QuantumStatus: model.QuantumTransitional,
		Reference:     "draft-irtf-cfrg-hybrid-kex",
		CodePoints:    codePoints(0x11EB),
		Aliases:       aliases("P256Kyber768"),
	})

	// Signature algorithms
	r.Register(model.Algorithm{
		Name: "RSA-PKCS1", Family: "RSA", Type: "signature",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC8017",
		Aliases:       aliases("rsa-pkcs1"),
	})
	r.Register(model.Algorithm{
		Name: "RSA-PSS", Family: "RSA", Type: "signature",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC8017",
	})
	r.Register(model.Algorithm{
		Name: "DSA", Family: "DSA", Type: "signature",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "FIPS 186-4",
	})
	r.Register(model.Algorithm{
		Name: "ECDSA", Family: "ECDSA", Type: "signature",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "FIPS 186-5",
	})
	r.Register(model.Algorithm{
		Name: "Ed25519", Family: "EdDSA", Type: "signature",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC8032",
	})
	r.Register(model.Algorithm{
		Name: "Ed448", Family: "EdDSA", Type: "signature",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC8032",
	})
	r.Register(model.Algorithm{
		Name: "ML-DSA-44", Family: "ML-DSA", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 204",
		Aliases:       aliases("Dilithium2"),
	})
	r.Register(model.Algorithm{
		Name: "ML-DSA-65", Family: "ML-DSA", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 204",
		Aliases:       aliases("Dilithium3"),
	})
	r.Register(model.Algorithm{
		Name: "ML-DSA-87", Family: "ML-DSA", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 204",
		Aliases:       aliases("Dilithium5"),
	})
	r.Register(model.Algorithm{
		Name: "SLH-DSA-SHA2-128S", Family: "SLH-DSA", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 205",
	})
	r.Register(model.Algorithm{
		Name: "SLH-DSA-SHAKE-128S", Family: "SLH-DSA", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST FIPS 205",
	})
	r.Register(model.Algorithm{
		Name: "Falcon-512", Family: "Falcon", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST PQC alternate",
	})
	r.Register(model.Algorithm{
		Name: "Falcon-1024", Family: "Falcon", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST PQC alternate",
	})
	r.Register(model.Algorithm{
		Name: "XMSS", Family: "XMSS", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC8391",
	})
	r.Register(model.Algorithm{
		Name: "LMS", Family: "LMS", Type: "signature",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC8554",
	})

	// Elliptic curves (used by ECDSA/ECDH)
	r.Register(model.Algorithm{
		Name: "P-256", Family: "EC", Type: "group",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "FIPS 186-5",
		Aliases:       aliases("secp256r1", "prime256v1"),
		CodePoints:    codePoints(uint16(tls.CurveP256)),
	})
	r.Register(model.Algorithm{
		Name: "P-384", Family: "EC", Type: "group",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "FIPS 186-5",
		Aliases:       aliases("secp384r1"),
		CodePoints:    codePoints(uint16(tls.CurveP384)),
	})
	r.Register(model.Algorithm{
		Name: "P-521", Family: "EC", Type: "group",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "FIPS 186-5",
		Aliases:       aliases("secp521r1"),
		CodePoints:    codePoints(uint16(tls.CurveP521)),
	})
	r.Register(model.Algorithm{
		Name: "X25519", Family: "EC", Type: "group",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC7748",
		CodePoints:    codePoints(uint16(tls.X25519)),
	})
	r.Register(model.Algorithm{
		Name: "X448", Family: "EC", Type: "group",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC7748",
		CodePoints:    codePoints(0x1e),
	})

	// Hashes
	r.Register(model.Algorithm{
		Name: "MD5", Family: "MD", Type: "hash",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC1321",
	})
	r.Register(model.Algorithm{
		Name: "SHA-1", Family: "SHA", Type: "hash",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "FIPS 180-4",
	})
	r.Register(model.Algorithm{
		Name: "SHA-256", Family: "SHA", Type: "hash",
		QuantumStatus: model.QuantumReduced,
		Reference:     "FIPS 180-4",
	})
	r.Register(model.Algorithm{
		Name: "SHA-384", Family: "SHA", Type: "hash",
		QuantumStatus: model.QuantumResistant,
		Reference:     "FIPS 180-4",
	})
	r.Register(model.Algorithm{
		Name: "SHA-512", Family: "SHA", Type: "hash",
		QuantumStatus: model.QuantumResistant,
		Reference:     "FIPS 180-4",
	})
	r.Register(model.Algorithm{
		Name: "SHA3-256", Family: "SHA3", Type: "hash",
		QuantumStatus: model.QuantumReduced,
		Reference:     "FIPS 202",
	})
	r.Register(model.Algorithm{
		Name: "SHA3-384", Family: "SHA3", Type: "hash",
		QuantumStatus: model.QuantumResistant,
		Reference:     "FIPS 202",
	})
	r.Register(model.Algorithm{
		Name: "SHA3-512", Family: "SHA3", Type: "hash",
		QuantumStatus: model.QuantumResistant,
		Reference:     "FIPS 202",
	})
	r.Register(model.Algorithm{
		Name: "SHAKE128", Family: "SHA3", Type: "hash",
		QuantumStatus: model.QuantumReduced,
		Reference:     "FIPS 202",
	})
	r.Register(model.Algorithm{
		Name: "SHAKE256", Family: "SHA3", Type: "hash",
		QuantumStatus: model.QuantumResistant,
		Reference:     "FIPS 202",
	})
	r.Register(model.Algorithm{
		Name: "BLAKE2b-512", Family: "BLAKE", Type: "hash",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC7693",
	})

	// Symmetric ciphers
	r.Register(model.Algorithm{
		Name: "AES-128-GCM", Family: "AES", Type: "cipher",
		QuantumStatus: model.QuantumReduced,
		Reference:     "NIST SP 800-38D",
	})
	r.Register(model.Algorithm{
		Name: "AES-128-CCM", Family: "AES", Type: "cipher",
		QuantumStatus: model.QuantumReduced,
		Reference:     "NIST SP 800-38C",
	})
	r.Register(model.Algorithm{
		Name: "AES-128-CBC", Family: "AES", Type: "cipher",
		QuantumStatus: model.QuantumReduced,
		Reference:     "NIST SP 800-38A",
	})
	r.Register(model.Algorithm{
		Name: "AES-256-GCM", Family: "AES", Type: "cipher",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST SP 800-38D",
	})
	r.Register(model.Algorithm{
		Name: "AES-256-CCM", Family: "AES", Type: "cipher",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST SP 800-38C",
	})
	r.Register(model.Algorithm{
		Name: "AES-256-CBC", Family: "AES", Type: "cipher",
		QuantumStatus: model.QuantumResistant,
		Reference:     "NIST SP 800-38A",
	})
	r.Register(model.Algorithm{
		Name: "CHACHA20-POLY1305", Family: "ChaCha", Type: "cipher",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC8439",
		Aliases:       aliases("ChaCha20-Poly1305"),
	})
	r.Register(model.Algorithm{
		Name: "3DES-EDE-CBC", Family: "3DES", Type: "cipher",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC1851",
		Aliases:       aliases("DES-CBC3"),
	})
	r.Register(model.Algorithm{
		Name: "RC4", Family: "RC", Type: "cipher",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC7465",
	})

	// TLS 1.3 cipher suites
	r.Register(model.Algorithm{
		Name: "TLS_AES_128_GCM_SHA256", Family: "TLS", Type: "cipher-suite",
		QuantumStatus: model.QuantumReduced,
		Reference:     "RFC8446",
		CodePoints:    codePoints(tls.TLS_AES_128_GCM_SHA256),
		Aliases:       aliases("TLS_AES_128_GCM_SHA256"),
	})
	r.Register(model.Algorithm{
		Name: "TLS_AES_256_GCM_SHA384", Family: "TLS", Type: "cipher-suite",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC8446",
		CodePoints:    codePoints(tls.TLS_AES_256_GCM_SHA384),
		Aliases:       aliases("TLS_AES_256_GCM_SHA384"),
	})
	r.Register(model.Algorithm{
		Name: "TLS_CHACHA20_POLY1305_SHA256", Family: "TLS", Type: "cipher-suite",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC8446",
		CodePoints:    codePoints(tls.TLS_CHACHA20_POLY1305_SHA256),
		Aliases:       aliases("TLS_CHACHA20_POLY1305_SHA256"),
	})

	// TLS versions
	r.Register(model.Algorithm{
		Name: "SSLv3", Family: "TLS", Type: "protocol",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC6101",
	})
	r.Register(model.Algorithm{
		Name: "TLSv1.0", Family: "TLS", Type: "protocol",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC2246",
	})
	r.Register(model.Algorithm{
		Name: "TLSv1.1", Family: "TLS", Type: "protocol",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC4346",
	})
	r.Register(model.Algorithm{
		Name: "TLSv1.2", Family: "TLS", Type: "protocol",
		QuantumStatus: model.QuantumVulnerable,
		Reference:     "RFC5246",
	})
	r.Register(model.Algorithm{
		Name: "TLSv1.3", Family: "TLS", Type: "protocol",
		QuantumStatus: model.QuantumResistant,
		Reference:     "RFC8446",
	})
}
