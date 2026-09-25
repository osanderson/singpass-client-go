// Package keyfile holds small helpers for generating, marshaling, and loading
// the EC P-256 (ES256 / ECDH-ES) key pairs a relying party registers with the
// authorization server. It carries no protocol logic and no dependency on the
// FAPI client library, so it is safe to use from key-generation tooling that
// runs before any client or discovery document exists.
package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateECKey generates a fresh EC P-256 (ES256 / ECDH-ES) private key.
func GenerateECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalECPrivateKeyPEM encodes key as a PKCS#8 "PRIVATE KEY" PEM block.
func MarshalECPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadECPrivateKey reads a PKCS#8 PEM EC private key from path.
func LoadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parse PKCS#8: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an EC private key (%T)", path, parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: key must be EC P-256", path)
	}
	return key, nil
}
