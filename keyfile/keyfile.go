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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

// WriteECPrivateKey saves key as PKCS#8 PEM at path, readable only by its
// owner (0600), creating missing parent directories as 0700. It never replaces
// an existing file — an error wrapping fs.ErrExist says so — because silently
// overwriting a key registered with Singpass breaks every login; remove the
// file first to rotate deliberately.
func WriteECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	pemBytes, err := MarshalECPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	f, err := createExclusive(path)
	if err != nil {
		return fmt.Errorf("write key %s: %w", path, err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("write key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("write key %s: %w", path, err)
	}
	return nil
}

// createExclusive creates path for writing, owner-only, failing if it exists.
// A variable so tests can make the write fail part-way.
var createExclusive = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// LoadOrGenerate returns the key at path, or — when there is no file — a new
// EC P-256 key saved there with WriteECPrivateKey. created reports which. Any
// other problem reading an existing file is an error, never a silent
// replacement.
func LoadOrGenerate(path string) (key *ecdsa.PrivateKey, created bool, err error) {
	if _, err := os.Stat(path); err == nil {
		key, err := LoadECPrivateKey(path)
		return key, false, err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("stat key %s: %w", path, err)
	}
	key, err = GenerateECKey()
	if err != nil {
		return nil, false, err
	}
	if err := WriteECPrivateKey(path, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}
