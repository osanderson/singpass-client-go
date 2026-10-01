package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/osanderson/singpass-client-go/keyfile"
)

// The files -tls-ca-dir holds: the CA certificate apps trust, and its key.
const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"
)

// tlsSettings are the -tls-* flags: a CA directory, or a certificate and key.
type tlsSettings struct {
	caDir, certFile, keyFile string
}

func (t tlsSettings) on() bool { return t.caDir != "" || t.certFile != "" || t.keyFile != "" }

func (t tlsSettings) check() error {
	switch {
	case t.caDir != "" && (t.certFile != "" || t.keyFile != ""):
		return errors.New("-tls-ca-dir and -tls-cert / -tls-key are alternatives: set one")
	case (t.certFile == "") != (t.keyFile == ""):
		return errors.New("-tls-cert and -tls-key go together")
	}
	return nil
}

// serverConfig returns the servers' TLS configuration. With a CA directory,
// it loads the CA there — creating it on first use, so apps that trust it
// keep working across restarts — and issues a certificate for hosts.
func (t tlsSettings) serverConfig(hosts []string) (*tls.Config, error) {
	if t.caDir == "" {
		cert, err := tls.LoadX509KeyPair(t.certFile, t.keyFile)
		if err != nil {
			return nil, fmt.Errorf("-tls-cert / -tls-key: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	ca, caKey, err := loadOrCreateCA(t.caDir)
	if err != nil {
		return nil, err
	}
	cert, err := issueServerCert(ca, caKey, hosts)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// rootCAs returns the certificates a health check trusts: the CA, or the
// certificates in -tls-cert.
func (t tlsSettings) rootCAs() (*x509.CertPool, error) {
	path := t.certFile
	if t.caDir != "" {
		path = filepath.Join(t.caDir, caCertFile)
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}
	return pool, nil
}

// loadOrCreateCA returns the CA in dir, creating its key and certificate if
// they don't exist yet.
func loadOrCreateCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("-tls-ca-dir: %w", err)
	}
	key, _, err := keyfile.LoadOrGenerate(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("-tls-ca-dir: %w", err)
	}
	certPath := filepath.Join(dir, caCertFile)
	if pemBytes, err := os.ReadFile(certPath); err == nil {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, nil, fmt.Errorf("%s: not a PEM certificate", certPath)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", certPath, err)
		}
		if !key.PublicKey.Equal(cert.PublicKey) {
			return nil, nil, fmt.Errorf("%s doesn't match %s: remove both to make a new CA", certPath, caKeyFile)
		}
		return cert, key, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "singpass-fake-server test CA (not GovTech, Singpass or Corppass)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, nil, fmt.Errorf("-tls-ca-dir: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// issueServerCert issues a certificate for hosts, signed by the CA, with a
// fresh key.
func issueServerCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, hosts []string) (tls.Certificate, error) {
	key, err := keyfile.GenerateECKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
