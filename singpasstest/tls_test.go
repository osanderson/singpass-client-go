package singpasstest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// selfSigned returns a TLS certificate for localhost and a pool trusting it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestTLS(t *testing.T) {
	cert, pool := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, port, _ := net.SplitHostPort(addr)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	if _, err := singpasstest.NewServer(singpasstest.Config{Addr: addr, BaseURL: "http://localhost:" + port, TLS: tlsConfig}); err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("http BaseURL with TLS: err = %v", err)
	}
	srv := startServer(t, singpasstest.Config{Addr: addr, BaseURL: "https://localhost:" + port, TLS: tlsConfig})
	if srv.Issuer() != "https://localhost:"+port+"/fapi" {
		t.Errorf("Issuer = %s", srv.Issuer())
	}
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name"}, k)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	c, err := singpass.NewMyinfo(context.Background(), singpass.MyinfoOptions{
		Issuer: srv.Issuer(), ClientID: "mi", RedirectURI: redirectURI, Scopes: []string{"openid", "name"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, singpass.Dependencies{AllowLoopbackHTTP: true, HTTPClient: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	// Authorize trusts the server's own certificate.
	if id := login(t, srv, c); id.Myinfo.PersonProfile().Name.String() == "" {
		t.Error("no Myinfo name over HTTPS")
	}
}

func TestPrivateHostsRefusedInProduction(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	k := newKeys(t)
	deps := singpass.Dependencies{AllowedPrivateHosts: []string{"singpass"}, Assurance: singpass.AssuranceProduction}
	_, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "x", RedirectURI: redirectURI, Scopes: []string{"openid"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, deps)
	if err == nil || !strings.Contains(err.Error(), "AllowedPrivateHosts") {
		t.Fatalf("err = %v, want AllowedPrivateHosts refused under production", err)
	}
}
