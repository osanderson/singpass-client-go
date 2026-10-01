package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osanderson/singpass-client-go/keyfile"
)

// portOf returns addr's port.
func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// With -tls-ca-dir, the servers serve HTTPS with a certificate from a CA kept
// in the directory, an http URL becomes https, and an app trusting the CA logs
// in. A restart keeps the CA.
func TestRunTLSCADir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	spAddr, cpAddr := freeAddr(t), freeAddr(t)
	args := []string{
		"-tls-ca-dir", dir,
		"-singpass-addr", spAddr, "-singpass-url", "http://localhost:" + portOf(t, spAddr),
		"-corppass-addr", cpAddr,
	}
	start := func() (context.CancelFunc, chan error, *lockedBuffer) {
		ctx, cancel := context.WithCancel(context.Background())
		var out, log lockedBuffer
		done := make(chan error, 1)
		go func() { done <- run(ctx, args, &out, &log) }()
		waitFor(t, &out, "X-Custom-NRIC")
		return cancel, done, &out
	}
	cancel, done, out := start()
	if !strings.Contains(out.String(), "trust "+filepath.Join(dir, "ca.pem")) ||
		!strings.Contains(out.String(), "Singpass issuer: https://localhost:"+portOf(t, spAddr)+"/fapi") ||
		!strings.Contains(out.String(), "Corppass issuer: https://"+cpAddr) {
		t.Errorf("stdout = %s", out.String())
	}
	if err := run(context.Background(), append([]string{"-healthcheck"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Errorf("healthcheck: %v", err)
	}
	hc := trustingClient(t, filepath.Join(dir, "ca.pem"))
	smokeLogins(t, hc, "https://localhost:"+portOf(t, spAddr)+"/fapi", "https://"+cpAddr)
	cancel()
	<-done

	ca, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	cancel, done, _ = start()
	again, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if !bytes.Equal(ca, again) {
		t.Error("restart replaced the CA")
	}
	cancel()
	<-done
}

// With -tls-cert and -tls-key, the servers serve that certificate.
func TestRunTLSOwnCert(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, err := loadOrCreateCA(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := issueServerCert(ca, caKey, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	var chain []byte
	for _, der := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.WriteECPrivateKey(keyFile, mustECKey(t, cert.PrivateKey)); err != nil {
		t.Fatal(err)
	}

	spAddr := freeAddr(t)
	args := []string{"-tls-cert", certFile, "-tls-key", keyFile, "-singpass-addr", spAddr,
		"-singpass-url", "https://localhost:" + portOf(t, spAddr), "-corppass-addr", ""}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, log lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, args, &out, &log) }()
	waitFor(t, &out, "X-Custom-NRIC")
	if strings.Contains(out.String(), "test CA") {
		t.Errorf("stdout mentions a test CA: %s", out.String())
	}
	if err := run(context.Background(), append([]string{"-healthcheck"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Errorf("healthcheck: %v", err)
	}
	smokeLogins(t, trustingClient(t, filepath.Join(dir, "ca", "ca.pem")), "https://localhost:"+portOf(t, spAddr)+"/fapi", "")
	cancel()
	<-done
}

func TestRunTLSErrors(t *testing.T) {
	dir := t.TempDir()
	mismatched := filepath.Join(dir, "mismatched")
	if _, _, err := loadOrCreateCA(mismatched); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(mismatched, "ca-key.pem")); err != nil {
		t.Fatal(err)
	}
	garbled := filepath.Join(dir, "garbled")
	if err := os.MkdirAll(garbled, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(garbled, "ca.pem"), []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"both kinds":         {[]string{"-tls-ca-dir", dir, "-tls-cert", "c.pem", "-tls-key", "k.pem"}, "alternatives"},
		"cert alone":         {[]string{"-tls-cert", "c.pem"}, "go together"},
		"missing cert":       {[]string{"-tls-cert", filepath.Join(dir, "c.pem"), "-tls-key", filepath.Join(dir, "k.pem"), "-corppass-addr", ""}, "-tls-cert / -tls-key"},
		"mismatched CA":      {[]string{"-tls-ca-dir", mismatched, "-corppass-addr", ""}, "doesn't match"},
		"garbled CA":         {[]string{"-tls-ca-dir", garbled, "-corppass-addr", ""}, "not a PEM certificate"},
		"healthcheck, no CA": {[]string{"-healthcheck", "-tls-ca-dir", filepath.Join(dir, "absent"), "-corppass-addr", ""}, "no such file"},
	} {
		err := run(context.Background(), tc.args, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestCertHosts(t *testing.T) {
	got := certHosts([]serverSpec{{url: "https://singpass:5156"}, {url: "https://singpass:5157"}, {url: "https://localhost:1"}})
	if strings.Join(got, " ") != "singpass localhost 127.0.0.1 ::1" {
		t.Errorf("certHosts = %q", got)
	}
	for in, want := range map[string]string{"": "https://0.0.0.0:5156", "http://x:1": "https://x:1", "https://y:2": "https://y:2"} {
		if got := httpsURL(in, "0.0.0.0:5156"); got != want {
			t.Errorf("httpsURL(%q) = %q, want %q", in, got, want)
		}
	}
	ca, caKey, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := issueServerCert(ca, caKey, []string{"singpass", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if strings.Join(leaf.DNSNames, " ") != "singpass" || len(leaf.IPAddresses) != 1 {
		t.Errorf("SANs = %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
}

func mustECKey(t *testing.T, k crypto.PrivateKey) *ecdsa.PrivateKey {
	t.Helper()
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key is %T", k)
	}
	return ec
}
