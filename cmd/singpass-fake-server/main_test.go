package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
)

type keyPair struct{ sig, enc *ecdsa.PrivateKey }

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	sig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return keyPair{sig, enc}
}

func (k keyPair) jwks(t *testing.T) []byte {
	t.Helper()
	j, err := singpass.OfflineClientJWKS(context.Background(), &k.sig.PublicKey, "sig-1", &k.enc.PublicKey, "enc-1")
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigErrors(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"no clients":      {`{"clients": []}`, "registers no clients"},
		"bad product":     {`{"clients": [{"id": "a", "product": "sign", "redirect_uris": ["http://localhost/cb"], "jwks_url": "http://x"}]}`, "product must be"},
		"no redirect":     {`{"clients": [{"id": "a", "product": "login", "jwks_url": "http://x"}]}`, "no redirect_uris"},
		"two key sources": {`{"clients": [{"id": "a", "product": "login", "redirect_uris": ["http://localhost/cb"], "jwks_url": "http://x", "jwks_file": "k.json"}]}`, "exactly one of"},
	} {
		if _, err := loadConfig(writeConfig(t, tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestParseJWKS(t *testing.T) {
	k := newKeyPair(t)
	c, err := parseJWKS(k.jwks(t))
	if err != nil || c.SigningKID != "sig-1" || c.EncryptionKID != "enc-1" || !c.SigningKey.Equal(&k.sig.PublicKey) {
		t.Fatalf("parseJWKS = %+v, %v", c, err)
	}
	if _, err := parseJWKS([]byte(`{"keys": [{"kty": "EC", "crv": "P-256", "use": "sig", "kid": "s", "x": "AA", "y": "AA", "d": "AA"}]}`)); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key accepted: %v", err)
	}
	if _, err := parseJWKS([]byte(`{"keys": []}`)); err == nil {
		t.Error("empty JWKS accepted")
	}
}

// lockedBuffer is an io.Writer safe for the server's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestRunEndToEnd(t *testing.T) {
	jwksPollInterval = 50 * time.Millisecond
	mi, mib := newKeyPair(t), newKeyPair(t)

	// The Myinfo app's JWKS comes up after the server, as an app often does.
	jwksURL := "http://" + freeAddr(t) + "/jwks.json"
	proxyReady := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		u, _ := url.Parse(jwksURL)
		ln, err := net.Listen("tcp", u.Host)
		if err != nil {
			t.Error(err)
			return
		}
		close(proxyReady)
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(mi.jwks(t)) }))
	}()

	cfg := writeConfig(t, `{"clients": [
		{"id": "mi", "product": "myinfo", "redirect_uris": ["https://app.example/cb"], "scopes": ["name", "uinfin"], "jwks_url": "`+jwksURL+`"},
		{"id": "mib", "product": "myinfo-business", "redirect_uris": ["https://app.example/cb"], "scopes": ["entity.basic_profile.name"], "jwks": `+string(mib.jwks(t))+`}
	]}`)
	spAddr, cpAddr := freeAddr(t), freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, log lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-config", cfg, "-singpass-addr", spAddr, "-corppass-addr", cpAddr, "-auto"}, &out, &log)
	}()

	<-proxyReady
	deadline := time.Now().Add(5 * time.Second)
	for !(strings.Contains(log.String(), `registered client "mi"`) && strings.Contains(log.String(), `registered client "mib"`)) {
		if time.Now().After(deadline) {
			t.Fatalf("clients not registered:\n%s", log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(log.String(), `client "mi": waiting for its JWKS`) {
		t.Errorf("expected the jwks_url to be retried:\n%s", log.String())
	}
	if !strings.Contains(out.String(), "Singpass issuer: http://"+spAddr+"/fapi") || !strings.Contains(out.String(), "test user: ") {
		t.Errorf("stdout = %s", out.String())
	}

	login := func(issuer, id string, k keyPair, business bool) {
		t.Helper()
		ctx := context.Background()
		deps := singpass.Dependencies{AllowLoopbackHTTP: true}
		var c *singpass.Client
		var err error
		if business {
			c, err = singpass.NewMyinfoBusiness(ctx, singpass.MyinfoBusinessOptions{Issuer: issuer, ClientID: id, RedirectURI: "https://app.example/cb",
				Scopes: []string{"openid", "entity.basic_profile.name"}, SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1"}, deps)
		} else {
			c, err = singpass.NewMyinfo(ctx, singpass.MyinfoOptions{Issuer: issuer, ClientID: id, RedirectURI: "https://app.example/cb",
				Scopes: []string{"openid", "name", "uinfin"}, SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1"}, deps)
		}
		if err != nil {
			t.Fatal(err)
		}
		redirect, state, err := c.BeginLogin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := hc.Get(redirect)
		if err != nil {
			t.Fatal(err)
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		id2, err := c.Complete(ctx, loc.RawQuery, state)
		if err != nil {
			t.Fatalf("%s: Complete: %v", id, err)
		}
		if business && id2.Myinfo.EntityProfile().Name.String() == "" || !business && id2.Myinfo.PersonProfile().Name.String() == "" {
			t.Errorf("%s: no Myinfo data", id)
		}
	}
	login("http://"+spAddr+"/fapi", "mi", mi, false)
	login("http://"+cpAddr, "mib", mib, true)

	cancel()
	if err := <-done; err != nil {
		t.Errorf("run: %v", err)
	}
}
