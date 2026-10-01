package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
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

func TestRunPersonaFlags(t *testing.T) {
	cfg := writeConfig(t, `{"clients": [{"id": "a", "product": "login", "redirect_uris": ["https://app.example/cb"], "jwks": `+string(newKeyPair(t).jwks(t))+`}]}`)
	if err := run(context.Background(), []string{"-config", cfg, "-only-personas"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "-only-personas needs -personas") {
		t.Errorf("-only-personas alone: %v", err)
	}
	personas := writeConfig(t, `[{"name": "Extra User", "nric": "S1234567D"}]`)
	ctx, cancel := context.WithCancel(context.Background())
	var out, log lockedBuffer // the command writes stderr from several goroutines
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-config", cfg, "-personas", personas, "-only-personas", "-corppass-addr", "", "-singpass-addr", freeAddr(t)}, &out, &log)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "S1234567D") {
		if time.Now().After(deadline) {
			t.Fatalf("stdout = %s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(out.String(), "Tan Xiao Hui") {
		t.Error("-only-personas kept the built-in users")
	}
	cancel()
	<-done
}

// run refuses bad flags and configuration before serving anything.
func TestRunErrors(t *testing.T) {
	jwks := string(newKeyPair(t).jwks(t))
	login := writeConfig(t, `{"clients": [{"id": "a", "product": "login", "redirect_uris": ["https://app.example/cb"], "jwks": `+jwks+`}]}`)
	business := writeConfig(t, `{"clients": [{"id": "b", "product": "myinfo-business", "redirect_uris": ["https://app.example/cb"], "jwks": `+jwks+`}]}`)
	noUsers := writeConfig(t, `[]`)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"unknown flag":          {[]string{"-nope"}, "flag provided but not defined"},
		"incomplete -client-id": {[]string{"-client-id", "a", "-client-product", "login"}, "-client-id: client \"a\" has no redirect_uris"},
		"missing config":        {[]string{"-config", filepath.Join(t.TempDir(), "absent.json")}, "no such file"},
		"config not JSON":       {[]string{"-config", writeConfig(t, `{`)}, "unexpected end"},
		"client without an id":  {[]string{"-config", writeConfig(t, `{"clients": [{"product": "login"}]}`)}, "a client has no id"},
		"client's server off":   {[]string{"-config", business, "-corppass-addr", "", "-singpass-addr", freeAddr(t)}, "which is disabled"},
		"missing personas file": {[]string{"-config", login, "-personas", filepath.Join(t.TempDir(), "absent.json"), "-corppass-addr", ""}, "no such file"},
		"no test users":         {[]string{"-config", login, "-personas", noUsers, "-only-personas", "-corppass-addr", ""}, "has no test users"},
		"bad listen address":    {[]string{"-config", login, "-singpass-addr", "not an address", "-corppass-addr", ""}, "start Singpass server"},
	} {
		err := run(context.Background(), tc.args, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// A client whose keys can't be read or used isn't registered, and the reason
// is reported; a jwks_url that doesn't answer yet is waited for.
func TestRunReportsClientKeyProblems(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	cfg := writeConfig(t, `{"clients": [
		{"id": "unreadable", "product": "login", "redirect_uris": ["https://app.example/cb"], "jwks_file": "`+filepath.Join(t.TempDir(), "absent.json")+`"},
		{"id": "keyless", "product": "login", "redirect_uris": ["https://app.example/cb"], "jwks": {"keys": []}},
		{"id": "pending", "product": "login", "redirect_uris": ["https://app.example/cb"], "jwks_url": "`+notFound.URL+`"}
	]}`)
	ctx, cancel := context.WithCancel(context.Background())
	var out, log lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-config", cfg, "-corppass-addr", "", "-singpass-addr", freeAddr(t)}, &out, &log)
	}()
	want := []string{`client "unreadable":`, `client "keyless": the JWKS needs`, `client "pending": waiting for its JWKS`, "HTTP 404"}
	deadline := time.Now().Add(3 * time.Second)
	for !containsAll(log.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("stderr lacks one of %q:\n%s", want, log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("run = %v", err)
	}
}

func containsAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func TestJWKPublicKeyErrors(t *testing.T) {
	for name, k := range map[string]jwk{
		"short x":      {Kid: "k", X: "AA", Y: "AA"},
		"not on curve": {Kid: "k", X: strings.Repeat("A", 43), Y: strings.Repeat("A", 43)},
	} {
		if _, err := k.publicKey(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// With no clients configured, the built-in test clients are registered, and
// an app logs in with their published keys and any loopback redirect URI.
func TestRunZeroConfig(t *testing.T) {
	spAddr, cpAddr := freeAddr(t), freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, log lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-singpass-addr", spAddr, "-corppass-addr", cpAddr}, &out, &log) }()
	waitFor(t, &out, "test clients: myinfo-business-test", "X-Custom-NRIC")
	keysURL := "http://" + spAddr + "/_fake/test-client/jwks.json"
	if !strings.Contains(out.String(), "test clients: login-test, myinfo-test") || !strings.Contains(out.String(), keysURL) ||
		!strings.Contains(out.String(), "test user: S9812381D") || !strings.Contains(out.String(), "test user: 201912345K / S7812345J") {
		t.Errorf("stdout = %s", out.String())
	}

	// The sign-in page is on; the header skips it.
	sig, enc := singpasstest.TestClientKeys()
	id := headerLogin(t, "http://"+spAddr+"/fapi", singpasstest.TestClientMyinfo, sig, enc, singpasstest.LoginAs{NRIC: "S8012345F"})
	if got := id.Myinfo.PersonProfile().UINFIN.String(); got != "S8012345F" {
		t.Errorf("uinfin = %q", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("run = %v", err)
	}
}

// Flags can be set from FAKE_* environment variables; a flag on the command
// line wins.
func TestRunFlagsFromEnv(t *testing.T) {
	k := newKeyPair(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(k.jwks(t)) }))
	defer jwks.Close()
	spAddr := freeAddr(t)
	t.Setenv("FAKE_SINGPASS_ADDR", "not used")
	t.Setenv("FAKE_CORPPASS_ADDR", "")
	t.Setenv("FAKE_SINGPASS_URL", "http://localhost:"+strings.Split(spAddr, ":")[1])
	t.Setenv("FAKE_CLIENT_ID", "my-app")
	t.Setenv("FAKE_CLIENT_PRODUCT", "myinfo")
	t.Setenv("FAKE_CLIENT_REDIRECT_URIS", "http://localhost:3000/cb, http://localhost:3000/cb2")
	t.Setenv("FAKE_CLIENT_SCOPES", "uinfin name")
	t.Setenv("FAKE_CLIENT_JWKS_URL", jwks.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, log lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-singpass-addr", spAddr}, &out, &log) }()
	waitFor(t, &log, `registered client "my-app" (myinfo)`)
	if !strings.Contains(out.String(), "Singpass issuer: http://localhost:") || strings.Contains(out.String(), "Corppass issuer") || strings.Contains(out.String(), "test clients") {
		t.Errorf("stdout = %s", out.String())
	}
	cancel()
	<-done

	t.Setenv("FAKE_AUTO", "maybe")
	if err := run(context.Background(), nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "FAKE_AUTO") {
		t.Errorf("bad FAKE_AUTO: err = %v", err)
	}
}

func TestHealthcheck(t *testing.T) {
	spAddr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, log lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-singpass-addr", spAddr, "-corppass-addr", ""}, &out, &log) }()
	waitFor(t, &out, "Singpass issuer")

	// An unspecified listen address is checked on loopback.
	port := strings.Split(spAddr, ":")[1]
	for _, addr := range []string{spAddr, "0.0.0.0:" + port, ":" + port} {
		if err := run(ctx, []string{"-healthcheck", "-singpass-addr", addr, "-corppass-addr", ""}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Errorf("healthcheck %s: %v", addr, err)
		}
	}
	if err := run(ctx, []string{"-healthcheck", "-singpass-addr", spAddr, "-corppass-addr", freeAddr(t)}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Error("healthcheck passed with the Corppass server down")
	}
	if err := run(ctx, []string{"-healthcheck", "-singpass-addr", "no port", "-corppass-addr", ""}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Error("healthcheck passed with a bad address")
	}
	cancel()
	<-done
}

// waitFor waits for b to contain every one of want.
func waitFor(t *testing.T, b *lockedBuffer, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !containsAll(b.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("output lacks one of %q:\n%s", want, b.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
