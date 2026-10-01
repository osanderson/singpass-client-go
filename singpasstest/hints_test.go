package singpasstest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// syncBuffer is a bytes.Buffer safe for the server's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func loggingServer(t *testing.T, cfg singpasstest.Config) (*singpasstest.Server, *syncBuffer) {
	t.Helper()
	var log syncBuffer
	cfg.Logger = slog.New(slog.NewTextHandler(&log, nil))
	return startServer(t, cfg), &log
}

// The usual client mistakes are rejected with how to fix them, in the
// error_description the client sees and in the server's log.
func TestRejectionHints(t *testing.T) {
	ctx := context.Background()
	srv, log := loggingServer(t, singpasstest.Config{})
	if err := srv.RegisterTestClients(); err != nil {
		t.Fatal(err)
	}
	k, other := newKeys(t), newKeys(t)
	testSig, _ := singpasstest.TestClientKeys()
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name"}, k)

	for name, tc := range map[string]struct {
		opts singpass.MyinfoOptions
		want string
	}{
		"unknown client": {singpass.MyinfoOptions{ClientID: "nope"},
			"No client 'nope' is registered here; the registered clients are login-test, mi, myinfo-test"},
		"redirect URI": {singpass.MyinfoOptions{RedirectURI: "https://other.example/cb"},
			"Client 'mi''s redirect URIs are https://rp.example/callback, not 'https://other.example/cb'"},
		"test client redirect URI": {singpass.MyinfoOptions{ClientID: singpasstest.TestClientMyinfo, RedirectURI: "https://other.example/cb",
			SigningKey: testSig, SigningKID: singpasstest.TestClientSigningKID},
			"Client 'myinfo-test' accepts any http://localhost redirect URI"},
		"signing key": {singpass.MyinfoOptions{SigningKey: other.sig},
			"Sign the client_assertion with the private half of client 'mi''s registered signing key, kid 'sig-1'"},
		"test client signing key": {singpass.MyinfoOptions{ClientID: singpasstest.TestClientMyinfo, SigningKID: singpasstest.TestClientSigningKID},
			"(a test client: its keys are at " + srv.TestClientKeysURL() + ")"},
		"kid": {singpass.MyinfoOptions{SigningKID: "sig-9"},
			"The client_assertion's header has kid 'sig-9', but client 'mi''s signing key is kid 'sig-1'"},
		"scope": {singpass.MyinfoOptions{Scopes: []string{"openid", "name", "vehicles.make"}},
			"scope 'vehicles.make' is not permitted for this client. Register the scope for client 'mi'; it has openid name"},
	} {
		t.Run(name, func(t *testing.T) {
			o := tc.opts
			if o.ClientID == "" {
				o.ClientID = "mi"
			}
			if o.RedirectURI == "" {
				o.RedirectURI = redirectURI
			}
			if o.Scopes == nil {
				o.Scopes = []string{"openid", "name"}
			}
			if o.SigningKey == nil {
				o.SigningKey = k.sig
			}
			if o.SigningKID == "" {
				o.SigningKID = "sig-1"
			}
			o.Issuer, o.EncryptionKey, o.EncryptionKID = srv.Issuer(), k.enc, "enc-1"
			c, err := singpass.NewMyinfo(ctx, o, devDeps)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = c.BeginLogin(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("BeginLogin err = %v\nwant it to contain %q", err, tc.want)
			}
			if !strings.Contains(log.String(), "rejected POST /fapi/par") {
				t.Errorf("not logged:\n%s", log.String())
			}
		})
	}
}

// A client_assertion with the wrong aud, and a DPoP proof with the wrong htu,
// are rejected saying what they must be.
func TestRejectionHintsAudAndHTU(t *testing.T) {
	srv, _ := loggingServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name"}, k)
	par := srv.Issuer() + "/par"

	status, e := postPAR(t, par, k, "sig-1", srv.Issuer()+"/token", par)
	if want := "The client_assertion's aud is '" + srv.Issuer() + "/token'; it must be the issuer, '" + srv.Issuer() + "'"; status != http.StatusUnauthorized || !strings.Contains(e.Description, want) {
		t.Errorf("wrong aud: %d %q\nwant %q", status, e.Description, want)
	}
	status, e = postPAR(t, par, k, "sig-1", srv.Issuer(), "http://localhost:8080/fapi/par")
	if want := "The DPoP proof's htu is 'http://localhost:8080/fapi/par'; it must be '" + par + "'"; status != http.StatusBadRequest || !strings.Contains(e.Description, want) {
		t.Errorf("wrong htu: %d %q\nwant %q", status, e.Description, want)
	}
}

// A code that can't be used is rejected saying why that usually happens.
func TestRejectionHintUnusableCode(t *testing.T) {
	srv, _ := loggingServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name"}, k)
	token := srv.Issuer() + "/token"
	status, e := postAuthenticated(t, token, k, "sig-1", srv.Issuer(), token, url.Values{
		"grant_type": {"authorization_code"}, "code": {"stale"}, "redirect_uri": {redirectURI}, "code_verifier": {strings.Repeat("v", 43)},
	})
	if want := "A code works once, soon after the login"; status != http.StatusBadRequest || e.Error != "invalid_grant" || !strings.Contains(e.Description, want) {
		t.Errorf("unusable code: %d %+v\nwant invalid_grant containing %q", status, e, want)
	}
}

// A request reaching the server at another host than its URL's is logged
// once, and its rejection says so.
func TestHostMismatchHint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, port, _ := net.SplitHostPort(addr)
	srv, log := loggingServer(t, singpasstest.Config{Addr: addr, BaseURL: "http://localhost:" + port})
	for range 2 {
		res, err := http.PostForm("http://"+addr+"/fapi/token", url.Values{"grant_type": {"authorization_code"}})
		if err != nil {
			t.Fatal(err)
		}
		var e oauthError
		_ = json.NewDecoder(res.Body).Decode(&e)
		res.Body.Close()
		if want := "This request reached the server at " + addr + ", but its URL is http://localhost:" + port; !strings.Contains(e.Description, want) {
			t.Errorf("description %q\nwant %q", e.Description, want)
		}
	}
	if n := strings.Count(log.String(), `msg="This request reached`); n != 1 {
		t.Errorf("host mismatch logged %d times:\n%s", n, log.String())
	}
	if res, err := http.Get(srv.Issuer() + "/.well-known/openid-configuration"); err == nil {
		res.Body.Close()
	}
	if strings.Contains(log.String(), "reached the server at localhost") {
		t.Errorf("a request at the server's own URL was flagged:\n%s", log.String())
	}
}

// postPAR sends a pushed authorization request for client "mi", signing its
// client_assertion with k's signing key (kid) for aud, and a DPoP proof for
// htu.
func postPAR(t *testing.T, par string, k testKeys, kid, aud, htu string) (int, oauthError) {
	t.Helper()
	return postAuthenticated(t, par, k, kid, aud, htu, url.Values{
		"response_type": {"code"}, "scope": {"openid name"},
		"redirect_uri": {redirectURI}, "state": {randID()}, "nonce": {randID()},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "code_challenge_method": {"S256"},
	})
}

// postAuthenticated posts form to endpoint as client "mi", with a
// client_assertion signed by k's signing key (kid) for aud, and a DPoP proof
// for htu.
func postAuthenticated(t *testing.T, endpoint string, k testKeys, kid, aud, htu string, form url.Values) (int, oauthError) {
	t.Helper()
	now := time.Now().Unix()
	assertion := signJWT(t, k.sig, map[string]any{"alg": "ES256", "kid": kid},
		map[string]any{"iss": "mi", "sub": "mi", "aud": aud, "jti": randID(), "iat": now, "exp": now + 60})
	dpopKey := newKeys(t).sig
	pub, _ := dpopKey.PublicKey.Bytes()
	b64 := base64.RawURLEncoding.EncodeToString
	proof := signJWT(t, dpopKey,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": b64(pub[1:33]), "y": b64(pub[33:])}},
		map[string]any{"jti": randID(), "htm": "POST", "htu": htu, "iat": now})
	form.Set("client_id", "mi")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var e oauthError
	_ = json.NewDecoder(res.Body).Decode(&e)
	return res.StatusCode, e
}

// signJWT returns a compact ES256 JWS of claims.
func signJWT(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
