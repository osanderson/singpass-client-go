package singpasstest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
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
			c, err := singpass.NewMyinfo(ctx, miOptions(tc.opts, srv, k), devDeps)
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

// miOptions is o for client "mi" with keys k at srv, with every field o
// leaves unset filled in.
func miOptions(o singpass.MyinfoOptions, srv *singpasstest.Server, k testKeys) singpass.MyinfoOptions {
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
	return o
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

// A client_assertion naming another client is rejected saying what its iss
// and sub must be.
func TestRejectionHintsAssertionIssuerSubject(t *testing.T) {
	srv, _ := loggingServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name"}, k)
	par := srv.Issuer() + "/par"

	for name, tc := range map[string]struct{ iss, sub string }{
		"iss": {"someone-else", "mi"},
		"sub": {"mi", "someone-else"},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := postAs(t, par, clientAssertion(t, k, "sig-1", tc.iss, tc.sub, srv.Issuer()), newKeys(t).sig, par, parForm(randID()))
			var e oauthError
			_ = json.Unmarshal(body, &e)
			if want := "The client_assertion's iss and sub must both be the client_id, 'mi'"; status != http.StatusUnauthorized || !strings.Contains(e.Description, want) {
				t.Errorf("%d %q\nwant it to contain %q", status, e.Description, want)
			}
		})
	}
}

// A token request whose redirect_uri or code_verifier isn't the login's, or
// without a DPoP proof, is rejected saying what to send.
func TestRejectionHintsTokenRequest(t *testing.T) {
	srv, _ := loggingServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name"}, k)

	for name, tc := range map[string]struct {
		redirectURI, verifier string
		noDPoP                bool
		want                  string
	}{
		"redirect_uri":  {redirectURI: "https://rp.example/other", want: "Send the token request the same redirect_uri as the pushed authorization request"},
		"code_verifier": {redirectURI: redirectURI, verifier: strings.Repeat("x", 43), want: "Send the PKCE code_verifier of the login this code came from"},
		"no DPoP":       {redirectURI: redirectURI, noDPoP: true, want: "Send a DPoP proof in the DPoP header, as Singpass and Corppass require"},
	} {
		t.Run(name, func(t *testing.T) {
			code, verifier, dpop := authorizationCode(t, srv, k)
			if tc.verifier != "" {
				verifier = tc.verifier
			}
			if tc.noDPoP {
				dpop = nil
			}
			token := srv.Issuer() + "/token"
			status, body := postAs(t, token, clientAssertion(t, k, "sig-1", "mi", "mi", srv.Issuer()), dpop, token, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {tc.redirectURI}, "code_verifier": {verifier},
			})
			var e oauthError
			_ = json.Unmarshal(body, &e)
			if status != http.StatusBadRequest || !strings.Contains(e.Description, tc.want) {
				t.Errorf("%d %+v\nwant it to contain %q", status, e, tc.want)
			}
		})
	}
}

// parForm is a pushed authorization request for client "mi" with PKCE
// verifier's challenge.
func parForm(verifier string) url.Values {
	challenge := sha256.Sum256([]byte(verifier))
	return url.Values{
		"response_type": {"code"}, "scope": {"openid name"},
		"redirect_uri": {redirectURI}, "state": {randID()}, "nonce": {randID()},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}
}

// authorizationCode logs in as client "mi" by hand, returning the code, its
// PKCE verifier and the DPoP key it's bound to.
func authorizationCode(t *testing.T, srv *singpasstest.Server, k testKeys) (code, verifier string, dpop *ecdsa.PrivateKey) {
	t.Helper()
	verifier, dpop = randID()+randID(), newKeys(t).sig
	par := srv.Issuer() + "/par"
	status, body := postAs(t, par, clientAssertion(t, k, "sig-1", "mi", "mi", srv.Issuer()), dpop, par, parForm(verifier))
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(body, &pushed); err != nil || status != http.StatusCreated {
		t.Fatalf("PAR: %d %s", status, body)
	}
	query, err := srv.Authorize(context.Background(), srv.Issuer()+"/auth?"+url.Values{"client_id": {"mi"}, "request_uri": {pushed.RequestURI}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(query)
	if q.Get("code") == "" {
		t.Fatalf("no code in %q", query)
	}
	return q.Get("code"), verifier, dpop
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
	status, body := postAs(t, endpoint, clientAssertion(t, k, kid, "mi", "mi", aud), newKeys(t).sig, htu, form)
	var e oauthError
	_ = json.Unmarshal(body, &e)
	return status, e
}

// clientAssertion is a client_assertion signed by k's signing key (kid).
func clientAssertion(t *testing.T, k testKeys, kid, iss, sub, aud string) string {
	t.Helper()
	now := time.Now().Unix()
	return signJWT(t, k.sig, map[string]any{"alg": "ES256", "kid": kid},
		map[string]any{"iss": iss, "sub": sub, "aud": aud, "jti": randID(), "iat": now, "exp": now + 60})
}

// postAs posts form to endpoint as client "mi" with assertion, and with a
// DPoP proof for htu signed by dpopKey unless it's nil. It returns the status
// and the response body.
func postAs(t *testing.T, endpoint, assertion string, dpopKey *ecdsa.PrivateKey, htu string, form url.Values) (int, []byte) {
	t.Helper()
	form.Set("client_id", "mi")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopKey != nil {
		pub, _ := dpopKey.PublicKey.Bytes()
		b64 := base64.RawURLEncoding.EncodeToString
		req.Header.Set("DPoP", signJWT(t, dpopKey,
			map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": b64(pub[1:33]), "y": b64(pub[33:])}},
			map[string]any{"jti": randID(), "htm": "POST", "htu": htu, "iat": time.Now().Unix()}))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, body
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

// The authorization request is read strictly: a repeated client_id or
// request_uri is refused, saying the spec forbids it, and doesn't use up the
// login.
func TestAuthorizeRefusesRepeatedParameters(t *testing.T) {
	ctx := context.Background()
	srv, log := loggingServer(t, singpasstest.Config{})
	c := myinfoClient(t, srv)
	redirectURL, state, err := c.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirectURL)
	for _, param := range []string{"client_id", "request_uri"} {
		repeated := *u
		q := repeated.Query()
		q.Add(param, q.Get(param))
		repeated.RawQuery = q.Encode()
		res, err := http.Get(repeated.String())
		if err != nil {
			t.Fatal(err)
		}
		var e oauthError
		_ = json.NewDecoder(res.Body).Decode(&e)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest || e.Error != "invalid_request" ||
			!strings.Contains(e.Description, param+" is included more than once") || !strings.Contains(e.Description, "RFC 6749 section 3.1") {
			t.Errorf("repeated %s: %d %+v", param, res.StatusCode, e)
		}
	}
	if !strings.Contains(log.String(), "rejected GET /fapi/auth") {
		t.Errorf("not logged:\n%s", log.String())
	}

	// The login still completes with the URL as PAR built it.
	query, err := srv.Authorize(ctx, redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(ctx, query, state); err != nil {
		t.Fatalf("login after the refusals: %v", err)
	}
}
