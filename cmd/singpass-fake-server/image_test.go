package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// TestImage logs in against a singpass-fake-server that is already running
// — in CI, the container image — at the issuers in SMOKE_SINGPASS_ISSUER and
// SMOKE_CORPPASS_ISSUER, as an app in another language would: with the
// built-in test clients, their keys fetched from the server, and the
// X-Custom-* headers. Over HTTPS, it trusts the CA certificate in
// SMOKE_CA_FILE. Skipped unless SMOKE_SINGPASS_ISSUER is set.
func TestImage(t *testing.T) {
	sp, cp := os.Getenv("SMOKE_SINGPASS_ISSUER"), os.Getenv("SMOKE_CORPPASS_ISSUER")
	if sp == "" {
		t.Skip("SMOKE_SINGPASS_ISSUER not set")
	}
	hc := http.DefaultClient
	if ca := os.Getenv("SMOKE_CA_FILE"); ca != "" {
		hc = trustingClient(t, ca)
	}
	smokeLogins(t, hc, sp, cp)
}

// smokeLogins logs in to the Singpass issuer sp as each of its test clients,
// and to the Corppass issuer cp, if set, as its test client.
func smokeLogins(t *testing.T, hc *http.Client, sp, cp string) {
	t.Helper()
	sig, enc := fetchTestClientKeys(t, hc, strings.TrimSuffix(sp, "/fapi")+"/_fake/test-client/jwks.json")

	id := headerLogin(t, hc, sp, singpasstest.TestClientMyinfo, sig, enc, singpasstest.LoginAs{NRIC: "S8012345F"})
	if got := id.Myinfo.PersonProfile().UINFIN.String(); got != "S8012345F" {
		t.Errorf("Myinfo uinfin = %q", got)
	}
	id = headerLogin(t, hc, sp, singpasstest.TestClientLogin, sig, enc, singpasstest.LoginAs{NRIC: "S1234567D"})
	if got := id.SubjectAttributes().IdentityNumber; got != "S1234567D" {
		t.Errorf("Login identity_number = %q", got)
	}
	if cp != "" {
		id = headerLogin(t, hc, cp, singpasstest.TestClientMyinfoBusiness, sig, enc, singpasstest.LoginAs{UEN: "201912345K", NRIC: "S7812345J"})
		if got := id.Myinfo.EntityProfile().Name.String(); got != "HARBOURFRONT TRADING PTE. LTD." {
			t.Errorf("Myinfo Business entity name = %q", got)
		}
	}
}

// trustingClient returns an HTTP client that trusts the CA certificates in
// the PEM file caFile.
func trustingClient(t *testing.T, caFile string) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("%s holds no certificate", caFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr}
}

// fetchTestClientKeys reads the test clients' private JWKS from the server.
func fetchTestClientKeys(t *testing.T, hc *http.Client, jwksURL string) (sig, enc *ecdsa.PrivateKey) {
	t.Helper()
	resp, err := hc.Get(jwksURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var set struct{ Keys []struct{ Use, D string } }
	if err := json.Unmarshal(body, &set); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", jwksURL, resp.StatusCode, body)
	}
	for _, k := range set.Keys {
		d, err := base64.RawURLEncoding.DecodeString(k.D)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		if err != nil {
			t.Fatal(err)
		}
		if k.Use == "sig" {
			sig = key
		} else {
			enc = key
		}
	}
	if sig == nil || enc == nil {
		t.Fatalf("%s lacks a key: %s", jwksURL, body)
	}
	return sig, enc
}

// headerLogin logs in to issuer as clientID over hc, choosing the user with
// the X-Custom-* headers, and returns the identity.
func headerLogin(t *testing.T, hc *http.Client, issuer, clientID string, sig, enc *ecdsa.PrivateKey, as singpasstest.LoginAs) *singpass.Identity {
	t.Helper()
	ctx := context.Background()
	deps := singpass.Dependencies{AllowLoopbackHTTP: true, HTTPClient: hc}
	if u, err := url.Parse(issuer); err == nil && u.Scheme == "https" {
		// Reached by a service name on a Docker network.
		deps.AllowedPrivateHosts = []string{u.Hostname()}
	}
	const redirect = "http://localhost:3000/callback"
	keys := func() (*ecdsa.PrivateKey, string, *ecdsa.PrivateKey, string) {
		return sig, singpasstest.TestClientSigningKID, enc, singpasstest.TestClientEncryptionKID
	}
	var c *singpass.Client
	var err error
	switch clientID {
	case singpasstest.TestClientLogin:
		o := singpass.LoginOptions{Issuer: issuer, ClientID: clientID, RedirectURI: redirect, Scopes: []string{"openid", "user.identity"}}
		o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID = keys()
		c, err = singpass.NewLogin(ctx, o, deps)
	case singpasstest.TestClientMyinfo:
		o := singpass.MyinfoOptions{Issuer: issuer, ClientID: clientID, RedirectURI: redirect, Scopes: []string{"openid", "uinfin", "name"}}
		o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID = keys()
		c, err = singpass.NewMyinfo(ctx, o, deps)
	default:
		o := singpass.MyinfoBusinessOptions{Issuer: issuer, ClientID: clientID, RedirectURI: redirect, Scopes: []string{"openid", "entity.basic_profile.name"}}
		o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID = keys()
		c, err = singpass.NewMyinfoBusiness(ctx, o, deps)
	}
	if err != nil {
		t.Fatal(err)
	}
	authURL, state, err := c.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	req.Header = as.Header()
	noFollow := &http.Client{Transport: hc.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize as %+v: %s", as, resp.Status)
	}
	id, err := c.Complete(ctx, loc.RawQuery, state)
	if err != nil {
		t.Fatalf("%s: Complete: %v", clientID, err)
	}
	return id
}
