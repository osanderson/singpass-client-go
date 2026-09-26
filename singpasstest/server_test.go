package singpasstest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

const redirectURI = "https://rp.example/callback"

type testKeys struct{ sig, enc *ecdsa.PrivateKey }

func newKeys(t *testing.T) testKeys {
	t.Helper()
	sig, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKeys{sig, enc}
}

func startServer(t *testing.T, cfg singpasstest.Config) *singpasstest.Server {
	t.Helper()
	srv, err := singpasstest.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func register(t *testing.T, srv *singpasstest.Server, id string, app singpasstest.App, scopes []string, k testKeys) {
	t.Helper()
	if err := srv.RegisterClient(singpasstest.Client{
		ID: id, App: app, RedirectURIs: []string{redirectURI}, Scopes: scopes,
		SigningKey: &k.sig.PublicKey, SigningKID: "sig-1",
		EncryptionKey: &k.enc.PublicKey, EncryptionKID: "enc-1",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
}

func login(t *testing.T, srv *singpasstest.Server, c *singpass.Client) *singpass.Identity {
	t.Helper()
	ctx := context.Background()
	redirectURL, _, err := c.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	query, err := srv.Authorize(ctx, redirectURL)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	id, err := c.Complete(ctx, query)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return id
}

var devDeps = singpass.Dependencies{AllowLoopbackHTTP: true}

func TestLoginEndToEnd(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "login-client", singpasstest.Login, []string{"user.identity"}, k)

	c, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "login-client", RedirectURI: redirectURI,
		Scopes:     []string{"openid", "user.identity"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}

	id := login(t, srv, c)
	want := srv.Personas()[0]
	if id.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", id.Subject, want.Subject)
	}
	if id.Issuer() != srv.Issuer() || id.AssuranceLevel() != "2" {
		t.Errorf("iss = %q, LOA = %q; want %q, 2", id.Issuer(), id.AssuranceLevel(), srv.Issuer())
	}
	if id.Myinfo != nil {
		t.Error("Login identity has Myinfo data")
	}
	if id.Scope != "openid user.identity" {
		t.Errorf("Scope = %q (Singpass omits scope; the client falls back to the requested one)", id.Scope)
	}
}

func TestMyinfoEndToEnd(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "myinfo-client", singpasstest.Myinfo, []string{"uinfin", "name", "regadd", "vehicles.make"}, k)
	persona := srv.Personas()[0]
	if err := srv.SetPersona(persona.Subject); err != nil {
		t.Fatal(err)
	}

	c, err := singpass.NewMyinfo(context.Background(), singpass.MyinfoOptions{
		Issuer: srv.Issuer(), ClientID: "myinfo-client", RedirectURI: redirectURI,
		Scopes:     []string{"openid", "uinfin", "name", "regadd", "vehicles.make"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatalf("NewMyinfo: %v", err)
	}

	id := login(t, srv, c)
	if id.Myinfo == nil {
		t.Fatal("no Myinfo data")
	}
	p := id.Myinfo.Person
	if got := p.Field("name").String(); got != "TAN XIAO HUI" {
		t.Errorf("name = %q", got)
	}
	if got := p.Object("regadd").Field("postal").String(); got != "460102" {
		t.Errorf("postal = %q", got)
	}
	if got := len(p.List("vehicles")); got != 1 {
		t.Errorf("vehicles = %d records, want 1", got)
	}
	if p.Has("sex") || p.Has("email") {
		t.Error("person_info contains fields outside the granted scopes")
	}
}

func TestMyinfoBusinessEndToEnd(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Issuer: singpasstest.Corppass})
	if strings.HasSuffix(srv.Issuer(), "/fapi") {
		t.Errorf("Corppass issuer %q has a /fapi path", srv.Issuer())
	}
	k := newKeys(t)
	scopes := []string{"entity.basic_profile.name", "authinfo"}
	register(t, srv, "biz-client", singpasstest.Myinfo, scopes, k)

	c, err := singpass.NewMyinfoBusiness(context.Background(), singpass.MyinfoBusinessOptions{
		Issuer: srv.Issuer(), ClientID: "biz-client", RedirectURI: redirectURI,
		Scopes:     append([]string{"openid"}, scopes...),
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatalf("NewMyinfoBusiness: %v", err)
	}

	// Corppass sends /userinfo sub = client_id and double-encoded blocks; the
	// client must tolerate the first and unwrap the second.
	id := login(t, srv, c)
	name := id.Myinfo.Entity.Object("basic_profile").Field("name").String()
	if name != "HARBOURFRONT TRADING PTE. LTD." {
		t.Errorf("entity name = %q", name)
	}
	auths := id.Myinfo.Auth.Authorisations()
	if len(auths) != 1 || auths[0].Role != "Approver" {
		t.Errorf("authorisations = %+v", auths)
	}
	if id.Scope != "openid entity.basic_profile.name authinfo" {
		t.Errorf("Scope = %q (Corppass echoes it)", id.Scope)
	}
}

func TestLoginRequiresAuthContextType(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	k := newKeys(t)
	register(t, srv, "login-client", singpasstest.Login, nil, k)

	// A Login app built without authentication_context_type is refused at PAR,
	// as Singpass does.
	deps := devDeps
	km, _ := singpass.NewKeyManager(k.sig, "sig-1")
	dec, _ := singpass.NewECDHDecrypter(k.enc, "enc-1")
	deps.Keys, deps.Decryption = km, dec
	c, err := singpass.New(context.Background(), singpass.Options{
		Issuer: srv.Issuer(), ClientID: "login-client", RedirectURI: redirectURI, Scopes: []string{"openid"},
	}, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.BeginLogin(context.Background()); err == nil || !strings.Contains(err.Error(), "authentication_context_type") {
		t.Fatalf("BeginLogin err = %v, want authentication_context_type error", err)
	}
}

func TestCancelledLoginIsDenied(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Interactive: true})
	k := newKeys(t)
	register(t, srv, "login-client", singpasstest.Login, nil, k)
	c, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "login-client", RedirectURI: redirectURI, Scopes: []string{"openid"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}
	redirectURL, _, err := c.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// The sign-in page carries the interaction handle; press Cancel.
	res, err := http.Get(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := regexp.MustCompile(`name="handle" value="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("no handle on sign-in page:\n%s", page)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err = noFollow.PostForm(srv.Issuer()+"/auth/decision", url.Values{"handle": {string(m[1])}, "decision": {"cancel"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	loc, _ := url.Parse(res.Header.Get("Location"))

	_, err = c.Complete(context.Background(), loc.RawQuery)
	var denied *singpass.DeniedError
	if !errors.As(err, &denied) || denied.Code != "access_denied" {
		t.Fatalf("Complete err = %v, want DeniedError access_denied", err)
	}
}

func TestLoopbackRefusedInProduction(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	k := newKeys(t)
	deps := singpass.Dependencies{AllowLoopbackHTTP: true, Assurance: singpass.AssuranceProduction}
	_, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "x", RedirectURI: redirectURI, Scopes: []string{"openid"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, deps)
	if err == nil || !strings.Contains(err.Error(), "AllowLoopbackHTTP") {
		t.Fatalf("err = %v, want AllowLoopbackHTTP refused under production", err)
	}
}

// TestLoopbackHTTPRedirectURI covers a local app's http://localhost redirect
// URI, which Singpass staging accepts: the callback must come back on exactly
// that http URI, for approvals and for cancellations.
func TestLoopbackHTTPRedirectURI(t *testing.T) {
	const local = "http://localhost:8080/login/callback"
	srv := startServer(t, singpasstest.Config{})
	k := newKeys(t)
	if err := srv.RegisterClient(singpasstest.Client{
		ID: "local-app", App: singpasstest.Login, RedirectURIs: []string{local},
		SigningKey: &k.sig.PublicKey, SigningKID: "sig-1", EncryptionKey: &k.enc.PublicKey, EncryptionKID: "enc-1",
	}); err != nil {
		t.Fatal(err)
	}
	c, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "local-app", RedirectURI: local, Scopes: []string{"openid"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}
	redirectURL, _, err := c.BeginLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Get(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, local+"?") {
		t.Fatalf("callback = %q, want it on %s", loc, local)
	}
	u, _ := url.Parse(loc)
	if _, err := c.Complete(context.Background(), u.RawQuery); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}
