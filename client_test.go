package singpass

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
)

// testIssuer is the issuer the fake discovery server claims to be. New's
// fetcher refuses loopback and private addresses (SSRF protection) and does no
// DNS for an IP literal, so a public IP literal passes its checks without any
// network access; fakeIssuer's transport then dials the local httptest server
// whatever address is requested. The address itself is never contacted.
const testIssuer = "https://1.1.1.1"

// discoveryDoc is a Singpass-shaped discovery document: every algorithm the
// default suite needs, including the /userinfo ones Myinfo adds.
func discoveryDoc() map[string]any {
	return map[string]any{
		"issuer":                                   testIssuer,
		"authorization_endpoint":                   testIssuer + "/auth",
		"pushed_authorization_request_endpoint":    testIssuer + "/par",
		"token_endpoint":                           testIssuer + "/token",
		"jwks_uri":                                 testIssuer + "/jwks",
		"userinfo_endpoint":                        testIssuer + "/userinfo",
		"id_token_signing_alg_values_supported":    []string{"ES256"},
		"id_token_encryption_alg_values_supported": []string{"ECDH-ES+A256KW"},
		"id_token_encryption_enc_values_supported": []string{"A256CBC-HS512"},
		"userinfo_signing_alg_values_supported":    []string{"ES256"},
		"userinfo_encryption_alg_values_supported": []string{"ECDH-ES+A256KW"},
		"userinfo_encryption_enc_values_supported": []string{"A256GCM"},
	}
}

// fakeIssuer serves doc as the discovery document (and an empty JWKS) over TLS
// and returns an HTTP client that reaches it for testIssuer.
func fakeIssuer(t *testing.T, doc map[string]any) *http.Client {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write(body)
		case "/jwks":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/par":
			// Accept any pushed authorization request (RFC 9126 §2.2).
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":60}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		// httptest's certificate is issued for example.com.
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
	}}
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testKeyDeps(t *testing.T) Dependencies {
	t.Helper()
	km, err := NewKeyManager(newECKey(t), "sig-1")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewECDHDecrypter(newECKey(t), "enc-1")
	if err != nil {
		t.Fatal(err)
	}
	return Dependencies{Keys: km, Decryption: dec}
}

func baseOptions() Options {
	return Options{
		Name:        "test",
		Issuer:      testIssuer,
		ClientID:    "client-1",
		RedirectURI: "https://rp.example/callback",
		Scopes:      []string{"openid"},
	}
}

func TestNewRequiresKeysAndDecryption(t *testing.T) {
	full := testKeyDeps(t)
	for name, deps := range map[string]Dependencies{
		"no Keys":       {Decryption: full.Decryption},
		"no Decryption": {Keys: full.Keys},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(context.Background(), baseOptions(), deps); err == nil {
				t.Fatal("New succeeded, want error")
			}
		})
	}
}

// TestNewLoginConfiguresClient builds a Login client against the fake issuer
// and checks the Login-specific choices reach the Client.
func TestNewLoginConfiguresClient(t *testing.T) {
	sigKey, encKey := newECKey(t), newECKey(t)
	c, err := NewLogin(context.Background(), LoginOptions{
		Issuer:        testIssuer,
		ClientID:      "client-1",
		RedirectURI:   "https://rp.example/callback",
		Scopes:        []string{"openid"},
		AcrValues:     "  urn:a   urn:b ",
		SigningKey:    sigKey,
		SigningKID:    "sig-1",
		EncryptionKey: encKey,
		EncryptionKID: "enc-1",
	}, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc())})
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}

	if c.name != "login" {
		t.Errorf("name = %q, want default %q", c.name, "login")
	}
	if c.fetchUserInfo {
		t.Error("Login client would call /userinfo")
	}
	if got, ok := extension.Get(c.extensions, authContextTypeExt); !ok || got != DefaultAuthContextType {
		t.Errorf("authentication_context_type = %q, %v; want %q", got, ok, DefaultAuthContextType)
	}
	if want := []string{"urn:a", "urn:b"}; !reflect.DeepEqual(c.acrValues, want) {
		t.Errorf("acrValues = %q, want %q", c.acrValues, want)
	}

	jwks, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	for _, kid := range []string{`"sig-1"`, `"enc-1"`} {
		if !strings.Contains(string(jwks), kid) {
			t.Errorf("public JWKS missing kid %s:\n%s", kid, jwks)
		}
	}
	if strings.Contains(string(jwks), `"d"`) {
		t.Errorf("public JWKS contains private key material:\n%s", jwks)
	}
}

func TestNewMyinfoConfiguresClient(t *testing.T) {
	c, err := NewMyinfo(context.Background(), MyinfoOptions{
		Issuer:        testIssuer,
		ClientID:      "client-1",
		RedirectURI:   "https://rp.example/callback",
		Scopes:        []string{"openid", "uinfin"},
		SigningKey:    newECKey(t),
		SigningKID:    "sig-1",
		EncryptionKey: newECKey(t),
		EncryptionKID: "enc-1",
	}, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc())})
	if err != nil {
		t.Fatalf("NewMyinfo: %v", err)
	}
	if !c.fetchUserInfo {
		t.Error("Myinfo client would not call /userinfo")
	}
	if _, ok := extension.Get(c.extensions, authContextTypeExt); ok {
		t.Error("Myinfo client sends authentication_context_type (Singpass rejects it)")
	}
	if c.acrValues != nil {
		t.Errorf("acrValues = %q, want none", c.acrValues)
	}
}

// TestNewFetchUserInfoRequiresEndpoint checks the fail-fast for an issuer that
// advertises no userinfo_endpoint.
func TestNewFetchUserInfoRequiresEndpoint(t *testing.T) {
	doc := discoveryDoc()
	delete(doc, "userinfo_endpoint")
	deps := testKeyDeps(t)
	deps.HTTPClient = fakeIssuer(t, doc)
	opts := baseOptions()
	opts.FetchUserInfo = true

	_, err := New(context.Background(), opts, deps)
	if err == nil || !strings.Contains(err.Error(), "userinfo_endpoint") {
		t.Fatalf("New err = %v, want userinfo_endpoint error", err)
	}

	// The same issuer is fine when /userinfo is not wanted.
	opts.FetchUserInfo = false
	deps.HTTPClient = fakeIssuer(t, doc)
	if _, err := New(context.Background(), opts, deps); err != nil {
		t.Fatalf("New without FetchUserInfo: %v", err)
	}
}

// TestNewFetchUserInfoDeclaresUserInfoAlgorithms shows the default suite adds
// the /userinfo algorithms when FetchUserInfo is set: an issuer that does not
// advertise them is refused at startup.
func TestNewFetchUserInfoDeclaresUserInfoAlgorithms(t *testing.T) {
	doc := discoveryDoc()
	delete(doc, "userinfo_signing_alg_values_supported")
	delete(doc, "userinfo_encryption_alg_values_supported")
	delete(doc, "userinfo_encryption_enc_values_supported")
	deps := testKeyDeps(t)
	deps.HTTPClient = fakeIssuer(t, doc)
	opts := baseOptions()
	opts.FetchUserInfo = true

	if _, err := New(context.Background(), opts, deps); err == nil || !strings.Contains(err.Error(), "does not support ES256 for userinfo") {
		t.Fatalf("New err = %v, want unsupported userinfo algorithm error", err)
	}
}

// TestNewAlgorithmsOverrideUsedVerbatim checks a caller-supplied Algorithms is
// not augmented with the /userinfo algorithms: the same issuer that refuses the
// default suite above accepts an override that declares none.
func TestNewAlgorithmsOverrideUsedVerbatim(t *testing.T) {
	doc := discoveryDoc()
	delete(doc, "userinfo_signing_alg_values_supported")
	delete(doc, "userinfo_encryption_alg_values_supported")
	delete(doc, "userinfo_encryption_enc_values_supported")
	deps := testKeyDeps(t)
	deps.HTTPClient = fakeIssuer(t, doc)
	override := resolveAlgorithms(nil, false)
	deps.Algorithms = &override
	opts := baseOptions()
	opts.FetchUserInfo = true

	if _, err := New(context.Background(), opts, deps); err != nil {
		t.Fatalf("New with Algorithms override: %v", err)
	}
}

func TestResolveAlgorithms(t *testing.T) {
	login := resolveAlgorithms(nil, false)
	if login.IDTokenKeyManagement != fapi.ECDHESA256KW || login.IDTokenContentEncryption != fapi.A256CBCHS512 {
		t.Errorf("id_token encryption = %v/%v, want ECDH-ES+A256KW/A256CBC-HS512", login.IDTokenKeyManagement, login.IDTokenContentEncryption)
	}
	if login.UserInfo != 0 || login.UserInfoKeyManagement != 0 || login.UserInfoContentEncryption != 0 {
		t.Errorf("Login suite declares /userinfo algorithms: %+v", login)
	}

	myinfo := resolveAlgorithms(nil, true)
	if myinfo.UserInfo != fapi.ES256 || myinfo.UserInfoKeyManagement != fapi.ECDHESA256KW || myinfo.UserInfoContentEncryption != fapi.A256GCM {
		t.Errorf("Myinfo /userinfo algorithms = %v/%v/%v, want ES256/ECDH-ES+A256KW/A256GCM",
			myinfo.UserInfo, myinfo.UserInfoKeyManagement, myinfo.UserInfoContentEncryption)
	}

	override := client.Algorithms{IDToken: fapi.PS256}
	if got := resolveAlgorithms(&override, true); !reflect.DeepEqual(got, override) {
		t.Errorf("override = %+v, want verbatim %+v", got, override)
	}
}

// encKID reports the kid of the key a Decrypter would publish, which identifies
// which key source ensureKeyDeps chose.
func encKID(t *testing.T, d keys.Decrypter) string {
	t.Helper()
	info, err := d.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	return info.KeyID
}

func sigKID(t *testing.T, km keys.KeyManager) string {
	t.Helper()
	info, err := km.PublicKey(context.Background(), keys.ClientAuthentication, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return info.KeyID
}

// TestEnsureKeyDepsPrecedence pins the documented order: injected
// Dependencies win outright; otherwise an EncryptionAgreer beats the in-memory
// EncryptionKey (and EncryptionKID is not used with it).
func TestEnsureKeyDepsPrecedence(t *testing.T) {
	sig, enc := newECKey(t), newECKey(t)
	agreerKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agreer, err := keys.NewInMemoryECDH(agreerKey, "agreer-kid")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("injected deps win", func(t *testing.T) {
		injected := testKeyDeps(t)
		got, err := ensureKeyDeps(injected, sig, "opt-sig", enc, agreer, "opt-enc")
		if err != nil {
			t.Fatal(err)
		}
		if got.Keys != injected.Keys || got.Decryption != injected.Decryption {
			t.Error("injected Keys/Decryption were replaced")
		}
	})

	t.Run("agreer beats in-memory key", func(t *testing.T) {
		got, err := ensureKeyDeps(Dependencies{}, sig, "opt-sig", enc, agreer, "opt-enc")
		if err != nil {
			t.Fatal(err)
		}
		if kid := sigKID(t, got.Keys); kid != "opt-sig" {
			t.Errorf("signing kid = %q, want opt-sig", kid)
		}
		if kid := encKID(t, got.Decryption); kid != "agreer-kid" {
			t.Errorf("encryption kid = %q, want agreer-kid (EncryptionKID must be ignored)", kid)
		}
	})

	t.Run("in-memory key when no agreer", func(t *testing.T) {
		got, err := ensureKeyDeps(Dependencies{}, sig, "opt-sig", enc, nil, "opt-enc")
		if err != nil {
			t.Fatal(err)
		}
		if kid := encKID(t, got.Decryption); kid != "opt-enc" {
			t.Errorf("encryption kid = %q, want opt-enc", kid)
		}
	})

	t.Run("missing key material is an error", func(t *testing.T) {
		if _, err := ensureKeyDeps(Dependencies{}, nil, "", enc, nil, "opt-enc"); err == nil {
			t.Error("no signing key: want error")
		}
		if _, err := ensureKeyDeps(Dependencies{}, sig, "opt-sig", nil, nil, ""); err == nil {
			t.Error("no encryption key or agreer: want error")
		}
	})
}

// TestCompleteStaleStateIsLoginExpired checks that ErrLoginExpired from the
// session store survives FAPIgo's and Complete's error wrapping, so a caller's
// errors.Is check works on what Complete returns.
func TestCompleteStaleStateIsLoginExpired(t *testing.T) {
	deps := testKeyDeps(t)
	deps.HTTPClient = fakeIssuer(t, discoveryDoc())
	c, err := New(context.Background(), baseOptions(), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	q := url.Values{"state": {"never-issued"}, "code": {"x"}, "iss": {testIssuer}}
	_, err = c.Complete(context.Background(), q.Encode())
	if !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("Complete err = %v, want ErrLoginExpired", err)
	}
}
