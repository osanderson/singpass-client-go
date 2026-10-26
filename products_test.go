package singpass

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
)

func TestEnvironmentIssuers(t *testing.T) {
	for _, tc := range []struct {
		env                Environment
		singpass, corppass string
	}{
		{Staging, StagingSingpassIssuer, StagingCorppassIssuer},
		{Production, ProductionSingpassIssuer, ProductionCorppassIssuer},
	} {
		sp, cp := tc.env.issuers()
		if sp != tc.singpass || cp != tc.corppass {
			t.Errorf("%v issuers = %q, %q; want %q, %q", tc.env, sp, cp, tc.singpass, tc.corppass)
		}
	}
}

func TestEnvironmentAssuranceDefault(t *testing.T) {
	if got := Production.forEnvironment(Dependencies{}).Assurance; got != AssuranceProduction {
		t.Errorf("Production default assurance = %v, want AssuranceProduction", got)
	}
	if got := Staging.forEnvironment(Dependencies{}).Assurance; got != 0 {
		t.Errorf("Staging changed assurance to %v", got)
	}
	// An explicit choice is kept.
	if got := Production.forEnvironment(Dependencies{Assurance: AssuranceDevelopment}).Assurance; got != AssuranceDevelopment {
		t.Errorf("Production overrode explicit assurance: %v", got)
	}
}

// TestProductionRefusesInMemorySessions checks the point of Environment:
// Production with the default (in-memory) session store fails at construction
// instead of running non-durably in production.
func TestProductionRefusesInMemorySessions(t *testing.T) {
	allowFakeHTTPInProduction(t)
	deps := Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc()), KeyCustody: KeyCustody{Durable: true}}
	_, err := NewLogin(context.Background(), LoginOptions{
		Environment: Production,
		Issuer:      testIssuer, // the fake; Production still sets the assurance
		ClientID:    "client-1", RedirectURI: "https://rp.example/callback", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "sig-1", EncryptionKey: newECKey(t), EncryptionKID: "enc-1", DPoPKey: newECKey(t),
	}, deps)
	if err == nil {
		t.Fatal("NewLogin succeeded with Production and the in-memory session store")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "session") {
		t.Errorf("err = %v, want a session-store assurance error", err)
	}
}

func TestProductionRequiresKeyCustody(t *testing.T) {
	_, err := NewLogin(context.Background(), LoginOptions{
		Environment: Production, Issuer: testIssuer,
		ClientID: "c", RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "s", EncryptionKey: newECKey(t), EncryptionKID: "e", DPoPKey: newECKey(t),
	}, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc())})
	if err == nil || !strings.Contains(err.Error(), "KeyCustody") {
		t.Fatalf("err = %v, want a KeyCustody error", err)
	}
}

func TestProductionRefusesDebug(t *testing.T) {
	_, err := NewLogin(context.Background(), LoginOptions{
		Environment: Production, Issuer: testIssuer,
		ClientID: "c", RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "s", EncryptionKey: newECKey(t), EncryptionKID: "e",
	}, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc()), KeyCustody: KeyCustody{Durable: true}, Debug: true})
	if err == nil || !strings.Contains(err.Error(), "Debug") {
		t.Fatalf("err = %v, want a Debug error", err)
	}
}

// A production issuer with development assurance is allowed, as an explicit
// choice, but logged.
func TestProductionIssuerWithoutProductionAssuranceWarns(t *testing.T) {
	var logs strings.Builder
	_, _ = NewLogin(context.Background(), LoginOptions{
		Environment: Production,
		ClientID:    "c", RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "s", EncryptionKey: newECKey(t), EncryptionKID: "e",
	}, Dependencies{
		Assurance:  AssuranceDevelopment,
		HTTPClient: fakeIssuer(t, discoveryDoc()),
		Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if !strings.Contains(logs.String(), "production issuer without AssuranceProduction") {
		t.Errorf("no warning logged; logs:\n%s", logs.String())
	}
}

// Under production, a DPoP key generated per process is refused: a login
// could only finish on the instance, and process, that started it.
func TestProductionRequiresSharedDPoPKey(t *testing.T) {
	opts := LoginOptions{
		Environment: Production, Issuer: testIssuer,
		ClientID: "c", RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "s", EncryptionKey: newECKey(t), EncryptionKID: "e",
	}
	deps := Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc()), KeyCustody: KeyCustody{Durable: true}}
	if _, err := NewLogin(context.Background(), opts, deps); err == nil || !strings.Contains(err.Error(), "DPoP key shared by every instance") {
		t.Errorf("per-process DPoP key: err = %v", err)
	}
	opts.DPoPKey = newECKey(t)
	if _, err := NewLogin(context.Background(), opts, deps); err != nil && strings.Contains(err.Error(), "DPoP") {
		t.Errorf("shared DPoP key refused: %v", err)
	}
}

func TestDPoPKeyMisuse(t *testing.T) {
	if _, err := NewKeyManagerWithDPoP(newECKey(t), "s", nil); err == nil || !strings.Contains(err.Error(), "DPoP key is nil") {
		t.Errorf("nil DPoP key: %v", err)
	}
	km, err := NewKeyManager(newECKey(t), "s")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ensureKeyDeps(context.Background(), Dependencies{Keys: km}, keyMaterial{dpop: newECKey(t)})
	if err == nil || !strings.Contains(err.Error(), "DPoPKey can't be combined with Dependencies.Keys") {
		t.Errorf("DPoPKey with Dependencies.Keys: %v", err)
	}
	shared, err := NewKeyManagerWithDPoP(newECKey(t), "s", newECKey(t))
	if err != nil || shared.(*rotatingKeyManager).ephemeralDPoP || !km.(*rotatingKeyManager).ephemeralDPoP {
		t.Errorf("ephemeralDPoP: shared %v, generated %v (%v)", shared.(*rotatingKeyManager).ephemeralDPoP, km.(*rotatingKeyManager).ephemeralDPoP, err)
	}
}

// allowFakeHTTPInProduction lets a production test reach the checks after
// discovery through fakeIssuer's in-memory transport, which isn't
// fapihttp.NewClient's.
func allowFakeHTTPInProduction(t *testing.T) {
	saved := checkProductionHTTPClient
	checkProductionHTTPClient = func(*http.Client) error { return nil }
	t.Cleanup(func() { checkProductionHTTPClient = saved })
}

// Under production, a supplied HTTPClient must be fapihttp.NewClient's,
// intact and without a loopback exception, and is refused before discovery
// uses it.
func TestProductionHTTPClientMustBeHardened(t *testing.T) {
	hardened, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	loopbackCfg := fapihttp.RecommendedTransportConfig()
	loopbackCfg.AllowLoopbackHosts = true
	loopback, err := fapihttp.NewClient(loopbackCfg)
	if err != nil {
		t.Fatal(err)
	}
	proxied := *hardened
	proxied.Transport = hardened.Transport.(*http.Transport).Clone()
	longer := *hardened
	longer.Timeout = time.Minute

	for name, tc := range map[string]struct {
		c    *http.Client
		want string // "" = accepted
	}{
		"plain":         {&http.Client{}, "must come from fapihttp.NewClient"},
		"cloned":        {&proxied, "must come from fapihttp.NewClient"},
		"loopback":      {loopback, "allows loopback addresses"},
		"NewClient's":   {hardened, ""},
		"copy, timeout": {&longer, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkProductionHTTPClient(tc.c)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}

	_, err = NewLogin(context.Background(), LoginOptions{
		Environment: Production, Issuer: testIssuer,
		ClientID: "c", RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "s", EncryptionKey: newECKey(t), EncryptionKID: "e", DPoPKey: newECKey(t),
	}, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc()), KeyCustody: KeyCustody{Durable: true}})
	if err == nil || !strings.Contains(err.Error(), "Dependencies.HTTPClient must come from fapihttp.NewClient") {
		t.Errorf("NewLogin err = %v, want the HTTPClient refused", err)
	}
}

// The default HTTP client is fapihttp.NewClient's, with only the loopback
// and private-host exceptions Dependencies asks for.
func TestDefaultHTTPClientIsHardened(t *testing.T) {
	for name, tc := range map[string]struct {
		deps     Dependencies
		loopback bool
		private  []string
	}{
		"default":             {Dependencies{HTTPTimeout: time.Second}, false, nil},
		"AllowLoopbackHTTP":   {Dependencies{HTTPTimeout: time.Second, AllowLoopbackHTTP: true}, true, nil},
		"AllowedPrivateHosts": {Dependencies{HTTPTimeout: time.Second, AllowedPrivateHosts: []string{"singpass"}}, false, []string{"singpass"}},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := defaultHTTPClient(tc.deps)
			if err != nil {
				t.Fatal(err)
			}
			h, ok := fapihttp.HardeningOf(c)
			if !ok {
				t.Fatal("default HTTP client isn't fapihttp.NewClient's")
			}
			if h.AllowsLoopback() != tc.loopback || !slices.Equal(h.AllowedPrivateHosts(), tc.private) {
				t.Errorf("loopback %v, private hosts %v; want %v, %v", h.AllowsLoopback(), h.AllowedPrivateHosts(), tc.loopback, tc.private)
			}
			if c.Timeout != time.Second {
				t.Errorf("Timeout = %v, want HTTPTimeout", c.Timeout)
			}
		})
	}
}

// TestProductionRequiresAuthorizationResponseIss checks the RFC 9207 baseline:
// production requires "iss" in the callback even before discovery raises it,
// as FAPIgo refuses anything less there, while development tolerates a test
// issuer that leaves it out.
func TestProductionRequiresAuthorizationResponseIss(t *testing.T) {
	for _, tc := range []struct {
		assurance AssuranceLevel
		want      client.AuthorizationResponseIssPolicy
	}{
		{0, client.TolerateAbsentAuthorizationResponseIss},
		{AssuranceDevelopment, client.TolerateAbsentAuthorizationResponseIss},
		{AssuranceProduction, client.RequireAuthorizationResponseIss},
	} {
		cfg := engineConfig(baseOptions(), Dependencies{Assurance: tc.assurance}, fapi.URL{}, client.DiscoveredMetadata{})
		if cfg.AuthorizationResponseIssPolicy != tc.want {
			t.Errorf("assurance %v: AuthorizationResponseIssPolicy = %v, want %v", tc.assurance, cfg.AuthorizationResponseIssPolicy, tc.want)
		}
	}
}
