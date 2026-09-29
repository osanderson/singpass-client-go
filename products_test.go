package singpass

import (
	"context"
	"log/slog"
	"strings"
	"testing"
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
	deps := Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc()), KeyCustody: KeyCustody{Durable: true}}
	_, err := NewLogin(context.Background(), LoginOptions{
		Environment: Production,
		Issuer:      testIssuer, // the fake; Production still sets the assurance
		ClientID:    "client-1", RedirectURI: "https://rp.example/callback", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "sig-1", EncryptionKey: newECKey(t), EncryptionKID: "enc-1",
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
		SigningKey: newECKey(t), SigningKID: "s", EncryptionKey: newECKey(t), EncryptionKID: "e",
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
