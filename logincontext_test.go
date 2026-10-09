package singpass

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

func newTestLogin(t *testing.T, o LoginOptions) (*Client, error) {
	t.Helper()
	o.Issuer, o.ClientID, o.RedirectURI, o.Scopes = testIssuer, "client-1", "https://rp.example/callback", []string{"openid"}
	o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID = newECKey(t), "sig-1", newECKey(t), "enc-1"
	return NewLogin(context.Background(), o, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc())})
}

func extValue(t *testing.T, ext extension.Values, def extension.Definition[string]) string {
	t.Helper()
	v, _ := extension.Get(ext, def)
	return v
}

func TestLoginContextParameters(t *testing.T) {
	c, err := newTestLogin(t, LoginOptions{
		AuthContextMessage: "Log in to Example Bank",
		AppClaimedHTTPS:    true,
		AppLaunchURL:       "https://app.example/singpass-return",
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := c.loginExtensions(LoginContext{})
	if err != nil {
		t.Fatal(err)
	}
	for def, want := range map[*extension.Definition[string]]string{
		&authContextTypeExt:      DefaultAuthContextType,
		&authContextMessageExt:   "Log in to Example Bank",
		&redirectURIHTTPSTypeExt: "app_claimed_https",
		&appLaunchURLExt:         "https://app.example/singpass-return",
	} {
		if got := extValue(t, ext, *def); got != want {
			t.Errorf("%s = %q, want %q", def.Name, got, want)
		}
	}

	// A per-login context overrides the client's, for that login only.
	ext, err = c.loginExtensions(LoginContext{Type: "APP_AUTHENTICATION_OTHER", Message: "Approve your transfer of $500"})
	if err != nil {
		t.Fatal(err)
	}
	if extValue(t, ext, authContextTypeExt) != "APP_AUTHENTICATION_OTHER" || extValue(t, ext, authContextMessageExt) != "Approve your transfer of $500" {
		t.Errorf("override not applied: %v", ext)
	}
	if _, _, err := c.BeginLoginWith(context.Background(), LoginContext{Message: "Pay <script>"}); err == nil || !strings.Contains(err.Error(), "AuthContextMessage") {
		t.Errorf("invalid per-login message: %v", err)
	}
	if _, _, err := c.BeginLoginWith(context.Background(), LoginContext{Message: "Approve your transfer"}); err != nil {
		t.Errorf("BeginLoginWith: %v", err)
	}
}

func TestLoginContextValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		o    LoginOptions
		want string
	}{
		"message too long":       {LoginOptions{AuthContextMessage: strings.Repeat("x", 101)}, "at most 100"},
		"message with backslash": {LoginOptions{AuthContextMessage: `a\b`}, "printable ASCII"},
		"message with backtick":  {LoginOptions{AuthContextMessage: "a`b"}, "printable ASCII"},
		"message non-ASCII":      {LoginOptions{AuthContextMessage: "café"}, "printable ASCII"},
		"http app launch URL":    {LoginOptions{AppLaunchURL: "http://app.example/return"}, "AppLaunchURL"},
	} {
		if _, err := newTestLogin(t, tc.o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
	if _, err := newTestLogin(t, LoginOptions{AuthContextMessage: strings.Repeat("x", 100)}); err != nil {
		t.Errorf("100-character message refused: %v", err)
	}

	// Myinfo clients take no login context.
	c, err := NewMyinfo(context.Background(), MyinfoOptions{
		Issuer: testIssuer, ClientID: "client-1", RedirectURI: "https://rp.example/callback", Scopes: []string{"openid"},
		SigningKey: newECKey(t), SigningKID: "sig-1", EncryptionKey: newECKey(t), EncryptionKID: "enc-1",
	}, Dependencies{HTTPClient: fakeIssuer(t, discoveryDoc())})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.BeginLoginWith(context.Background(), LoginContext{Message: "hi"}); err == nil || !strings.Contains(err.Error(), "only for Singpass Login") {
		t.Errorf("Myinfo login context: %v", err)
	}
	o := baseOptions()
	o.AuthContextMessage = "hi"
	if _, err := New(context.Background(), o, testKeyDeps(t)); err == nil || !strings.Contains(err.Error(), "only for Singpass Login") {
		t.Errorf("message without AuthContextType: %v", err)
	}
}

// TestPARExtensionDefinitionsAreValid runs the Singpass PAR extension
// definitions through FAPIgo's own validation of a definition, so a field
// FAPIgo starts requiring (as Sensitivity became in v0.52.0) is caught here.
func TestPARExtensionDefinitionsAreValid(t *testing.T) {
	if _, err := extension.NewRegistry(authContextTypeExt, authContextMessageExt, redirectURIHTTPSTypeExt, appLaunchURLExt); err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	for _, d := range []extension.Definition[string]{authContextTypeExt, authContextMessageExt, redirectURIHTTPSTypeExt, appLaunchURLExt} {
		if d.Sensitivity != extension.NotSensitive {
			t.Errorf("%s: Sensitivity = %v, want NotSensitive: none is secret", d.Name, d.Sensitivity)
		}
	}
}
