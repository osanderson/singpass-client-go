package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/examples/demo/internal/config"
	"github.com/osanderson/singpass-client-go/keyfile"
	"github.com/osanderson/singpass-client-go/myinfo"
)

// TestFormatAmount covers the money-formatting gate: it separates thousands only
// when the label is money-ish AND the value is a plain number (integer part ≥ 4
// digits), preserving a decimal fraction (CPF balances carry cents), and leaves
// identifiers, postal codes, years and non-money labels untouched.
func TestFormatAmount(t *testing.T) {
	cases := []struct {
		label, value, want string
	}{
		{"CPF balances › MA (MediSave)", "74584.94", "74,584.94"}, // decimal preserved
		{"CPF balances › OA (Ordinary)", "89365.6", "89,365.60"},  // 1-digit fraction padded to cents
		{"Amount", "12345", "12,345"},                             // integer (no forced .00)
		{"Revenue", "1000000", "1,000,000"},
		{"Issued amount", "500", "500"},           // < 4 int digits: unchanged
		{"Amount", "999", "999"},                  // < 4 int digits: unchanged
		{"Employment", "45000.00", "45,000.00"},   // NOA income line, keyword "employment"
		{"Date of birth", "20240101", "20240101"}, // not money-ish: unchanged
		{"UINFIN", "S1234567D", "S1234567D"},      // non-numeric: unchanged
		{"Postal", "460123", "460123"},            // not money-ish: unchanged
		{"Amount", "1234.5.6", "1234.5.6"},        // malformed: unchanged
		{"Amount", "", ""},                        // empty: unchanged
	}
	for _, c := range cases {
		if got := formatAmount(c.label, c.value); got != c.want {
			t.Errorf("formatAmount(%q, %q) = %q, want %q", c.label, c.value, got, c.want)
		}
	}
}

func TestClaimString(t *testing.T) {
	m := map[string]any{"s": "text", "n": 42.5, "b": true, "o": map[string]any{}}
	for key, want := range map[string]string{"s": "text", "n": "42.5", "b": "true", "o": "", "absent": ""} {
		if got := claimString(m, key); got != want {
			t.Errorf("claimString(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestSourceKind(t *testing.T) {
	for s, want := range map[myinfo.Source]string{
		myinfo.SourceGovernmentVerified:   "gov",
		myinfo.SourceUserProvidedVerified: "userv",
		myinfo.SourceUserProvided:         "user",
		myinfo.SourceNotApplicable:        "na",
		myinfo.SourceUnknown:              "",
	} {
		if got := sourceKind(s); got != want {
			t.Errorf("sourceKind(%v) = %q, want %q", s, got, want)
		}
	}
}

func TestBuildAppErrors(t *testing.T) {
	ctx := context.Background()
	if _, _, err := buildApp(ctx, config.AppConfig{Name: "login", SigKeyPath: filepath.Join(t.TempDir(), "absent.pem")}, singpass.Dependencies{}); err == nil {
		t.Error("buildApp with a missing signing key succeeded")
	}
	key, err := keyfile.GenerateECKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildApp(ctx, config.AppConfig{Name: "other", SigKey: key, EncKey: key}, singpass.Dependencies{}); err == nil || !strings.Contains(err.Error(), "unknown app") {
		t.Errorf("buildApp for an unknown app: %v", err)
	}
}

// DEMO_MOCK_PERSONAS adds test users to mock mode's sign-in pages; a file that
// can't be read stops the demo starting.
func TestMockPersonasFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "personas.json")
	if err := os.WriteFile(path, []byte(`[{"name":"EXTRA USER","nric":"S9999999D"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEMO_MOCK_PERSONAS", path)
	h := newMockApp(t)
	b := newBrowser(t, h)
	res, err := http.Get(b.do(http.MethodGet, "/login/login").Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(page), "EXTRA USER") {
		t.Error("the sign-in page doesn't list the extra test user")
	}

	t.Setenv("DEMO_MOCK_PERSONAS", filepath.Join(t.TempDir(), "absent.json"))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newApp(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("newApp with an unreadable DEMO_MOCK_PERSONAS succeeded")
	}
}
