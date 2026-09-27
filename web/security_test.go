package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
)

func TestSecureHeaders(t *testing.T) {
	h := SecureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	for k, want := range map[string]string{
		"Content-Security-Policy":    DefaultContentSecurityPolicy,
		"X-Frame-Options":            "DENY",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS sent over plain HTTP: %q", got)
	}

	for name, req := range map[string]*http.Request{
		"direct TLS": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.TLS = &tls.ConnectionState{}
			return r
		}(),
		"proxy (Cloud Run)": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			return r
		}(),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Errorf("%s: no HSTS over HTTPS", name)
		}
	}
}

func TestNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	NoStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestHandlersAreNoStore checks the helper's own login, callback and logout
// responses — which set cookies and carry codes — are never cached.
func TestHandlersAreNoStore(t *testing.T) {
	auth := &fakeAuth{redirectURL: "https://as.example/auth", state: "st-1", id: &singpass.Identity{Subject: "S"}}
	h, app, _ := newTestHandlers(auth)
	cases := map[string]struct {
		handler http.HandlerFunc
		req     *http.Request
	}{
		"login":    {h.Login(app), httptest.NewRequest(http.MethodGet, "/login/login", nil)},
		"callback": {h.Callback(app), callbackRequest("st-1", "st-1")},
		"logout":   {h.Logout(), httptest.NewRequest(http.MethodPost, "/login/logout", nil)},
	}
	for name, c := range cases {
		rec := httptest.NewRecorder()
		c.handler(rec, c.req)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", name, got)
		}
	}
}

func TestCookieNames(t *testing.T) {
	for _, tc := range []struct {
		name                string
		cfg                 CookieConfig
		wantSession, wantSt string
	}{
		{"insecure default", CookieConfig{}, "sid", "sp_state_"},
		{"secure default", CookieConfig{Secure: true}, "__Host-sid", "__Host-sp_state_"},
		{"DefaultCookieConfig(true)", DefaultCookieConfig(true), "__Host-sid", "__Host-sp_state_"},
		{"secure, custom path", CookieConfig{Secure: true, Path: "/app"}, "sid", "sp_state_"},
		{"custom names kept", CookieConfig{Secure: true, SessionName: "my_sid", StatePrefix: "my_st_"}, "my_sid", "my_st_"},
	} {
		got := tc.cfg.withDefaults()
		if got.SessionName != tc.wantSession || got.StatePrefix != tc.wantSt {
			t.Errorf("%s: names = %q, %q; want %q, %q", tc.name, got.SessionName, got.StatePrefix, tc.wantSession, tc.wantSt)
		}
	}
}
