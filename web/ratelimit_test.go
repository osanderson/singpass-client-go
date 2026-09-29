package web

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
)

// countingAuth counts BeginLogin calls: each is a request to Singpass.
type countingAuth struct{ begun int }

func (c *countingAuth) BeginLogin(context.Context) (string, string, error) {
	c.begun++
	return "https://as.example/authorize", "st", nil
}

func (c *countingAuth) Complete(context.Context, string, string) (*singpass.Identity, error) {
	return nil, errors.New("unused")
}

func loginFrom(h *Handlers, app *App, addr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/login/login", nil)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	h.Login(app)(rec, req)
	return rec
}

func TestLoginRateLimit(t *testing.T) {
	auth := &countingAuth{}
	app := &App{Name: "login", Auth: auth}
	h := New(Config{Apps: []*App{app}, LoginRateLimit: &LoginRateLimit{Burst: 2, Every: time.Minute}})
	now := time.Unix(1_700_000_000, 0)
	h.limiter.now = func() time.Time { return now }

	for i := range 2 {
		if rec := loginFrom(h, app, "198.51.100.7:1234"); rec.Code != http.StatusFound {
			t.Fatalf("login %d: status %d, want 302", i+1, rec.Code)
		}
	}
	rec := loginFrom(h, app, "198.51.100.7:5678") // same client, another port
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Errorf("over the limit: status %d, Retry-After %q; want 429, 60", rec.Code, rec.Header().Get("Retry-After"))
	}
	if auth.begun != 2 {
		t.Errorf("BeginLogin called %d times, want 2: a refused login must not reach Singpass", auth.begun)
	}
	if rec := loginFrom(h, app, "203.0.113.9:1234"); rec.Code != http.StatusFound {
		t.Errorf("another client: status %d, want 302", rec.Code)
	}

	now = now.Add(time.Minute)
	if rec := loginFrom(h, app, "198.51.100.7:1234"); rec.Code != http.StatusFound {
		t.Errorf("after Every: status %d, want 302", rec.Code)
	}
}

func TestLoginRateLimitKeyAndOnError(t *testing.T) {
	auth := &countingAuth{}
	app := &App{Name: "login", Auth: auth}
	var got error
	h := New(Config{
		Apps: []*App{app},
		LoginRateLimit: &LoginRateLimit{Burst: 1, Key: func(r *http.Request) string {
			return r.Header.Get("X-Client")
		}},
		OnError: func(w http.ResponseWriter, _ *http.Request, _ *App, err error) {
			got = err
			w.WriteHeader(http.StatusTeapot)
		},
	})
	req := func(client string) int {
		r := httptest.NewRequest(http.MethodGet, "/login/login", nil)
		r.Header.Set("X-Client", client)
		rec := httptest.NewRecorder()
		h.Login(app)(rec, r)
		return rec.Code
	}
	if req("a") != http.StatusFound || req("b") != http.StatusFound {
		t.Fatal("first login per key refused")
	}
	if code := req("a"); code != http.StatusTeapot || !errors.Is(got, ErrTooManyLogins) {
		t.Errorf("status %d, OnError got %v; want OnError with ErrTooManyLogins", code, got)
	}
}

func TestRateLimiterSweepsRefilledClients(t *testing.T) {
	rl := newRateLimiter(LoginRateLimit{Burst: 2, Every: time.Second})
	now := time.Unix(1_700_000_000, 0)
	rl.now = func() time.Time { return now }
	for _, addr := range []string{"192.0.2.1:1", "192.0.2.2:1"} {
		rl.allow(&http.Request{RemoteAddr: addr})
	}
	now = now.Add(time.Minute)
	rl.allow(&http.Request{RemoteAddr: "192.0.2.3:1"})
	if len(rl.buckets) != 1 {
		t.Errorf("%d buckets after the sweep, want only the new client's", len(rl.buckets))
	}
}

func TestSessionIdentityWarning(t *testing.T) {
	var logs bytes.Buffer
	New(Config{LoginSessions: NewMemoryLoginSessionStore(), Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if !strings.Contains(logs.String(), "SessionIdentity") {
		t.Errorf("no warning for a LoginSessions store without SessionIdentity; logs: %s", logs.String())
	}
	logs.Reset()
	New(Config{LoginSessions: NewMemoryLoginSessionStore(), SessionIdentity: MinimalIdentity, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if logs.Len() != 0 {
		t.Errorf("warned with SessionIdentity set: %s", logs.String())
	}
}
