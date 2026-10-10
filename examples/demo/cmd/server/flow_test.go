package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/osanderson/singpass-client-go/examples/demo/internal/config"
)

// newMockApp builds the demo in mock mode, as DEMO_MOCK=1 runs it: every app
// enabled against in-process fake Singpass and Corppass servers.
func newMockApp(t *testing.T) http.Handler {
	t.Helper()
	t.Setenv("DEMO_MOCK", "1")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, closeApp, err := newApp(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeApp)
	return h
}

// browser drives the demo's handler as one browser: it keeps the cookies the
// demo sets, and talks to the fake servers over HTTP.
type browser struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, h http.Handler) *browser {
	return &browser{t: t, h: h, cookies: map[string]*http.Cookie{}}
}

// do sends a request for target (a path and query) to the demo.
func (b *browser) do(method, target string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "198.51.100.7:1234"
	if method == http.MethodPost {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

var (
	formAction = regexp.MustCompile(`<form method="post" action="([^"]+)">`)
	formHandle = regexp.MustCompile(`name="handle" value="([^"]+)"`)
	formScope  = regexp.MustCompile(`name="scope" value="([^"]*)"`)
	personaBtn = regexp.MustCompile(`<button name="subject" value="([^"]+)"`)
)

// signIn follows the demo's redirect to the fake server's sign-in page and
// submits it: as its first test user, or with decision "cancel". It returns
// the callback (a path and query) the fake server redirects back to.
func (b *browser) signIn(authURL, decision string) string {
	b.t.Helper()
	res, err := http.Get(authURL)
	if err != nil {
		b.t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	action, handle, scope := formAction.FindSubmatch(page), formHandle.FindSubmatch(page), formScope.FindSubmatch(page)
	if action == nil || handle == nil || scope == nil {
		b.t.Fatalf("no sign-in form at %s:\n%s", authURL, page)
	}
	form := url.Values{"handle": {string(handle[1])}, "scope": {string(scope[1])}}
	if decision == "cancel" {
		form.Set("decision", "cancel")
	} else {
		form.Set("subject", string(personaBtn.FindSubmatch(page)[1]))
	}
	base, _ := url.Parse(authURL)
	target, _ := base.Parse(string(action[1]))
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err = noFollow.PostForm(target.String(), form)
	if err != nil {
		b.t.Fatal(err)
	}
	res.Body.Close()
	// The fake answers its sign-in form with 303 (RFC 9700 §4.12).
	callback, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusSeeOther {
		b.t.Fatalf("sign-in: %s, Location %q", res.Status, res.Header.Get("Location"))
	}
	return callback.RequestURI()
}

// login runs a login to app through the fake server's sign-in page and
// returns the signed-in page.
func (b *browser) login(app string) string {
	b.t.Helper()
	rec := b.do(http.MethodGet, "/"+app+"/login")
	if rec.Code != http.StatusFound {
		b.t.Fatalf("/%s/login: %d", app, rec.Code)
	}
	rec = b.do(http.MethodGet, b.signIn(rec.Header().Get("Location"), ""))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		b.t.Fatalf("/%s/callback: %d to %q: %s", app, rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	rec = b.do(http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		b.t.Fatalf("profile page: %d", rec.Code)
	}
	return rec.Body.String()
}

// TestMockLogins logs in to each app in mock mode and checks the signed-in
// page shows the identity and, for Myinfo and Myinfo Business, the typed data.
func TestMockLogins(t *testing.T) {
	h := newMockApp(t)
	for _, tc := range []struct {
		app  string
		want []string
	}{
		{"login", []string{"Singpass Login", "Subject type", "Auth methods (amr)"}},
		{"mi", []string{"Myinfo", "person_info", "returned items are typed"}},
		{"mib", []string{"Myinfo Business", "entity_info", "Acting user", "Authorisations"}},
	} {
		t.Run(tc.app, func(t *testing.T) {
			b := newBrowser(t, h)
			page := b.login(tc.app)
			for _, w := range tc.want {
				if !strings.Contains(page, w) {
					t.Errorf("signed-in page lacks %q", w)
				}
			}
			if rec := b.do(http.MethodPost, "/"+tc.app+"/logout"); rec.Code != http.StatusFound {
				t.Fatalf("logout: %d", rec.Code)
			}
			if page := b.do(http.MethodGet, "/").Body.String(); !strings.Contains(page, "/"+tc.app+"/login") {
				t.Error("home page after logout doesn't offer the login again")
			}
		})
	}
}

// TestMockLoginFailures covers the pages for a login that doesn't complete: a
// cancelled one, a stale callback, and one over the rate limit.
func TestMockLoginFailures(t *testing.T) {
	h := newMockApp(t)

	t.Run("cancelled", func(t *testing.T) {
		b := newBrowser(t, h)
		rec := b.do(http.MethodGet, "/login/login")
		rec = b.do(http.MethodGet, b.signIn(rec.Header().Get("Location"), "cancel"))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "was declined") {
			t.Errorf("cancelled login: %d\n%s", rec.Code, rec.Body)
		}
	})

	t.Run("stale callback", func(t *testing.T) {
		b := newBrowser(t, h)
		rec := b.do(http.MethodGet, "/mi/callback?code=c&state=unknown")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "login expired") {
			t.Errorf("stale callback: %d\n%s", rec.Code, rec.Body)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		b := newBrowser(t, h)
		var rec *httptest.ResponseRecorder
		for range 11 {
			rec = b.do(http.MethodGet, "/mib/login")
		}
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Too many logins") {
			t.Errorf("11th login: %d\n%s", rec.Code, rec.Body)
		}
	})

	t.Run("unknown page", func(t *testing.T) {
		if rec := newBrowser(t, h).do(http.MethodGet, "/nope"); rec.Code != http.StatusNotFound {
			t.Errorf("/nope: %d", rec.Code)
		}
	})
}

// TestServe starts the demo on a free port, checks it answers, and shuts it
// down by cancelling its context.
func TestServe(t *testing.T) {
	t.Setenv("DEMO_MOCK", "1")
	t.Setenv("APP_ADDR", "127.0.0.1:0")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	listening := &signalWriter{match: "msg=listening", seen: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, &cfg, slog.New(slog.NewTextHandler(listening, nil))) }()
	select {
	case <-listening.seen:
	case err := <-done:
		t.Fatalf("serve returned before listening: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve after cancel = %v, want nil", err)
	}

	cfg.Addr = "not an address"
	if err := serve(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("serve on a bad address succeeded")
	}
}

// TestNewLoggerJSON checks the JSON log lines use the keys Cloud Logging reads:
// "severity" (with WARNING, not WARN) and "message".
func TestNewLoggerJSON(t *testing.T) {
	var buf strings.Builder
	newLogger(&buf, true).WithGroup("g").Warn("careful", "k", "v")
	newLogger(&buf, true).Info("hello")
	for _, want := range []string{`"severity":"WARNING"`, `"message":"careful"`, `"severity":"INFO"`, `"message":"hello"`, `"g":{"k":"v"}`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("JSON logs lack %s:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	newLogger(&buf, false).Info("hello")
	if !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("text log = %q", buf.String())
	}
}

// signalWriter closes seen the first time a write contains match.
type signalWriter struct {
	match string
	seen  chan struct{}
	once  sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.match) {
		w.once.Do(func() { close(w.seen) })
	}
	return len(p), nil
}
