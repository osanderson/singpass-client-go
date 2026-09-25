package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
)

// fakeAuth is a scriptable authClient. It records whether Complete was reached,
// so tests can assert the state check short-circuits before the FAPI exchange.
type fakeAuth struct {
	redirectURL, state string
	beginErr           error

	id          *singpass.Identity
	completeErr error
	completed   bool
}

func (f *fakeAuth) BeginLogin(context.Context) (string, string, error) {
	return f.redirectURL, f.state, f.beginErr
}

func (f *fakeAuth) Complete(context.Context, string) (*singpass.Identity, error) {
	f.completed = true
	return f.id, f.completeErr
}

// outcome records which callback the handlers invoked.
type outcome struct {
	authenticated *singpass.Identity
	denied        *singpass.DeniedError
	err           error
}

func newTestHandlers(auth *fakeAuth) (*Handlers, *App, *outcome) {
	app := &App{Name: "login", Title: "Singpass", Auth: auth, JWKS: []byte(`{"keys":[]}`)}
	got := &outcome{}
	h := New(Config{
		Apps: []*App{app},
		OnAuthenticated: func(w http.ResponseWriter, _ *http.Request, _ *App, id *singpass.Identity) {
			got.authenticated = id
			w.WriteHeader(http.StatusNoContent)
		},
		OnDenied: func(w http.ResponseWriter, _ *http.Request, _ *App, d *singpass.DeniedError) {
			got.denied = d
			w.WriteHeader(http.StatusNoContent)
		},
		OnError: func(w http.ResponseWriter, _ *http.Request, _ *App, err error) {
			got.err = err
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	return h, app, got
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func callbackRequest(state, cookieState string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/login/callback?code=c&state="+state, nil)
	if cookieState != "" {
		req.AddCookie(&http.Cookie{Name: "sp_state_login", Value: cookieState})
	}
	return req
}

func TestLoginSetsStateCookieAndRedirects(t *testing.T) {
	auth := &fakeAuth{redirectURL: "https://as.example/authorize?request_uri=x", state: "st-1"}
	h, app, _ := newTestHandlers(auth)

	rec := httptest.NewRecorder()
	h.Login(app)(rec, httptest.NewRequest(http.MethodGet, "/login/login", nil))

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != auth.redirectURL {
		t.Fatalf("got %d Location=%q, want 302 to %q", rec.Code, rec.Header().Get("Location"), auth.redirectURL)
	}
	c := cookieNamed(rec, "sp_state_login")
	if c == nil || c.Value != "st-1" || !c.HttpOnly {
		t.Fatalf("state cookie = %+v, want HttpOnly sp_state_login=st-1", c)
	}
}

func TestLoginBeginErrorRoutesToOnError(t *testing.T) {
	auth := &fakeAuth{beginErr: errors.New("par failed")}
	h, app, got := newTestHandlers(auth)

	rec := httptest.NewRecorder()
	h.Login(app)(rec, httptest.NewRequest(http.MethodGet, "/login/login", nil))

	if got.err == nil || cookieNamed(rec, "sp_state_login") != nil {
		t.Fatalf("OnError err=%v, state cookie set=%v; want error and no cookie", got.err, cookieNamed(rec, "sp_state_login") != nil)
	}
}

// TestCallbackStateMismatch covers every way the state binding can fail: each
// must reach OnError, clear the state cookie, and never call Complete.
func TestCallbackStateMismatch(t *testing.T) {
	cases := map[string]*http.Request{
		"no cookie":        callbackRequest("st-1", ""),
		"different value":  callbackRequest("st-1", "st-2"),
		"no state in URL":  callbackRequest("", "st-1"),
		"empty everywhere": callbackRequest("", ""),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			auth := &fakeAuth{id: &singpass.Identity{Subject: "S"}}
			h, app, got := newTestHandlers(auth)

			rec := httptest.NewRecorder()
			h.Callback(app)(rec, req)

			if auth.completed {
				t.Error("Complete was called despite state mismatch")
			}
			if got.err == nil || got.authenticated != nil {
				t.Errorf("outcome = %+v, want OnError only", got)
			}
			if c := cookieNamed(rec, "sp_state_login"); c == nil || c.MaxAge >= 0 {
				t.Errorf("state cookie = %+v, want cleared", c)
			}
			if cookieNamed(rec, "sid") != nil {
				t.Error("session cookie set despite state mismatch")
			}
		})
	}
}

func TestCallbackDeniedRoutesToOnDenied(t *testing.T) {
	denied := &singpass.DeniedError{Code: "access_denied", Description: "user cancelled"}
	auth := &fakeAuth{completeErr: denied}
	h, app, got := newTestHandlers(auth)

	rec := httptest.NewRecorder()
	h.Callback(app)(rec, callbackRequest("st-1", "st-1"))

	if got.denied != denied || got.err != nil {
		t.Fatalf("outcome = %+v, want OnDenied with %v", got, denied)
	}
	if cookieNamed(rec, "sid") != nil {
		t.Error("session cookie set for a denied login")
	}
}

// TestCallbackWrappedDeniedRoutesToOnDenied checks errors.As is used, so a
// DeniedError wrapped by a caller's own client still counts as a denial.
func TestCallbackWrappedDeniedRoutesToOnDenied(t *testing.T) {
	denied := &singpass.DeniedError{Code: "login_required"}
	auth := &fakeAuth{completeErr: errors.Join(errors.New("wrapped"), denied)}
	h, app, got := newTestHandlers(auth)

	h.Callback(app)(httptest.NewRecorder(), callbackRequest("st-1", "st-1"))

	if got.denied != denied {
		t.Fatalf("outcome = %+v, want OnDenied", got)
	}
}

func TestCallbackErrorRoutesToOnError(t *testing.T) {
	auth := &fakeAuth{completeErr: errors.New("token exchange failed")}
	h, app, got := newTestHandlers(auth)

	rec := httptest.NewRecorder()
	h.Callback(app)(rec, callbackRequest("st-1", "st-1"))

	if got.err == nil || got.denied != nil || got.authenticated != nil {
		t.Fatalf("outcome = %+v, want OnError only", got)
	}
	if cookieNamed(rec, "sid") != nil {
		t.Error("session cookie set for a failed login")
	}
}

func TestCallbackSuccessCreatesSession(t *testing.T) {
	want := &singpass.Identity{App: "login", Subject: "S1234567D"}
	auth := &fakeAuth{id: want}
	h, app, got := newTestHandlers(auth)

	rec := httptest.NewRecorder()
	h.Callback(app)(rec, callbackRequest("st-1", "st-1"))

	if got.authenticated != want {
		t.Fatalf("OnAuthenticated identity = %v, want %v", got.authenticated, want)
	}
	if c := cookieNamed(rec, "sp_state_login"); c == nil || c.MaxAge >= 0 {
		t.Errorf("state cookie = %+v, want cleared after use", c)
	}
	sid := cookieNamed(rec, "sid")
	if sid == nil || sid.Value == "" || !sid.HttpOnly {
		t.Fatalf("session cookie = %+v, want HttpOnly sid", sid)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sid)
	if id, ok := h.CurrentIdentity(req); !ok || id != want {
		t.Fatalf("CurrentIdentity = %v, %v; want the logged-in identity", id, ok)
	}
}

// TestCallbackReplacesPreviousSession checks a second login drops the session
// the browser already held instead of leaving it live alongside the new one.
func TestCallbackReplacesPreviousSession(t *testing.T) {
	auth := &fakeAuth{id: &singpass.Identity{Subject: "S"}}
	h, app, _ := newTestHandlers(auth)

	oldSID := h.sessions.Create(&singpass.Identity{Subject: "old"}, h.cookies.SessionTTL)
	req := callbackRequest("st-1", "st-1")
	req.AddCookie(&http.Cookie{Name: "sid", Value: oldSID})

	rec := httptest.NewRecorder()
	h.Callback(app)(rec, req)

	if _, ok := h.sessions.Get(oldSID); ok {
		t.Error("previous session still valid after re-login")
	}
	if c := cookieNamed(rec, "sid"); c == nil || c.Value == oldSID {
		t.Errorf("session cookie = %+v, want a fresh sid", c)
	}
}

func TestCurrentIdentityWithoutSession(t *testing.T) {
	h, _, _ := newTestHandlers(&fakeAuth{})

	if _, ok := h.CurrentIdentity(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Error("CurrentIdentity ok with no cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "forged"})
	if _, ok := h.CurrentIdentity(req); ok {
		t.Error("CurrentIdentity ok for an unknown sid")
	}
}

func TestLogout(t *testing.T) {
	newLoggedIn := func() (*Handlers, string) {
		h, _, _ := newTestHandlers(&fakeAuth{})
		return h, h.sessions.Create(&singpass.Identity{Subject: "S"}, h.cookies.SessionTTL)
	}

	t.Run("POST same-origin logs out", func(t *testing.T) {
		h, sid := newLoggedIn()
		req := httptest.NewRequest(http.MethodPost, "/login/logout", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: "sid", Value: sid})

		rec := httptest.NewRecorder()
		h.Logout()(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if _, ok := h.sessions.Get(sid); ok {
			t.Error("session still valid after logout")
		}
		if c := cookieNamed(rec, "sid"); c == nil || c.MaxAge >= 0 {
			t.Errorf("sid cookie = %+v, want cleared", c)
		}
	})

	t.Run("GET is refused", func(t *testing.T) {
		h, sid := newLoggedIn()
		req := httptest.NewRequest(http.MethodGet, "/login/logout", nil)
		req.AddCookie(&http.Cookie{Name: "sid", Value: sid})

		rec := httptest.NewRecorder()
		h.Logout()(rec, req)

		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("status = %d Allow=%q, want 405 Allow=POST", rec.Code, rec.Header().Get("Allow"))
		}
		if _, ok := h.sessions.Get(sid); !ok {
			t.Error("GET logged the user out")
		}
	})

	t.Run("cross-site POST is refused", func(t *testing.T) {
		h, sid := newLoggedIn()
		req := httptest.NewRequest(http.MethodPost, "/login/logout", strings.NewReader(""))
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.AddCookie(&http.Cookie{Name: "sid", Value: sid})

		rec := httptest.NewRecorder()
		h.Logout()(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if _, ok := h.sessions.Get(sid); !ok {
			t.Error("cross-site POST logged the user out")
		}
	})
}

func TestJWKSServesAppKeys(t *testing.T) {
	h, app, _ := newTestHandlers(&fakeAuth{})

	rec := httptest.NewRecorder()
	h.JWKS(app)(rec, httptest.NewRequest(http.MethodGet, "/login/jwks.json", nil))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Body.String() != string(app.JWKS) {
		t.Errorf("body = %q, want %q", rec.Body.String(), app.JWKS)
	}
}

// TestRegisterRoutes checks the mux wiring end to end, including that logout is
// mounted and rejects GET.
func TestRegisterRoutes(t *testing.T) {
	h, _, _ := newTestHandlers(&fakeAuth{redirectURL: "https://as.example/a", state: "s"})
	mux := h.Mux()

	for path, want := range map[string]int{
		"/login/login":     http.StatusFound,
		"/login/jwks.json": http.StatusOK,
		"/login/logout":    http.StatusMethodNotAllowed,
		"/other/login":     http.StatusNotFound,
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
	}
}
