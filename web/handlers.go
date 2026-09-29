// Package web is an optional HTTP helper for building a relying-party web app on
// top of the singpass package. It serves one or more relying parties, each under its
// own /{name}/* routes: the authorization redirect, the callback dance
// (delegated to singpass.Client), an app session referenced by an opaque HttpOnly
// cookie, and each client's public JWKS.
//
// The helper emits no HTML: rendering (the landing page, the signed-in view,
// error pages) is the caller's, supplied through the OnAuthenticated / OnDenied
// / OnError callbacks and the CurrentIdentity accessor. Use RegisterRoutes to
// mount the routes on your own mux, or Mux for a ready-made one you can add a
// "/" handler to.
//
// Wrap the whole app in SecureHeaders (browser security headers) and every page
// that shows the identity in NoStore; behind HTTPS set
// Config.Cookies to DefaultCookieConfig(true). Set Config.SessionIdentity (e.g.
// MinimalIdentity) to keep personal data out of the login session.
package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
)

// ErrStateMismatch is passed to Config.OnError when a callback's state doesn't
// match the state cookie set at /{name}/login — usually because the cookie
// expired (CookieConfig.StateTTL), the login was started in another browser,
// or the callback page was reloaded. It wraps singpass.ErrLoginExpired, so one
// errors.Is(err, singpass.ErrLoginExpired) check covers every stale-login case.
var ErrStateMismatch = fmt.Errorf("web: login state mismatch: %w", singpass.ErrLoginExpired)

// Authenticator is the part of *singpass.Client the handlers use. Any
// *singpass.Client satisfies it; tests can substitute a stub.
type Authenticator interface {
	BeginLogin(ctx context.Context) (redirectURL, state string, err error)
	Complete(ctx context.Context, rawQuery, state string) (*singpass.Identity, error)
}

// App is one relying party the helper exposes. Name is the URL/cookie slug
// (e.g. "login"); it appears in the redirect URI /{name}/callback, so avoid
// "singpass", "corppass" and "myinfo", which Singpass/Corppass reject in
// redirect URIs. Title is a human-facing label the caller may use in its
// own rendering; Auth drives the FAPI flow; JWKS is that client's public key
// set, served at /{name}/jwks.json for the authorization server to fetch.
type App struct {
	Name  string
	Title string
	Auth  Authenticator
	JWKS  []byte
}

// Config configures a Handlers. Only Apps is required.
type Config struct {
	// Apps are the relying parties to serve, in registration order.
	Apps []*App

	// LoginSessions stores authenticated identities (the application login
	// session, not FAPIgo's protocol session store). Nil installs
	// NewMemoryLoginSessionStore().
	LoginSessions LoginSessionStore

	// Cookies controls cookie names, TTLs and attributes. The zero value uses
	// DefaultCookieConfig(false); set Cookies.Secure true behind HTTPS.
	Cookies CookieConfig

	// Logger receives warnings (e.g. state mismatches) and the id_token
	// lifetime line. Nil means slog.Default().
	Logger *slog.Logger

	// SessionIdentity chooses what the login session keeps of each identity,
	// and so what CurrentIdentity returns. It is given the full identity and
	// returns what to store: WithoutMyinfo drops the Myinfo data, and
	// MinimalIdentity keeps only the subject and the claims that describe the
	// login. Nil stores the full identity, Myinfo data included — in the
	// database, with a durable store such as sqlstore's. OnAuthenticated
	// always receives the full identity.
	SessionIdentity func(*singpass.Identity) *singpass.Identity

	// OnAuthenticated is called after a successful login, once the app session
	// has been created and its cookie set, with the full identity: keep what
	// the app needs of it there. Nil redirects to "/".
	OnAuthenticated func(w http.ResponseWriter, r *http.Request, app *App, id *singpass.Identity)

	// OnDenied is called when the user cancelled or the server denied the
	// request. Nil redirects to "/".
	OnDenied func(w http.ResponseWriter, r *http.Request, app *App, denied *singpass.DeniedError)

	// OnError is called on a protocol or transport failure, or with
	// ErrTooManyLogins when LoginRateLimit refuses a login. Nil writes a 500,
	// or a 429 for ErrTooManyLogins.
	OnError func(w http.ResponseWriter, r *http.Request, app *App, err error)

	// LoginRateLimit limits how often one client may start a login. Nil
	// means no limit: set it for any app reachable from the internet, with a
	// Key that finds the client's address behind your proxy.
	LoginRateLimit *LoginRateLimit
}

// Handlers is the HTTP surface for a set of relying parties. Build it with New.
type Handlers struct {
	apps     []*App
	byName   map[string]*App
	sessions LoginSessionStore
	cookies  CookieConfig
	log      *slog.Logger

	sessionIdentity func(*singpass.Identity) *singpass.Identity

	onAuthenticated func(http.ResponseWriter, *http.Request, *App, *singpass.Identity)
	onDenied        func(http.ResponseWriter, *http.Request, *App, *singpass.DeniedError)
	onError         func(http.ResponseWriter, *http.Request, *App, error)

	limiter *rateLimiter // nil: no limit
}

// New builds a Handlers from cfg, applying defaults for every optional field.
func New(cfg Config) *Handlers {
	byName := make(map[string]*App, len(cfg.Apps))
	for _, a := range cfg.Apps {
		byName[a.Name] = a
	}
	h := &Handlers{
		apps:            cfg.Apps,
		byName:          byName,
		sessions:        cfg.LoginSessions,
		cookies:         cfg.Cookies.withDefaults(),
		log:             cfg.Logger,
		sessionIdentity: cfg.SessionIdentity,
		onAuthenticated: cfg.OnAuthenticated,
		onDenied:        cfg.OnDenied,
		onError:         cfg.OnError,
	}
	if h.sessions == nil {
		h.sessions = NewMemoryLoginSessionStore()
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.onAuthenticated == nil {
		h.onAuthenticated = func(w http.ResponseWriter, r *http.Request, _ *App, _ *singpass.Identity) {
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
	if h.onDenied == nil {
		h.onDenied = func(w http.ResponseWriter, r *http.Request, _ *App, _ *singpass.DeniedError) {
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
	if h.onError == nil {
		h.onError = func(w http.ResponseWriter, _ *http.Request, _ *App, err error) {
			if errors.Is(err, ErrTooManyLogins) {
				http.Error(w, "too many logins started; try again shortly", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "login failed", http.StatusInternalServerError)
		}
	}
	if cfg.LoginRateLimit != nil {
		h.limiter = newRateLimiter(*cfg.LoginRateLimit)
	}
	if cfg.SessionIdentity == nil && cfg.LoginSessions != nil {
		h.log.Warn("web: login sessions keep each full identity, Myinfo data included, in the LoginSessions store; " +
			"set Config.SessionIdentity (e.g. web.MinimalIdentity) to keep less")
	}
	return h
}

// Apps returns the configured apps in registration order (for a caller
// rendering a landing page).
func (h *Handlers) Apps() []*App { return h.apps }

// App returns the app registered under name, or nil.
func (h *Handlers) App(name string) *App { return h.byName[name] }

// RegisterRoutes mounts each app's /{name}/login, /{name}/callback,
// /{name}/logout (POST only) and /{name}/jwks.json on mux. It does not register "/": the
// landing/profile page is the caller's, mounted with CurrentIdentity.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	for _, a := range h.apps {
		base := "/" + a.Name
		mux.HandleFunc(base+"/login", h.Login(a))
		mux.HandleFunc(base+"/callback", h.Callback(a))
		mux.HandleFunc(base+"/logout", h.Logout())
		mux.HandleFunc(base+"/jwks.json", h.JWKS(a))
	}
}

// Mux returns a new *http.ServeMux with the per-app routes registered. Add a
// "/" handler for the landing/profile page.
func (h *Handlers) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// Login runs PAR, sets the per-app state cookie, and redirects the browser to
// the authorization server.
func (h *Handlers) Login(a *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if h.limiter != nil {
			if ok, retry := h.limiter.allow(r); !ok {
				h.log.Warn("login rate limited", "app", a.Name)
				w.Header().Set("Retry-After", retryAfterSeconds(retry))
				h.onError(w, r, a, ErrTooManyLogins)
				return
			}
		}
		redirectURL, state, err := a.Auth.BeginLogin(r.Context())
		if err != nil {
			h.log.Error("begin login", "app", a.Name, "err", err)
			h.onError(w, r, a, err)
			return
		}
		// Bind this authorization request to its callback via a short-lived,
		// per-app cookie.
		http.SetCookie(w, h.cookies.set(h.cookies.stateName(a.Name), state, h.cookies.StateTTL))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// Callback validates the redirect from the authorization server and, on
// success, establishes an application session before invoking OnAuthenticated.
func (h *Handlers) Callback(a *App) http.HandlerFunc {
	stateCookie := h.cookies.stateName(a.Name)
	return func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		// Defense in depth: the callback's state must match the cookie we set at
		// /{name}/login. FAPIgo independently validates state/nonce/iss against
		// its own session store; this is a belt-and-braces check at the HTTP edge.
		c, err := r.Cookie(stateCookie)
		if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
			h.log.Warn("callback state mismatch", "app", a.Name)
			http.SetCookie(w, h.cookies.clear(stateCookie))
			h.onError(w, r, a, ErrStateMismatch)
			return
		}
		http.SetCookie(w, h.cookies.clear(stateCookie))

		// The state cookie binds the callback to this browser (RFC 9700 §4.7).
		id, err := a.Auth.Complete(r.Context(), r.URL.RawQuery, c.Value)
		if err != nil {
			var denied *singpass.DeniedError
			if errors.As(err, &denied) {
				h.log.Info("login denied", "app", a.Name, "code", denied.Code)
				h.onDenied(w, r, a, denied)
				return
			}
			h.log.Error("complete login", "app", a.Name, "err", err)
			h.onError(w, r, a, err)
			return
		}

		// Report the id_token's exact lifetime (exp − iat, both validated by
		// FAPIgo) for comparison across products. Login/Myinfo run ~minutes;
		// Corppass Myinfo Business is longer.
		if !id.IDTokenExpiry.IsZero() && !id.IDTokenIssuedAt.IsZero() {
			h.log.Info("id_token lifetime",
				"app", a.Name,
				"exp", id.IDTokenExpiry.UTC().Format(time.RFC3339),
				"lifetime", id.IDTokenExpiry.Sub(id.IDTokenIssuedAt).Round(time.Second).String(),
			)
		}

		// Replace, rather than add to, any session this browser already holds, so
		// re-logging in (or switching apps) does not leave the old entry live.
		if c, err := r.Cookie(h.cookies.SessionName); err == nil && c.Value != "" {
			if err := h.sessions.Delete(r.Context(), c.Value); err != nil {
				h.log.Warn("drop previous session", "app", a.Name, "err", err)
			}
		}
		stored := id
		if h.sessionIdentity != nil {
			if stored = h.sessionIdentity(id); stored == nil {
				h.log.Error("create session", "app", a.Name, "err", "SessionIdentity returned nil")
				h.onError(w, r, a, errors.New("web: Config.SessionIdentity returned nil"))
				return
			}
		}
		sid, err := h.sessions.Create(r.Context(), stored, h.cookies.SessionTTL)
		if err != nil {
			h.log.Error("create session", "app", a.Name, "err", err)
			h.onError(w, r, a, fmt.Errorf("web: create session: %w", err))
			return
		}
		http.SetCookie(w, h.cookies.set(h.cookies.SessionName, sid, h.cookies.SessionTTL))
		h.onAuthenticated(w, r, a, id)
	}
}

// Logout drops the server-side session and its cookie, then redirects to "/".
// It accepts only POST, and rejects cross-origin browser requests
// (http.CrossOriginProtection), so a third-party page can neither link nor
// auto-submit a form to log the user out. Render logout as a same-origin
// <form method="post">.
func (h *Handlers) Logout() http.HandlerFunc {
	var csrf http.CrossOriginProtection
	return func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := csrf.Check(r); err != nil {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if c, err := r.Cookie(h.cookies.SessionName); err == nil {
			if err := h.sessions.Delete(r.Context(), c.Value); err != nil {
				h.log.Warn("delete session on logout", "err", err)
			}
		}
		http.SetCookie(w, h.cookies.clear(h.cookies.SessionName))
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// JWKS serves one app's public client JWKS for the authorization server to fetch.
func (h *Handlers) JWKS(a *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(a.JWKS)
	}
}

// CurrentIdentity returns the identity for the request's session cookie, if any.
// A caller uses it in its "/" handler to choose between the landing and
// signed-in views.
func (h *Handlers) CurrentIdentity(r *http.Request) (*singpass.Identity, bool) {
	c, err := r.Cookie(h.cookies.SessionName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	id, ok, err := h.sessions.Get(r.Context(), c.Value)
	if err != nil {
		h.log.Error("load session", "err", err)
		return nil, false
	}
	return id, ok
}
