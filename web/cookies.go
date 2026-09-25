package web

import (
	"net/http"
	"time"
)

// CookieConfig controls the two cookies the web helper sets: the app session
// cookie (referencing a LoginSessionStore entry) and the per-request, per-app state
// cookie (a defense-in-depth binding between an authorization request and its
// callback). The zero value is not usable — call DefaultCookieConfig and adjust.
type CookieConfig struct {
	// SessionName is the app session cookie name (default "sid").
	SessionName string
	// StatePrefix is prepended to the app name to form the per-app state cookie
	// name (default "sp_state_"), so concurrent logins to different apps don't
	// clobber each other.
	StatePrefix string
	// SessionTTL is the app session cookie lifetime (default 30m).
	SessionTTL time.Duration
	// StateTTL is the per-request state cookie lifetime (default 10m).
	StateTTL time.Duration
	// Path is the cookie Path attribute (default "/").
	Path string
	// SameSite is the cookie SameSite attribute (default http.SameSiteLaxMode).
	SameSite http.SameSite
	// Secure sets the cookie Secure attribute; enable when served over HTTPS.
	Secure bool
}

// DefaultCookieConfig returns the standard cookie settings (Secure controls the
// Secure attribute — set it true behind HTTPS).
func DefaultCookieConfig(secure bool) CookieConfig {
	return CookieConfig{
		SessionName: "sid",
		StatePrefix: "sp_state_",
		SessionTTL:  30 * time.Minute,
		StateTTL:    10 * time.Minute,
		Path:        "/",
		SameSite:    http.SameSiteLaxMode,
		Secure:      secure,
	}
}

// withDefaults fills any zero field with its default, leaving Secure as set.
func (c CookieConfig) withDefaults() CookieConfig {
	d := DefaultCookieConfig(c.Secure)
	if c.SessionName != "" {
		d.SessionName = c.SessionName
	}
	if c.StatePrefix != "" {
		d.StatePrefix = c.StatePrefix
	}
	if c.SessionTTL != 0 {
		d.SessionTTL = c.SessionTTL
	}
	if c.StateTTL != 0 {
		d.StateTTL = c.StateTTL
	}
	if c.Path != "" {
		d.Path = c.Path
	}
	if c.SameSite != 0 {
		d.SameSite = c.SameSite
	}
	return d
}

func (c CookieConfig) stateName(app string) string { return c.StatePrefix + app }

func (c CookieConfig) set(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	}
}

func (c CookieConfig) clear(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
		MaxAge:   -1,
	}
}
