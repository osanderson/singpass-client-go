package web

import (
	"net/http"
	"strings"
	"time"
)

// CookieConfig controls the two cookies the web helper sets: the app session
// cookie (referencing a LoginSessionStore entry) and the per-request, per-app state
// cookie (a defense-in-depth binding between an authorization request and its
// callback). The zero value is not usable — call DefaultCookieConfig and adjust.
type CookieConfig struct {
	// SessionName is the app session cookie name. Default "__Host-sid" when
	// Secure — the __Host- prefix makes browsers enforce Secure, Path=/ and no
	// Domain, so a sibling subdomain can't plant or overwrite it — otherwise
	// "sid". The prefix is dropped when Path isn't "/" or Secure is off.
	SessionName string
	// StatePrefix is prepended to the app name to form the per-app state cookie
	// name, so concurrent logins to different apps don't clobber each other.
	// Default "__Host-sp_state_" or "sp_state_", as for SessionName.
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

// hostPrefix is the cookie-name prefix that makes browsers require Secure,
// Path=/ and no Domain (RFC 6265bis §4.1.3.2).
const hostPrefix = "__Host-"

// DefaultCookieConfig returns the standard cookie settings (Secure controls the
// Secure attribute — set it true behind HTTPS). With secure, the cookie names
// carry the __Host- prefix.
func DefaultCookieConfig(secure bool) CookieConfig {
	session, state := "sid", "sp_state_"
	if secure {
		session, state = hostPrefix+session, hostPrefix+state
	}
	return CookieConfig{
		SessionName: session,
		StatePrefix: state,
		SessionTTL:  30 * time.Minute,
		StateTTL:    10 * time.Minute,
		Path:        "/",
		SameSite:    http.SameSiteLaxMode,
		Secure:      secure,
	}
}

// withDefaults fills any zero field with its default, leaving Secure as set.
// A __Host- name is only valid with Secure and Path "/" (the helper never sets
// Domain), so the prefix is dropped from the names under a custom Path.
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
	if d.Path != "/" || !d.Secure {
		d.SessionName = strings.TrimPrefix(d.SessionName, hostPrefix)
		d.StatePrefix = strings.TrimPrefix(d.StatePrefix, hostPrefix)
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
