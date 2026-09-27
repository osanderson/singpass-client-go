package web

import (
	"net/http"
	"strings"
)

// DefaultContentSecurityPolicy is the Content-Security-Policy SecureHeaders
// sends. It suits server-rendered pages with no JavaScript: nothing may load
// from other origins, no scripts run, inline styles are allowed, forms may only
// post back to the app, and no other site may frame the pages. Use
// SecureHeadersWithPolicy if your pages need more.
const DefaultContentSecurityPolicy = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// SecureHeaders wraps next with browser security headers suited to a login
// app that shows personal data:
//
//   - Content-Security-Policy: DefaultContentSecurityPolicy
//   - X-Frame-Options: DENY (clickjacking; for browsers without frame-ancestors)
//   - X-Content-Type-Options: nosniff
//   - Referrer-Policy: no-referrer (callback URLs carry the code and state)
//   - Cross-Origin-Opener-Policy: same-origin
//   - Permissions-Policy denying camera, microphone and geolocation
//   - Strict-Transport-Security (two years) when the request arrived over
//     HTTPS, directly or via a proxy setting X-Forwarded-Proto
//
// Headers next sets itself take precedence.
func SecureHeaders(next http.Handler) http.Handler {
	return SecureHeadersWithPolicy(DefaultContentSecurityPolicy, next)
}

// SecureHeadersWithPolicy is SecureHeaders with a custom Content-Security-Policy
// (empty to send none).
func SecureHeadersWithPolicy(csp string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if csp != "" {
			h.Set("Content-Security-Policy", csp)
		}
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if isHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		next.ServeHTTP(w, r)
	})
}

// NoStore wraps next so its responses are never cached — by the browser
// (including its back/forward cache) or a shared proxy. Use it on every page
// that shows the signed-in identity or personal data, so they can't be
// reopened from cache after logout. The web helper's own login, callback and
// logout responses are already no-store.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		next.ServeHTTP(w, r)
	})
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// isHTTPS reports whether r reached the app over HTTPS: directly, or through
// a TLS-terminating proxy (Cloud Run, a load balancer) that sets
// X-Forwarded-Proto. Only a security-header decision rests on this.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}
