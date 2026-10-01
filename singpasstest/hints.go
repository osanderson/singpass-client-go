package singpasstest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// reject writes err, the server engine's rejection of r, as an OAuth error
// response. Being a fake for development, it says more than a real server:
// the error_description adds the engine's internal cause and, for the usual
// mistakes, how to fix them. The rejection is logged too. param reads the
// request's form (or query) parameters.
func (s *Server) reject(w http.ResponseWriter, r *http.Request, param func(string) string, err error) {
	var serr *server.Error
	if !errors.As(err, &serr) {
		s.rejectWith(w, r, param, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	desc := serr.PublicDescription()
	// The cause adds the detail, except for an unknown client, which the
	// hint puts better.
	if cause := errors.Unwrap(serr); cause != nil && !strings.Contains(desc, cause.Error()) && desc != "unknown client" {
		desc += ": " + cause.Error()
	}
	if h := s.hint(r, param, serr); h != "" {
		desc += ". " + h
	}
	s.rejectWith(w, r, param, serr.HTTPStatus(), string(serr.Code()), desc)
}

// rejectWith writes and logs an OAuth error response.
func (s *Server) rejectWith(w http.ResponseWriter, r *http.Request, param func(string) string, status int, code, desc string) {
	if h := s.hostHint(r); h != "" {
		desc += ". " + h
	}
	s.log.Warn("rejected "+r.Method+" "+r.URL.Path, "client_id", param("client_id"), "error", code, "error_description", desc)
	writeOAuthError(w, status, code, oauthSafe(desc))
}

// formParam reads a parameter of form.
func formParam(form server.FormRequest) func(string) string {
	return func(name string) string { return formValue(form, name) }
}

// hint says how to fix the mistake serr reports, if it is a usual one.
func (s *Server) hint(r *http.Request, param func(string) string, serr *server.Error) string {
	clientID := param("client_id")
	c, registered := s.clients.get(fapi.ClientID(clientID))
	cause := ""
	if u := errors.Unwrap(serr); u != nil {
		cause = u.Error()
	}
	switch desc := serr.PublicDescription(); {
	case desc == "unknown client":
		return s.clientsHint(clientID)

	case desc == "redirect_uri is not registered for this client" && registered:
		h := fmt.Sprintf("Client %q's redirect URIs are %s", clientID, strings.Join(c.cfg.RedirectURIs, ", "))
		if c.cfg.AnyLoopbackRedirectURI {
			h = fmt.Sprintf("Client %q accepts any http://localhost redirect URI", clientID)
		}
		return fmt.Sprintf("%s, not %q", h, parRedirectURI(server.FormRequest{Parameters: []server.FormParameter{
			{Name: "redirect_uri", Value: param("redirect_uri")}, {Name: "request", Value: param("request")},
		}}))

	case desc == "no matching client key" && registered:
		return fmt.Sprintf("The client_assertion's header has kid %q, but client %q's signing key is kid %q%s",
			jwtHeader(param("client_assertion")).Kid, clientID, c.cfg.SigningKID, s.testKeysHint(clientID))

	case desc == "client assertion verification failed" && strings.Contains(cause, "aud does not match"):
		return fmt.Sprintf("The client_assertion's aud is %s; it must be the issuer, %q, not the PAR or token endpoint",
			audString(jwtClaims(param("client_assertion"))["aud"]), s.issuer)

	case desc == "client assertion verification failed" && strings.Contains(cause, "invalid signature") && registered:
		return fmt.Sprintf("Sign the client_assertion with the private half of client %q's registered signing key, kid %q%s",
			clientID, c.cfg.SigningKID, s.testKeysHint(clientID))

	case desc == "client assertion verification failed" && strings.Contains(cause, "iss/sub"):
		return fmt.Sprintf("The client_assertion's iss and sub must both be the client_id, %q", clientID)

	case desc == "DPoP proof verification failed" && strings.Contains(cause, "htu does not match"):
		htu, _ := jwtClaims(r.Header.Get("DPoP"))["htu"].(string)
		want := s.base + r.URL.Path
		return fmt.Sprintf("The DPoP proof's htu is %q; it must be %q, the endpoint as this server's discovery document gives it. "+
			"If you reach the server at another URL, make that the server's URL (Config.BaseURL; for singpass-fake-server, "+
			"-singpass-url / FAKE_SINGPASS_URL or -corppass-url / FAKE_CORPPASS_URL)", htu, want)

	case desc == "DPoP proof is required":
		return "Send a DPoP proof in the DPoP header, as Singpass and Corppass require"

	case desc == "DPoP proof key does not match the dpop_jkt bound to this authorization code":
		return "Sign the token request's DPoP proof with the same key as the pushed authorization request's: " +
			"with several app instances, share one DPoP key, or send each callback to the instance that started the login"

	case desc == "scope is not valid for this client" && registered:
		return fmt.Sprintf("Register the scope for client %q; it has %s", clientID, scopesSummary(c.cfg.Scopes))

	case desc == "redirect_uri does not match the authorization request":
		return "Send the token request the same redirect_uri as the pushed authorization request"

	case desc == "code_verifier does not match code_challenge":
		return "Send the PKCE code_verifier of the login this code came from"

	case strings.HasPrefix(desc, "code is invalid, expired, or already used"):
		return "A code works once, soon after the login, and this server keeps codes in memory, so a restart forgets them"
	}
	return ""
}

// clientsHint lists the registered clients, for an unknown client_id.
func (s *Server) clientsHint(clientID string) string {
	ids := s.clients.ids()
	if len(ids) == 0 {
		return fmt.Sprintf("No client %q is registered here: there are no clients", clientID)
	}
	return fmt.Sprintf("No client %q is registered here; the registered clients are %s", clientID, strings.Join(ids, ", "))
}

// testKeysHint points a test client at its published keys.
func (s *Server) testKeysHint(clientID string) string {
	for _, id := range s.TestClients() {
		if id == clientID {
			return " (a test client: its keys are at " + s.TestClientKeysURL() + ")"
		}
	}
	return ""
}

// hostHint reports a request that reached the server at another host and
// port than its URL: the usual sign of a port published elsewhere, or a
// proxy, without the server's URL set to match. Each such host is logged
// once.
func (s *Server) hostHint(r *http.Request) string {
	base, err := url.Parse(s.base)
	if err != nil || r.Host == "" || strings.EqualFold(r.Host, base.Host) {
		return ""
	}
	return fmt.Sprintf("This request reached the server at %s, but its URL is %s: set the server's URL to the one clients use "+
		"(Config.BaseURL; for singpass-fake-server, -singpass-url / FAKE_SINGPASS_URL or -corppass-url / FAKE_CORPPASS_URL)", r.Host, s.base)
}

// checkHost logs, once per host, a request that reached the server at
// another host and port than its URL.
func (s *Server) checkHost(r *http.Request) {
	h := s.hostHint(r)
	if h == "" {
		return
	}
	s.mu.Lock()
	seen := s.hostsSeen[strings.ToLower(r.Host)]
	if s.hostsSeen == nil {
		s.hostsSeen = map[string]bool{}
	}
	s.hostsSeen[strings.ToLower(r.Host)] = true
	s.mu.Unlock()
	if !seen {
		s.log.Warn(h)
	}
}

func scopesSummary(scopes []string) string {
	all := append([]string{"openid"}, scopes...)
	if len(all) > 12 {
		return fmt.Sprintf("%d scopes", len(all))
	}
	return strings.Join(all, " ")
}

// jwtHeader decodes a compact JWS's header without verifying it.
func jwtHeader(jws string) (h struct{ Kid, Alg string }) {
	part, _, _ := strings.Cut(jws, ".")
	if raw, err := base64.RawURLEncoding.DecodeString(part); err == nil {
		_ = json.Unmarshal(raw, &h)
	}
	return h
}

// jwtClaims decodes a compact JWS's claims without verifying them.
func jwtClaims(jws string) map[string]any {
	parts := strings.Split(jws, ".")
	claims := map[string]any{}
	if len(parts) == 3 {
		if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(raw, &claims)
		}
	}
	return claims
}

func audString(aud any) string {
	b, _ := json.Marshal(aud)
	return string(b)
}

// oauthSafe makes desc a valid error_description (RFC 6749 §5.2): printable
// ASCII without " or \.
func oauthSafe(desc string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '"':
			return '\''
		case r == '\\':
			return '/'
		case r < 0x20 || r > 0x7e:
			return '?'
		}
		return r
	}, desc)
}
