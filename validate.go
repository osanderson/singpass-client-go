package singpass

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateOptions reports every problem with opts that Singpass or Corppass
// would otherwise reject later — at the pushed authorization request or the
// callback, usually with an opaque error — so New fails fast and names the
// option to fix. production is whether the client runs under
// AssuranceProduction.
func validateOptions(opts Options, production bool) error {
	var errs []error
	if strings.TrimSpace(opts.ClientID) == "" {
		errs = append(errs, errors.New("ClientID is required: use the client_id issued in the developer portal"))
	}
	if err := validateRedirectURI(opts.RedirectURI, production); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, validateScopes(opts.Scopes)...)
	if len(errs) == 0 {
		return nil
	}
	for i, err := range errs {
		errs[i] = fmt.Errorf("singpass: %w", err)
	}
	return errors.Join(errs...)
}

// validateRedirectURI checks the redirect URI is one Singpass can register
// and redirect to: absolute, without a fragment, with a host name rather than
// an IP address (the developer portal refuses those), and https — or
// http://localhost for local development, which Singpass staging allows.
func validateRedirectURI(raw string, production bool) error {
	if raw == "" {
		return errors.New("RedirectURI is required: use the redirect URI registered in the developer portal")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("RedirectURI %q is not a valid URL: %w", raw, err)
	}
	switch {
	case !u.IsAbs() || u.Host == "":
		return fmt.Errorf("RedirectURI %q must be an absolute URL, e.g. https://app.example.com/callback", raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return fmt.Errorf("RedirectURI %q must not contain a fragment (#…)", raw)
	case net.ParseIP(u.Hostname()) != nil:
		return fmt.Errorf("RedirectURI %q uses an IP address, which the developer portal doesn't accept: use a host name (localhost for local development)", raw)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && strings.EqualFold(u.Hostname(), "localhost"):
		if production {
			return fmt.Errorf("RedirectURI %q uses http: production redirect URIs must use https", raw)
		}
		return nil
	case u.Scheme == "http":
		return fmt.Errorf("RedirectURI %q must use https (http is only accepted for localhost, on staging)", raw)
	default:
		return fmt.Errorf("RedirectURI %q must use https", raw)
	}
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateScopes checks the requested scopes: "openid" must be one of them,
// and each must be a single non-empty token, listed once.
func validateScopes(scopes []string) []error {
	if len(scopes) == 0 {
		return []error{errors.New(`no Scopes: include "openid", plus the scopes your app is approved for`)}
	}
	var errs []error
	seen := map[string]bool{}
	for _, s := range scopes {
		switch {
		case strings.TrimSpace(s) == "":
			errs = append(errs, errors.New("an entry in Scopes is empty"))
		case strings.ContainsAny(s, " \t\n"):
			errs = append(errs, fmt.Errorf("scope %q in Scopes contains whitespace: list each scope separately", s))
		case seen[s]:
			errs = append(errs, fmt.Errorf("scope %q is listed more than once in Scopes", s))
		}
		seen[s] = true
	}
	if !seen["openid"] {
		errs = append(errs, errors.New(`"openid" is missing from Scopes`))
	}
	return errs
}
