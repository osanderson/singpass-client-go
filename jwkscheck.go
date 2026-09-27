package singpass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// maxJWKSBytes bounds the JWKS CheckPublishedJWKS reads.
	maxJWKSBytes = 1 << 20
	// maxJWKSResponseTime is how quickly Singpass and Corppass require a
	// client's JWKS endpoint to respond.
	maxJWKSResponseTime = 3 * time.Second
)

// CheckPublishedJWKS fetches the JWKS at jwksURL — the JWKS URL registered for
// this client in the Singpass or Corppass developer portal — and checks that it
// publishes this client's keys (Client.PublicJWKS): every key present under
// its kid, with the same public key and use, and no private key material. A
// mismatch there is the usual cause of an "invalid_client" error at login, so
// run it after deploying or rotating keys, e.g. as a startup or readiness
// check. It also checks the endpoint answers within the 3 seconds Singpass
// and Corppass allow, without a redirect. It returns nil when the published
// set is correct, or an error naming each problem. Extra published keys, such as an outgoing key during a
// rotation, are allowed.
func (c *Client) CheckPublishedJWKS(ctx context.Context, jwksURL string) error {
	want, err := c.PublicJWKS(ctx)
	if err != nil {
		return err
	}
	return CheckPublishedJWKS(ctx, c.httpClient, jwksURL, want)
}

// CheckPublishedJWKS is Client.CheckPublishedJWKS for when there is no Client
// yet, e.g. during onboarding: it checks the JWKS at jwksURL against want, a
// JWKS such as OfflineClientJWKS returns. A nil hc uses a client with a
// 15-second timeout. jwksURL must use https, except on a loopback host.
func CheckPublishedJWKS(ctx context.Context, hc *http.Client, jwksURL string, want []byte) error {
	var wantSet jwkSet
	if err := json.Unmarshal(want, &wantSet); err != nil {
		return fmt.Errorf("singpass: parse expected JWKS: %w", err)
	}
	served, err := fetchJWKS(ctx, hc, jwksURL)
	if err != nil {
		return err
	}
	return compareJWKS(jwksURL, wantSet, served)
}

type jwkSet struct {
	Keys []map[string]any `json:"keys"`
}

func fetchJWKS(ctx context.Context, hc *http.Client, jwksURL string) (jwkSet, error) {
	u, err := url.Parse(jwksURL)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return jwkSet{}, fmt.Errorf("singpass: JWKS URL %q is not an absolute URL", jwksURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return jwkSet{}, fmt.Errorf("singpass: JWKS URL %q must use https: Singpass and Corppass only fetch https URLs", jwksURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: defaultHTTPTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return jwkSet{}, fmt.Errorf("singpass: fetch JWKS: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	// Report a redirect rather than follow it: Corppass doesn't follow them.
	noRedirects := *hc
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	start := time.Now()
	resp, err := noRedirects.Do(req)
	if err != nil {
		return jwkSet{}, fmt.Errorf("singpass: fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return jwkSet{}, fmt.Errorf("singpass: %s redirects (HTTP %d to %q): register the final URL, as Corppass doesn't follow redirects", jwksURL, resp.StatusCode, loc)
	}
	if resp.StatusCode != http.StatusOK {
		return jwkSet{}, fmt.Errorf("singpass: fetch JWKS from %s: HTTP %d", jwksURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return jwkSet{}, fmt.Errorf("singpass: read JWKS from %s: %w", jwksURL, err)
	}
	if len(body) > maxJWKSBytes {
		return jwkSet{}, fmt.Errorf("singpass: JWKS at %s is larger than %d bytes", jwksURL, maxJWKSBytes)
	}
	if took := time.Since(start); took > maxJWKSResponseTime {
		return jwkSet{}, fmt.Errorf("singpass: %s took %s to respond: Singpass and Corppass need it within %s, or logins fail", jwksURL, took.Round(time.Millisecond), maxJWKSResponseTime)
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil || set.Keys == nil {
		return jwkSet{}, fmt.Errorf(`singpass: %s does not serve a JWKS (a JSON object with a "keys" array)`, jwksURL)
	}
	return set, nil
}

// privateJWKMembers are the JWK members that carry private key material
// (RFC 7518 §6.2.2, §6.3.2, §6.4).
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// publicJWKMembers identify an EC or RSA public key.
var publicJWKMembers = []string{"kty", "crv", "x", "y", "n", "e"}

func compareJWKS(jwksURL string, want, served jwkSet) error {
	var errs []error
	byKID := map[string]map[string]any{}
	for _, k := range served.Keys {
		kid, _ := k["kid"].(string)
		for _, m := range privateJWKMembers {
			if _, ok := k[m]; ok {
				errs = append(errs, fmt.Errorf("singpass: %s publishes private key material (%q) in key %q: take it down and replace the key now", jwksURL, m, kid))
				break
			}
		}
		if kid != "" {
			byKID[kid] = k
		}
	}
	for _, w := range want.Keys {
		kid, _ := w["kid"].(string)
		use, _ := w["use"].(string)
		got, ok := byKID[kid]
		if !ok {
			errs = append(errs, fmt.Errorf("singpass: %s is missing the %s key %q: publish this client's current JWKS there", jwksURL, useName(use), kid))
			continue
		}
		for _, m := range publicJWKMembers {
			if fmt.Sprint(w[m]) != fmt.Sprint(got[m]) {
				errs = append(errs, fmt.Errorf("singpass: %s publishes a different %s key under kid %q than the one this client holds: publish the current JWKS, or load the key that matches it", jwksURL, useName(use), kid))
				break
			}
		}
		if gotUse, _ := got["use"].(string); gotUse != "" && use != "" && gotUse != use {
			errs = append(errs, fmt.Errorf("singpass: %s publishes key %q with use %q, want %q", jwksURL, kid, gotUse, use))
		}
	}
	return errors.Join(errs...)
}

func useName(use string) string {
	switch use {
	case "sig":
		return "signing"
	case "enc":
		return "encryption"
	default:
		return "client"
	}
}
