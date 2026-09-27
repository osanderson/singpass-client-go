package singpass

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveJWKS serves body at /jwks.json on a loopback test server.
func serveJWKS(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/jwks.json"
}

func TestCheckPublishedJWKS(t *testing.T) {
	ctx := context.Background()
	sig, enc := newECKey(t), newECKey(t)
	want, err := OfflineClientJWKS(ctx, &sig.PublicKey, "sig-1", &enc.PublicKey, "enc-1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := OfflineClientJWKS(ctx, &newECKey(t).PublicKey, "sig-1", &enc.PublicKey, "enc-1")
	if err != nil {
		t.Fatal(err)
	}
	var set jwkSet
	if err := json.Unmarshal(want, &set); err != nil {
		t.Fatal(err)
	}
	// The same set plus an outgoing key, as during a rotation.
	rotating := jwkSet{Keys: append(append([]map[string]any{}, set.Keys...), map[string]any{
		"kty": "EC", "crv": "P-256", "kid": "sig-0", "use": "sig", "x": "AAAA", "y": "AAAA",
	})}
	rotatingJSON, _ := json.Marshal(rotating)
	// The set with a private member leaked into the signing key.
	leaked := jwkSet{Keys: []map[string]any{{}, set.Keys[1]}}
	for k, v := range set.Keys[0] {
		leaked.Keys[0][k] = v
	}
	leaked.Keys[0]["d"] = "secret"
	leakedJSON, _ := json.Marshal(leaked)

	for name, tc := range map[string]struct {
		status int
		body   string
		want   string // "" = no error; else a substring of the error
	}{
		"matches":        {200, string(want), ""},
		"rotation extra": {200, string(rotatingJSON), ""},
		"empty":          {200, `{"keys":[]}`, `missing the signing key "sig-1"`},
		"stale key":      {200, string(other), `different signing key under kid "sig-1"`},
		"private key":    {200, string(leakedJSON), "private key material"},
		"not a JWKS":     {200, `<html></html>`, "does not serve a JWKS"},
		"not found":      {404, `not found`, "HTTP 404"},
	} {
		t.Run(name, func(t *testing.T) {
			err := CheckPublishedJWKS(ctx, nil, serveJWKS(t, tc.status, tc.body), want)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	redirect := httptest.NewServer(http.RedirectHandler("/elsewhere", http.StatusFound))
	defer redirect.Close()
	if err := CheckPublishedJWKS(ctx, nil, redirect.URL, want); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("redirecting URL: %v", err)
	}

	if err := CheckPublishedJWKS(ctx, nil, "http://rp.example/jwks.json", want); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Errorf("plain http URL: %v", err)
	}
}
