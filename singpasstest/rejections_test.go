package singpasstest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/osanderson/singpass-client-go/singpasstest"
)

// oauthError is an error response's body.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// post sends form to the server's endpoint path and returns the status and
// the decoded error, if any.
func post(t *testing.T, srv *singpasstest.Server, path string, form url.Values) (int, oauthError) {
	t.Helper()
	res, err := http.PostForm(srv.Issuer()+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var e oauthError
	_ = json.NewDecoder(res.Body).Decode(&e)
	return res.StatusCode, e
}

// The fake server refuses the requests Singpass refuses, with the same kind of
// error, before any client authentication.
func TestServerRejectsBadRequests(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	for _, c := range []struct {
		id  string
		app singpasstest.App
	}{{"login-rp", singpasstest.Login}, {"myinfo-rp", singpasstest.Myinfo}} {
		k := newKeys(t)
		if err := srv.RegisterClient(singpasstest.Client{
			ID: c.id, App: c.app, RedirectURIs: []string{redirectURI}, Scopes: []string{"name"},
			SigningKey: &k.sig.PublicKey, SigningKID: "s", EncryptionKey: &k.enc.PublicKey, EncryptionKID: "e",
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name, path string
		form       url.Values
		wantStatus int
		wantError  string
		wantDesc   string
	}{
		{"Login PAR without a context type", "/par", url.Values{"client_id": {"login-rp"}},
			http.StatusBadRequest, "invalid_request", "authentication_context_type is required"},
		{"Myinfo PAR with a context type", "/par", url.Values{"client_id": {"myinfo-rp"}, "authentication_context_type": {"APP_AUTHENTICATION_DEFAULT"}},
			http.StatusBadRequest, "invalid_request", "only be provided for Login apps"},
		{"PAR with a bad redirect_uri_https_type", "/par", url.Values{"client_id": {"login-rp"}, "redirect_uri_https_type": {"custom"}},
			http.StatusBadRequest, "invalid_request", "redirect_uri_https_type"},
		{"PAR with a message containing <", "/par", url.Values{"client_id": {"login-rp"}, "authentication_context_type": {"X"}, "authentication_context_message": {"<b>hi</b>"}},
			http.StatusBadRequest, "invalid_request", "authentication_context_message"},
		{"PAR with a message over 100 characters", "/par", url.Values{"client_id": {"login-rp"}, "authentication_context_type": {"X"}, "authentication_context_message": {strings.Repeat("a", 101)}},
			http.StatusBadRequest, "invalid_request", "authentication_context_message"},
		{"token with another grant type", "/token", url.Values{"grant_type": {"client_credentials"}},
			http.StatusBadRequest, "unsupported_grant_type", ""},
		{"token without client authentication", "/token", url.Values{"grant_type": {"authorization_code"}, "code": {"nope"}},
			http.StatusUnauthorized, "invalid_client", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, e := post(t, srv, tc.path, tc.form)
			if status != tc.wantStatus || (tc.wantError != "" && e.Error != tc.wantError) || !strings.Contains(e.Description, tc.wantDesc) {
				t.Errorf("%d %+v, want %d %s containing %q", status, e, tc.wantStatus, tc.wantError, tc.wantDesc)
			}
		})
	}
}

// Requests that aren't well-formed at all are refused too.
func TestServerRejectsMalformedRequests(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Interactive: true})
	for _, path := range []string{"/par", "/token"} {
		res, err := http.Post(srv.Issuer()+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s with a JSON body: %d, want 400", path, res.StatusCode)
		}
	}

	// /userinfo without an access token is refused with a DPoP challenge.
	res, err := http.Get(srv.Issuer() + "/userinfo")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode < 400 || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "DPoP") {
		t.Errorf("/userinfo without a token: %d, WWW-Authenticate %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}

	// /auth for an unknown request_uri, and a decision for an unknown login.
	res, err = http.Get(srv.Issuer() + "/auth?client_id=x&request_uri=urn:ietf:params:oauth:request_uri:nope")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode < 400 {
		t.Errorf("/auth for an unknown request_uri: %d %s", res.StatusCode, body)
	}
	if status, _ := post(t, srv, "/auth/decision", url.Values{"handle": {"nope"}}); status != http.StatusBadRequest {
		t.Errorf("decision with a bad handle: %d, want 400", status)
	}

	// The server's own JWKS is published.
	res, err = http.Get(srv.Issuer() + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	var set struct{ Keys []map[string]any }
	_ = json.NewDecoder(res.Body).Decode(&set)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || len(set.Keys) == 0 {
		t.Errorf("/jwks: %d with %d keys", res.StatusCode, len(set.Keys))
	}
}
