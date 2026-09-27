package singpass

import (
	"context"
	"strings"
	"testing"
)

func TestNewRejectsInvalidOptions(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate     func(*Options)
		production bool
		want       []string // substrings of the error
	}{
		"no client_id":         {func(o *Options) { o.ClientID = "" }, false, []string{"ClientID is required"}},
		"no redirect":          {func(o *Options) { o.RedirectURI = "" }, false, []string{"RedirectURI is required"}},
		"relative redirect":    {func(o *Options) { o.RedirectURI = "/callback" }, false, []string{"absolute URL"}},
		"http redirect":        {func(o *Options) { o.RedirectURI = "http://rp.example/callback" }, false, []string{"must use https"}},
		"fragment":             {func(o *Options) { o.RedirectURI = "https://rp.example/callback#x" }, false, []string{"fragment"}},
		"loopback, production": {func(o *Options) { o.RedirectURI = "http://localhost:8080/callback" }, true, []string{"production redirect URIs must use https"}},
		"loopback IP":          {func(o *Options) { o.RedirectURI = "http://127.0.0.1:8080/callback" }, false, []string{"IP address"}},
		"IPv6 loopback":        {func(o *Options) { o.RedirectURI = "http://[::1]:8080/callback" }, false, []string{"IP address"}},
		"https IP":             {func(o *Options) { o.RedirectURI = "https://203.0.113.10/callback" }, false, []string{"IP address"}},
		"no scopes":            {func(o *Options) { o.Scopes = nil }, false, []string{"no Scopes"}},
		"no openid":            {func(o *Options) { o.Scopes = []string{"name"} }, false, []string{`"openid" is missing from Scopes`}},
		"joined scopes":        {func(o *Options) { o.Scopes = []string{"openid name"} }, false, []string{"contains whitespace", `"openid" is missing from Scopes`}},
		"duplicate scope":      {func(o *Options) { o.Scopes = []string{"openid", "name", "name"} }, false, []string{`"name" is listed more than once`}},
		"several problems": {func(o *Options) { o.ClientID = ""; o.Scopes = []string{"name"} }, false,
			[]string{"ClientID is required", `"openid" is missing from Scopes`}},
	} {
		t.Run(name, func(t *testing.T) {
			o := baseOptions()
			tc.mutate(&o)
			deps := testKeyDeps(t)
			if tc.production {
				deps.Assurance = AssuranceProduction
			}
			_, err := New(context.Background(), o, deps)
			if err == nil {
				t.Fatal("New succeeded, want error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
		})
	}
}

func TestValidateOptionsAccepts(t *testing.T) {
	for _, uri := range []string{
		"https://rp.example/callback",
		"https://rp.example:8443/cb?app=login",
		"http://localhost:8080/callback",
	} {
		o := baseOptions()
		o.RedirectURI = uri
		if err := validateOptions(o, false); err != nil {
			t.Errorf("%s: %v", uri, err)
		}
	}
	o := baseOptions()
	o.Scopes = []string{"openid", "user.identity", "name"}
	if err := validateOptions(o, true); err != nil {
		t.Errorf("production https: %v", err)
	}
}

func TestKeyIDsRequired(t *testing.T) {
	if _, err := NewKeyManager(newECKey(t), ""); err == nil || !strings.Contains(err.Error(), "kid is required") {
		t.Errorf("NewKeyManager with no kid: %v", err)
	}
	if _, err := NewECDHDecrypter(newECKey(t), ""); err == nil || !strings.Contains(err.Error(), "kid is required") {
		t.Errorf("NewECDHDecrypter with no kid: %v", err)
	}
}
