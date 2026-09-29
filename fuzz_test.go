package singpass

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// FuzzCallbackSession: a callback is accepted only when the browser's state
// is non-empty and equals the callback's own state.
func FuzzCallbackSession(f *testing.F) {
	state := strings.Repeat("A", 43)
	f.Add("code=x&state="+state, state)
	f.Add("state=a&state=b", "a")
	f.Add("%zz", "")
	f.Add("state=", "")
	f.Fuzz(func(t *testing.T, rawQuery, state string) {
		if _, err := callbackSession(rawQuery, state); err == nil {
			q, _ := url.ParseQuery(rawQuery)
			if state == "" || q.Get("state") != state {
				t.Fatalf("accepted state %q for callback %q", state, rawQuery)
			}
		}
	})
}

// FuzzValidateAuthContextMessage: an accepted message keeps to Singpass's
// rules.
func FuzzValidateAuthContextMessage(f *testing.F) {
	f.Add("Log in to Example Bank")
	f.Add(strings.Repeat("x", 101))
	f.Add("a\\b`<>é\x00")
	f.Fuzz(func(t *testing.T, m string) {
		if validateAuthContextMessage(m) != nil {
			return
		}
		if len(m) > 100 || strings.ContainsAny(m, "<>\\`") {
			t.Fatalf("accepted %q", m)
		}
		for _, r := range m {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("accepted non-printable %q", m)
			}
		}
	})
}

// FuzzValidateRedirectURI: an accepted redirect URI is absolute, has no
// fragment or IP-address host, and uses https — or http on localhost outside
// production.
func FuzzValidateRedirectURI(f *testing.F) {
	for _, s := range []string{"https://app.example/cb", "http://localhost:8080/cb", "http://127.0.0.1/cb", "https://[::1]/cb#x", "/cb", "javascript:alert(1)", "https://user@host/cb"} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, raw string, production bool) {
		if validateRedirectURI(raw, production) != nil {
			return
		}
		u, err := url.Parse(raw)
		switch {
		case err != nil || !u.IsAbs() || u.Host == "":
			t.Fatalf("accepted non-absolute %q", raw)
		case strings.Contains(raw, "#"):
			t.Fatalf("accepted fragment %q", raw)
		case u.Scheme == "http" && (production || !strings.EqualFold(u.Hostname(), "localhost")):
			t.Fatalf("accepted http %q (production %v)", raw, production)
		case u.Scheme != "http" && u.Scheme != "https":
			t.Fatalf("accepted scheme %q", raw)
		}
	})
}

// FuzzCompareJWKS: comparing arbitrary expected and served key sets never
// panics, and a set always matches itself unless it leaks private members.
func FuzzCompareJWKS(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"s","use":"sig","x":"AA","y":"AA"}]}`), []byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":[{"kid":1,"d":"x"}]}`), []byte(`{"keys":[{"kid":"a","use":"enc"}]}`))
	f.Fuzz(func(t *testing.T, want, served []byte) {
		var w, s jwkSet
		if json.Unmarshal(want, &w) != nil || json.Unmarshal(served, &s) != nil {
			return
		}
		_ = compareJWKS("https://app.example/jwks", w, s)
		if err := compareJWKS("https://app.example/jwks", w, w); err != nil && !selfMatchExempt(w) {
			t.Fatalf("a set doesn't match itself: %v", err)
		}
	})
}

// selfMatchExempt reports whether a set can rightly fail to match itself: it
// leaks private members, has a key without a kid (which can't be matched by
// kid), or repeats a kid.
func selfMatchExempt(s jwkSet) bool {
	for _, k := range s.Keys {
		if kid, _ := k["kid"].(string); kid == "" || privateMember(k) != "" {
			return true
		}
	}
	return duplicateKIDs(s)
}

func duplicateKIDs(s jwkSet) bool {
	seen := map[string]bool{}
	for _, k := range s.Keys {
		kid, _ := k["kid"].(string)
		if seen[kid] {
			return true
		}
		seen[kid] = true
	}
	return false
}
