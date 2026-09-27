package web

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/myinfo"
)

func fullIdentity() *singpass.Identity {
	return &singpass.Identity{
		App: "mib", Subject: "201912345K", Scope: "openid entity.basic_profile.name",
		Claims: map[string]any{
			"iss": "https://stg-id.corppass.gov.sg", "aud": "rp", "sub": "201912345K", "sub_type": "entity",
			"acr": "urn:singpass:authentication:loa:2", "amr": []any{"pwd", "otp-sms"}, "iat": 1.0, "exp": 2.0,
			"nonce":          "n-1",
			"sub_attributes": map[string]any{"entity_name": "HARBOURFRONT TRADING PTE. LTD."},
			"act":            map[string]any{"sub": "u-1", "sub_attributes": map[string]any{"identity_number": "S7812345J"}},
		},
		Myinfo: myinfo.Parse(map[string]any{"person_info": map[string]any{"name": map[string]any{"value": "LIM WEI MING"}}}),
	}
}

func TestWithoutMyinfo(t *testing.T) {
	full := fullIdentity()
	got := WithoutMyinfo(full)
	if got.Myinfo != nil || got.Subject != full.Subject || !reflect.DeepEqual(got.Claims, full.Claims) {
		t.Errorf("WithoutMyinfo = %+v", got)
	}
	if full.Myinfo == nil {
		t.Error("WithoutMyinfo changed its argument")
	}
}

func TestMinimalIdentity(t *testing.T) {
	full := fullIdentity()
	got := MinimalIdentity(full)
	if got.Myinfo != nil || got.App != "mib" || got.Subject != "201912345K" || got.Scope != full.Scope {
		t.Errorf("MinimalIdentity = %+v", got)
	}
	for _, k := range []string{"sub_attributes", "act", "nonce"} {
		if _, ok := got.Claims[k]; ok {
			t.Errorf("MinimalIdentity kept %q", k)
		}
	}
	if got.Issuer() != "https://stg-id.corppass.gov.sg" || got.SubjectType() != "entity" || len(got.AuthMethods()) != 2 {
		t.Errorf("accessors on the minimal identity: %q %q %v", got.Issuer(), got.SubjectType(), got.AuthMethods())
	}
	if got.SubjectAttributes().Present() || got.ActingParty() != nil {
		t.Error("minimal identity still has personal claims")
	}
	if full.Myinfo == nil || full.Claims["sub_attributes"] == nil {
		t.Error("MinimalIdentity changed its argument")
	}
}

func TestCallbackStoresSessionIdentity(t *testing.T) {
	full := fullIdentity()
	app := &App{Name: "mib", Auth: &fakeAuth{id: full}}
	var authenticated *singpass.Identity
	h := New(Config{
		Apps:            []*App{app},
		SessionIdentity: MinimalIdentity,
		OnAuthenticated: func(w http.ResponseWriter, _ *http.Request, _ *App, id *singpass.Identity) {
			authenticated = id
		},
	})
	rec := httptest.NewRecorder()
	h.Callback(app)(rec, callbackRequestFor("mib", "st-1"))
	if authenticated != full {
		t.Fatal("OnAuthenticated should get the full identity")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookieNamed(rec, "sid"))
	stored, ok := h.CurrentIdentity(req)
	if !ok || stored.Myinfo != nil || stored.Subject != full.Subject || stored.Claims["sub_attributes"] != nil {
		t.Errorf("CurrentIdentity = %+v, %v; want the minimal identity", stored, ok)
	}
}

func TestCallbackSessionIdentityNil(t *testing.T) {
	app := &App{Name: "login", Auth: &fakeAuth{id: fullIdentity()}}
	var gotErr error
	h := New(Config{
		Apps:            []*App{app},
		SessionIdentity: func(*singpass.Identity) *singpass.Identity { return nil },
		OnError:         func(_ http.ResponseWriter, _ *http.Request, _ *App, err error) { gotErr = err },
	})
	rec := httptest.NewRecorder()
	h.Callback(app)(rec, callbackRequestFor("login", "st-1"))
	if gotErr == nil || cookieNamed(rec, "sid") != nil {
		t.Errorf("nil SessionIdentity: err %v, session cookie %v", gotErr, cookieNamed(rec, "sid"))
	}
}

// callbackRequestFor is a callback for app with a matching state cookie.
func callbackRequestFor(app, state string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/"+app+"/callback?code=c&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "sp_state_" + app, Value: state})
	return req
}
