package singpasstest_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

func TestPersonaBuilders(t *testing.T) {
	u := singpasstest.UserPersona(" s1234567d ", "tan ah kow")
	if u.Subject != singpasstest.UserPersona("S1234567D", "").Subject {
		t.Error("the same NRIC should give the same subject")
	}
	if u.SubAttributes["identity_number"] != "S1234567D" || u.SubAttributes["name"] != "TAN AH KOW" {
		t.Errorf("sub_attributes = %v", u.SubAttributes)
	}
	pi := u.UserInfo["person_info"].(map[string]any)
	if pi["partialuinfin"].(map[string]any)["value"] != "*****567D" {
		t.Errorf("partialuinfin = %v", pi["partialuinfin"])
	}
	e := singpasstest.EntityPersona("201912345k", "", "S1234567D", "")
	if e.Subject != "201912345K" || e.Act == nil || e.Act.Subject != u.Subject || !strings.HasPrefix(e.Name, "TEST ENTITY 201912345K") {
		t.Errorf("entity persona = %+v", e)
	}
}

// customLogin runs a login through the interactive sign-in page's custom
// form and returns the callback response.
func customLogin(t *testing.T, redirectURL string, form url.Values) *http.Response {
	t.Helper()
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	field := func(name string) string {
		m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindSubmatch(page)
		if m == nil {
			t.Fatalf("sign-in page has no %s field", name)
		}
		return string(m[1])
	}
	action := regexp.MustCompile(`action="([^"]*)"`).FindSubmatch(page)
	form.Set("handle", field("handle"))
	form.Set("scope", field("scope"))
	form.Set("client_id", field("client_id"))
	form.Set("decision", "custom")
	resp, err = hc.PostForm(string(action[1]), form)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCustomLoginSingpass(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Interactive: true})
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"uinfin", "partialuinfin", "name"}, k)
	c, err := singpass.NewMyinfo(context.Background(), singpass.MyinfoOptions{
		Issuer: srv.Issuer(), ClientID: "mi", RedirectURI: redirectURI, Scopes: []string{"openid", "uinfin", "partialuinfin", "name"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A malformed NRIC re-renders the page with the error.
	redirect, _, _ := c.BeginLogin(ctx)
	resp := customLogin(t, redirect, url.Values{"nric": {"12345"}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "must be a letter, 7 digits and a letter") || !strings.Contains(string(body), "Log in to mi") {
		t.Errorf("bad NRIC: %d %s", resp.StatusCode, body)
	}

	redirect, state, _ := c.BeginLogin(ctx)
	resp = customLogin(t, redirect, url.Values{"nric": {"s7654321z"}, "name": {"Lee Mei Ling"}})
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("custom login: %d %v", resp.StatusCode, err)
	}
	id, err := c.Complete(ctx, loc.RawQuery, state)
	if err != nil {
		t.Fatal(err)
	}
	p := id.Myinfo.PersonProfile()
	if p.UINFIN.String() != "S7654321Z" || p.PartialUINFIN.String() != "*****321Z" || p.Name.String() != "LEE MEI LING" || id.Subject != singpasstest.UserPersona("S7654321Z", "").Subject {
		t.Errorf("identity = %s %q %q %q", id.Subject, p.UINFIN.String(), p.PartialUINFIN.String(), p.Name.String())
	}
}

func TestCustomLoginCorppass(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Issuer: singpasstest.Corppass, Interactive: true})
	k := newKeys(t)
	register(t, srv, "mib", singpasstest.Myinfo, []string{"entity.basic_profile.name", "entity.basic_profile.registration_number"}, k)
	c, err := singpass.NewMyinfoBusiness(context.Background(), singpass.MyinfoBusinessOptions{
		Issuer: srv.Issuer(), ClientID: "mib", RedirectURI: redirectURI,
		Scopes:     []string{"openid", "entity.basic_profile.name", "entity.basic_profile.registration_number"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	redirect, state, _ := c.BeginLogin(ctx)
	resp := customLogin(t, redirect, url.Values{"uen": {"53123456A"}, "entity": {"Kopi Corner"}, "nric": {"S7654321Z"}, "name": {"Lee Mei Ling"}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	id, err := c.Complete(ctx, loc.RawQuery, state)
	if err != nil {
		t.Fatalf("Complete: %v (status %d)", err, resp.StatusCode)
	}
	e := id.Myinfo.EntityProfile()
	if id.Subject != "53123456A" || e.Name.String() != "KOPI CORNER" || id.ActingParty() == nil || id.ActingParty().Attributes.IdentityNumber != "S7654321Z" {
		t.Errorf("identity = %s %q %+v", id.Subject, e.Name.String(), id.ActingParty())
	}
}

func TestRicherDefaultPersonas(t *testing.T) {
	ps := singpasstest.DefaultPersonas(singpasstest.Singpass)
	if len(ps) != 3 {
		t.Fatalf("%d Singpass personas, want 3", len(ps))
	}
	hafiz := ps[1].UserInfo["person_info"].(map[string]any)
	for _, k := range []string{"cpfbalances", "noa-basic", "noa", "noahistory-basic", "hdbownership", "drivinglicence", "childrenbirthrecords"} {
		if hafiz[k] == nil {
			t.Errorf("Hafiz has no %s", k)
		}
	}
	foreigner := ps[2].UserInfo["person_info"].(map[string]any)
	if foreigner["passtype"] == nil || !strings.HasPrefix(ps[2].SubAttributes["identity_number"].(string), "G") {
		t.Error("the third persona should be a foreigner with a pass")
	}
}
