package singpasstest_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// myinfoClient registers a Myinfo client on srv and returns a library client
// for it.
func myinfoClient(t *testing.T, srv *singpasstest.Server) *singpass.Client {
	t.Helper()
	k := newKeys(t)
	scopes := []string{"uinfin", "name"}
	register(t, srv, "mi", singpasstest.Myinfo, scopes, k)
	c, err := singpass.NewMyinfo(context.Background(), singpass.MyinfoOptions{
		Issuer: srv.Issuer(), ClientID: "mi", RedirectURI: redirectURI, Scopes: append([]string{"openid"}, scopes...),
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// myinfoBusinessClient is myinfoClient for a Corppass server.
func myinfoBusinessClient(t *testing.T, srv *singpasstest.Server) *singpass.Client {
	t.Helper()
	k := newKeys(t)
	scopes := []string{"entity.basic_profile.name"}
	register(t, srv, "mib", singpasstest.Myinfo, scopes, k)
	c, err := singpass.NewMyinfoBusiness(context.Background(), singpass.MyinfoBusinessOptions{
		Issuer: srv.Issuer(), ClientID: "mib", RedirectURI: redirectURI, Scopes: append([]string{"openid"}, scopes...),
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func loginAs(t *testing.T, srv *singpasstest.Server, c *singpass.Client, as singpasstest.LoginAs) (*singpass.Identity, error) {
	t.Helper()
	ctx := context.Background()
	redirectURL, state, err := c.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	query, err := srv.AuthorizeAs(ctx, redirectURL, as)
	if err != nil {
		t.Fatalf("AuthorizeAs: %v", err)
	}
	return c.Complete(ctx, query, state)
}

func TestLoginAsSingpass(t *testing.T) {
	// Interactive: the headers skip the sign-in page.
	srv := startServer(t, singpasstest.Config{Interactive: true})
	c := myinfoClient(t, srv)
	hafiz := singpasstest.DefaultPersonas(singpasstest.Singpass)[1]

	// A persona's NRIC logs in as that persona, with its data.
	id, err := loginAs(t, srv, c, singpasstest.LoginAs{NRIC: "s8012345f", Name: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if p := id.Myinfo.PersonProfile(); id.Subject != hafiz.Subject || p.UINFIN.String() != "S8012345F" || p.Name.String() != "MUHAMMAD HAFIZ BIN ISMAIL" {
		t.Errorf("persona login = %s %q %q", id.Subject, p.UINFIN.String(), p.Name.String())
	}

	// Any other NRIC is a new user, and a UUID replaces the subject.
	const uuid = "0f0e0d0c-0b0a-4908-8706-050403020100"
	id, err = loginAs(t, srv, c, singpasstest.LoginAs{NRIC: "T0123456G", Name: "Ng Siew Lan", UUID: strings.ToUpper(uuid)})
	if err != nil {
		t.Fatal(err)
	}
	if p := id.Myinfo.PersonProfile(); id.Subject != uuid || p.UINFIN.String() != "T0123456G" || p.Name.String() != "NG SIEW LAN" {
		t.Errorf("new user = %s %q %q", id.Subject, p.UINFIN.String(), p.Name.String())
	}

	// A persona with a replaced UUID keeps its data.
	id, err = loginAs(t, srv, c, singpasstest.LoginAs{NRIC: "S8012345F", UUID: uuid})
	if err != nil {
		t.Fatal(err)
	}
	if p := id.Myinfo.PersonProfile(); id.Subject != uuid || p.Name.String() != "MUHAMMAD HAFIZ BIN ISMAIL" {
		t.Errorf("persona with UUID = %s %q", id.Subject, p.Name.String())
	}

	_, err = loginAs(t, srv, c, singpasstest.LoginAs{Cancel: true})
	var denied *singpass.DeniedError
	if !errors.As(err, &denied) || denied.Code != "access_denied" {
		t.Fatalf("cancel: err = %v, want DeniedError access_denied", err)
	}
}

func TestLoginAsCorppass(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Issuer: singpasstest.Corppass})
	c := myinfoBusinessClient(t, srv)

	// The persona's entity, with someone else acting for it.
	const uuid = "0f0e0d0c-0b0a-4908-8706-050403020100"
	id, err := loginAs(t, srv, c, singpasstest.LoginAs{UEN: "201912345K", NRIC: "S7654321Z", Name: "Lee Mei Ling", UUID: uuid})
	if err != nil {
		t.Fatal(err)
	}
	act := id.ActingParty()
	if id.Subject != "201912345K" || id.Myinfo.EntityProfile().Name.String() != "HARBOURFRONT TRADING PTE. LTD." ||
		act == nil || act.Subject != uuid || act.Attributes.IdentityNumber != "S7654321Z" || act.Attributes.Name != "LEE MEI LING" {
		t.Errorf("persona entity = %s %q %+v", id.Subject, id.Myinfo.EntityProfile().Name.String(), act)
	}

	// The persona's acting person keeps their UUID.
	persona := singpasstest.DefaultPersonas(singpasstest.Corppass)[0]
	id, err = loginAs(t, srv, c, singpasstest.LoginAs{UEN: "201912345K", NRIC: "S7812345J"})
	if err != nil {
		t.Fatal(err)
	}
	if act := id.ActingParty(); act == nil || act.Subject != persona.Act.Subject {
		t.Errorf("persona's actor = %+v", act)
	}

	// A new entity.
	id, err = loginAs(t, srv, c, singpasstest.LoginAs{UEN: "53123456A", NRIC: "S7654321Z"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "53123456A" || id.Myinfo.EntityProfile().Name.String() != "TEST ENTITY 53123456A" {
		t.Errorf("new entity = %s %q", id.Subject, id.Myinfo.EntityProfile().Name.String())
	}
}

func TestLoginAsRejectsBadHeaders(t *testing.T) {
	sp := startServer(t, singpasstest.Config{})
	cp := startServer(t, singpasstest.Config{Issuer: singpasstest.Corppass})
	spc, cpc := myinfoClient(t, sp), myinfoBusinessClient(t, cp)
	for name, tc := range map[string]struct {
		corppass bool
		as       singpasstest.LoginAs
		header   http.Header
		want     string
	}{
		"bad NRIC":           {as: singpasstest.LoginAs{NRIC: "12345"}, want: "must be a letter, 7 digits and a letter"},
		"no NRIC":            {as: singpasstest.LoginAs{Name: "Tan"}, want: "X-Custom-NRIC is required"},
		"UEN on Singpass":    {as: singpasstest.LoginAs{NRIC: "S1234567D", UEN: "201912345K"}, want: "X-Custom-UEN is for Corppass"},
		"bad UUID":           {as: singpasstest.LoginAs{NRIC: "S1234567D", UUID: "not-a-uuid"}, want: "must be a UUID"},
		"cancel and NRIC":    {header: http.Header{"X-Custom-Error": {"access_denied"}, "X-Custom-Nric": {"S1234567D"}}, want: "cannot be combined"},
		"unknown error":      {header: http.Header{"X-Custom-Error": {"server_error"}}, want: `"server_error" is not supported`},
		"no UEN on Corppass": {corppass: true, as: singpasstest.LoginAs{NRIC: "S1234567D"}, want: "X-Custom-UEN is required on Corppass"},
		"bad UEN":            {corppass: true, as: singpasstest.LoginAs{NRIC: "S1234567D", UEN: "1"}, want: "must be 9 or 10 letters and digits"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, c := sp, spc
			if tc.corppass {
				srv, c = cp, cpc
			}
			ctx := context.Background()
			redirectURL, state, err := c.BeginLogin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			h := tc.header
			if h == nil {
				h = tc.as.Header()
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, redirectURL, nil)
			req.Header = h
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var e oauthError
			_ = json.NewDecoder(res.Body).Decode(&e)
			res.Body.Close()
			if res.StatusCode != http.StatusBadRequest || e.Error != "invalid_request" || !strings.Contains(e.Description, tc.want) {
				t.Fatalf("got %d %+v, want 400 invalid_request containing %q", res.StatusCode, e, tc.want)
			}

			// The rejected request didn't use up the login.
			query, err := srv.Authorize(ctx, redirectURL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Complete(ctx, query, state); err != nil {
				t.Fatalf("login after rejected headers: %v", err)
			}
		})
	}
}

func TestAuthorizeNeedsLoginAsWhenInteractive(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Interactive: true})
	if _, err := srv.Authorize(context.Background(), srv.Issuer()+"/auth"); err == nil || !strings.Contains(err.Error(), "non-interactive") {
		t.Errorf("Authorize on an interactive server: err = %v", err)
	}
}

func TestLoginAsHeader(t *testing.T) {
	h := singpasstest.LoginAs{NRIC: "S1234567D", UUID: "u", UEN: "e", Name: "n", Cancel: true}.Header()
	for name, want := range map[string]string{
		singpasstest.HeaderNRIC: "S1234567D", singpasstest.HeaderUUID: "u", singpasstest.HeaderUEN: "e",
		singpasstest.HeaderName: "n", singpasstest.HeaderError: "access_denied",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if h := (singpasstest.LoginAs{}).Header(); len(h) != 0 {
		t.Errorf("zero LoginAs headers = %v", h)
	}
}
