package singpasstest_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// A persona file mixing Singpass and Corppass users; the first pastes a whole
// decrypted /userinfo response.
const personaJSON = `[
  {"nric": "S1234567D", "userinfo": {
     "person_info": {
       "name": {"value": "TAN AH KOW", "source": "1", "classification": "C", "lastupdated": "2026-01-01"},
       "uinfin": {"value": "S1234567D", "source": "1", "classification": "C", "lastupdated": "2026-01-01"},
       "cpfbalances": {"source": "1", "classification": "C", "lastupdated": "2026-01-01", "oa": {"value": 12345.67}}
     },
     "iss": "https://stg-id.singpass.gov.sg/fapi", "aud": "old-client", "sub": "old-sub", "iat": 1700000000}},
  {"name": "Custom-named user", "nric": "T0123456G", "sub": "fixed-sub-1"},
  {"uen": "201912345K", "nric": "S1234567D", "userinfo": {
     "entity_info": {"basic_profile": {"name": {"value": "ACME PTE. LTD."}}}}}
]`

func TestParsePersonas(t *testing.T) {
	sp, err := singpasstest.ParsePersonas([]byte(personaJSON), singpasstest.Singpass)
	if err != nil {
		t.Fatal(err)
	}
	if len(sp) != 2 {
		t.Fatalf("%d Singpass personas, want 2", len(sp))
	}
	if sp[0].Name != "TAN AH KOW (custom)" || sp[0].SubAttributes["name"] != "TAN AH KOW" || sp[0].UserInfo["iss"] != nil || sp[0].UserInfo["sub"] != nil {
		t.Errorf("pasted response persona = %+v", sp[0])
	}
	if sp[1].Name != "Custom-named user" || sp[1].Subject != "fixed-sub-1" {
		t.Errorf("named persona = %+v", sp[1])
	}

	cp, err := singpasstest.ParsePersonas([]byte(`{"personas": `+personaJSON+`}`), singpasstest.Corppass)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp) != 1 || cp[0].Subject != "201912345K" || !strings.HasPrefix(cp[0].Name, "ACME PTE. LTD.") || cp[0].Act == nil {
		t.Errorf("Corppass personas = %+v", cp)
	}
}

func TestParsePersonasErrors(t *testing.T) {
	for name, tc := range map[string]struct{ json, want string }{
		"not JSON":      {`nope`, "want a JSON list"},
		"bad NRIC":      {`[{"nric": "1234"}]`, "persona 1: NRIC / FIN"},
		"unknown block": {`[{"nric": "S1234567D", "userinfo": {"personinfo": {}}}]`, `unknown block "personinfo"`},
		"block type":    {`[{"nric": "S1234567D", "userinfo": {"person_info": "x"}}]`, "must be an object"},
		"duplicate":     {`[{"nric": "S1234567D"}, {"nric": "s1234567d"}]`, "used more than once"},
	} {
		if _, err := singpasstest.ParsePersonas([]byte(tc.json), singpasstest.Singpass); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestLoadedPersonaLogsIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "personas.json")
	if err := os.WriteFile(path, []byte(personaJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := singpasstest.LoadPersonas(path, singpasstest.Singpass)
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, singpasstest.Config{Personas: ps})
	if err := srv.SetPersona(ps[0].Subject); err != nil {
		t.Fatal(err)
	}
	k := newKeys(t)
	register(t, srv, "mi", singpasstest.Myinfo, []string{"name", "uinfin", "cpfbalances"}, k)
	c, err := singpass.NewMyinfo(context.Background(), singpass.MyinfoOptions{
		Issuer: srv.Issuer(), ClientID: "mi", RedirectURI: redirectURI, Scopes: []string{"openid", "name", "uinfin", "cpfbalances"},
		SigningKey: k.sig, SigningKID: "sig-1", EncryptionKey: k.enc, EncryptionKID: "enc-1",
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	p := login(t, srv, c).Myinfo.PersonProfile()
	if oa, _ := p.CPFBalances.OA.Float(); p.Name.String() != "TAN AH KOW" || oa != 12345.67 {
		t.Errorf("loaded persona's data = %q, %v", p.Name.String(), oa)
	}
}

func TestEnvelopeHelpers(t *testing.T) {
	if v := singpasstest.Value(42); v["value"] != 42 || v["source"] != "1" {
		t.Errorf("Value = %v", v)
	}
	if c := singpasstest.Coded("SG", "SINGAPORE CITIZEN"); c["code"] != "SG" || c["desc"] != "SINGAPORE CITIZEN" {
		t.Errorf("Coded = %v", c)
	}
}
