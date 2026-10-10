package singpasstest

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/idfoundry/fapigo/server"
)

// Value returns a Myinfo data item with a value — the envelope /userinfo
// uses, government-verified — for writing Persona.UserInfo in code:
//
//	"name": singpasstest.Value("TAN AH KOW"),
//	"cpfbalances": map[string]any{"oa": singpasstest.Value(1000.5)},
func Value(v any) map[string]any { return field(v) }

// Coded returns a coded Myinfo data item, e.g. Coded("SG", "SINGAPORE
// CITIZEN"), in the same envelope as Value.
func Coded(code, desc string) map[string]any { return coded(code, desc) }

// personaFile is the JSON format LoadPersonas reads: a list of test users,
// or an object with a "personas" list.
type personaEntry struct {
	// Name is shown on the sign-in page. Empty means the Myinfo name, or the
	// NRIC or UEN.
	Name string `json:"name"`
	// NRIC is the person's NRIC or FIN: the Singpass user, or on Corppass the
	// person acting for the entity.
	NRIC string `json:"nric"`
	// PersonName is the person's name for the id_token; empty means the Myinfo
	// name, or Name.
	PersonName string `json:"person_name"`
	// UEN and EntityName make the entry a Corppass entity.
	UEN        string `json:"uen"`
	EntityName string `json:"entity_name"`
	// Sub overrides the id_token subject of a Singpass user; empty means a
	// stable UUID derived from the NRIC. At most 255 printable ASCII
	// characters (OIDC Core §2).
	Sub string   `json:"sub"`
	ACR string   `json:"acr"`
	AMR []string `json:"amr"`
	// UserInfo is the /userinfo data: person_info (and, on Corppass,
	// entity_info, corppass_info, auth_info, tp_auth_info). A whole decrypted
	// /userinfo response can be pasted in; its iss, aud, sub and iat are
	// ignored, as the server sets them.
	UserInfo map[string]any `json:"userinfo"`
}

// userInfoBlocks are the /userinfo blocks a persona may carry; the claims the
// server sets itself are dropped when a whole response is pasted in.
var (
	userInfoBlocks  = map[string]bool{"person_info": true, "entity_info": true, "corppass_info": true, "auth_info": true, "tp_auth_info": true}
	serverSetClaims = map[string]bool{"iss": true, "aud": true, "sub": true, "iat": true, "exp": true}
)

// LoadPersonas reads test users for issuer from a JSON file, e.g. for
// Config.Personas:
//
//	[
//	  {"nric": "S1234567D", "userinfo": {"person_info": {"name": {"value": "TAN AH KOW"}}}},
//	  {"uen": "201912345K", "entity_name": "ACME PTE. LTD.", "nric": "S1234567D",
//	   "userinfo": {"entity_info": {"basic_profile": {"name": {"value": "ACME PTE. LTD."}}}}}
//	]
//
// An entry with a "uen" is a Corppass entity, acting through the person
// "nric"; one without is a Singpass user. Entries for the other issuer are
// skipped, so one file can serve both servers. "userinfo" is the /userinfo
// data in Myinfo's shape — a real staging response, such as the demo's raw
// /userinfo view, can be pasted in whole. Without it, a user gets the data
// UserPersona or EntityPersona gives.
func LoadPersonas(path string, issuer Issuer) ([]Persona, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ps, err := ParsePersonas(raw, issuer)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ps, nil
}

// ParsePersonas is LoadPersonas for JSON already in memory.
func ParsePersonas(data []byte, issuer Issuer) ([]Persona, error) {
	var entries []personaEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		var wrapped struct {
			Personas []personaEntry `json:"personas"`
		}
		if err2 := json.Unmarshal(data, &wrapped); err2 != nil || wrapped.Personas == nil {
			return nil, fmt.Errorf("want a JSON list of personas, or {\"personas\": [...]}: %w", err)
		}
		entries = wrapped.Personas
	}
	var out []Persona
	seen := map[string]bool{}
	for i, e := range entries {
		corppass := strings.TrimSpace(e.UEN) != ""
		if corppass != (issuer == Corppass) {
			continue
		}
		p, err := e.persona(corppass)
		if err != nil {
			return nil, fmt.Errorf("persona %d: %w", i+1, err)
		}
		if err := checkSubject(p.Subject); err != nil {
			return nil, fmt.Errorf("persona %d: %w", i+1, err)
		}
		if seen[p.Subject] {
			return nil, fmt.Errorf("persona %d: subject %q is used more than once", i+1, p.Subject)
		}
		seen[p.Subject] = true
		out = append(out, p)
	}
	return out, nil
}

func (e personaEntry) persona(corppass bool) (Persona, error) {
	if err := checkCustom(e.NRIC, e.UEN, corppass); err != nil {
		return Persona{}, err
	}
	info := map[string]any{}
	for k, v := range e.UserInfo {
		switch {
		case userInfoBlocks[k]:
			if _, ok := v.(map[string]any); !ok {
				return Persona{}, fmt.Errorf("userinfo %q must be an object", k)
			}
			info[k] = v
		case serverSetClaims[k]:
			// Set by the server; dropped from a pasted response.
		default:
			return Persona{}, fmt.Errorf("userinfo has an unknown block %q (want person_info, entity_info, corppass_info, auth_info or tp_auth_info)", k)
		}
	}
	personName := firstNonEmpty(e.PersonName, myinfoName(info["person_info"]))
	var p Persona
	if corppass {
		p = EntityPersona(e.UEN, firstNonEmpty(e.EntityName, myinfoName(entityProfile(info))), e.NRIC, personName)
	} else {
		p = UserPersona(e.NRIC, firstNonEmpty(personName, e.Name))
		if e.Sub != "" {
			p.Subject = e.Sub
		}
	}
	if e.Name != "" {
		p.Name = e.Name
	}
	if len(info) > 0 {
		p.UserInfo = info
	}
	p.ACR, p.AMR = e.ACR, e.AMR
	return p, nil
}

// myinfoName reads the "name" item's value from a person_info or
// basic_profile object.
func myinfoName(block any) string {
	m, _ := block.(map[string]any)
	name, _ := m["name"].(map[string]any)
	s, _ := name["value"].(string)
	return s
}

func entityProfile(info map[string]any) any {
	e, _ := info["entity_info"].(map[string]any)
	return e["basic_profile"]
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// checkSubject reports a subject the server can't issue: OIDC Core §2 limits
// "sub" to 255 ASCII characters, and FAPIgo refuses longer, non-ASCII or
// control characters. Checked when personas load, so a bad one is named at
// startup rather than failing its login with a 500.
func checkSubject(sub string) error {
	if _, err := server.NewSubjectID(sub); err != nil {
		return fmt.Errorf("subject %q: %w", sub, err)
	}
	return nil
}
