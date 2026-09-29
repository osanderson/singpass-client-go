package singpasstest

import "testing"

// FuzzParsePersonas: arbitrary persona files never panic, and an accepted
// file gives each persona a distinct subject.
func FuzzParsePersonas(f *testing.F) {
	f.Add([]byte(`[{"nric": "S1234567D", "userinfo": {"person_info": {"name": {"value": "X"}}, "iss": "x"}}]`))
	f.Add([]byte(`{"personas": [{"uen": "201912345K", "nric": "S1234567D", "userinfo": {"entity_info": {"basic_profile": {}}}}]}`))
	f.Add([]byte(`[{"nric": "S1234567D", "userinfo": {"person_info": 1}}]`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, issuer := range []Issuer{Singpass, Corppass} {
			ps, err := ParsePersonas(data, issuer)
			if err != nil {
				continue
			}
			seen := map[string]bool{}
			for _, p := range ps {
				if p.Subject == "" || seen[p.Subject] {
					t.Fatalf("persona subject %q empty or repeated", p.Subject)
				}
				seen[p.Subject] = true
			}
		}
	})
}
