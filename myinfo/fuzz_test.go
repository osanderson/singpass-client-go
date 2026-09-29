package myinfo

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzParse feeds arbitrary /userinfo JSON through Parse, every typed
// profile and the generic accessors: none may panic, and a Response must
// survive a MarshalJSON / UnmarshalJSON round trip unchanged.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`{"person_info": {"name": {"value": "TAN", "source": "1"}, "dob": {"value": "1998-06-06"},
		  "regadd": {"type": "SG", "block": {"value": "1"}, "floor": {"value": "2"}, "unit": {"value": "3"}, "postal": {"value": "123456"}},
		  "mobileno": {"prefix": {"value": "+"}, "areacode": {"value": "65"}, "nbr": {"value": "91234567"}},
		  "cpfbalances": {"oa": {"value": 1.5}}, "vehicles": [{"make": {"value": "X"}}],
		  "noahistory": {"noas": [{"amount": {"value": 1}}]}, "childrenbirthrecords": [{"vaccinationrequirements": [{"fulfilled": {"value": true}}]}]}}`,
		`{"entity_info": "{\"basic_profile\":{\"name\":{\"value\":\"ACME\"}},\"appointments\":[{\"individual_appointment\":{\"name\":{\"value\":\"A\"}}}]}",
		  "corppass_info": {"email": "a@b", "email_verified": true},
		  "auth_info": {"Result_Set": {"ESrvc_Result": [{"CPESrvcID": "X", "Auth_Result_Set": {"Row": [{"CPRole": "R"}]}}]}}}`,
		`{"person_info": {"email": {"unavailable": true}}, "tp_auth_info": "[1,2"}`,
		`{"entity_info": {"financials": [{"company_financial": {"revenue": {"value": -1e308}}}], "history": {"previous_names": [null, 1]}}}`,
		`{}`, `{"person_info": null}`, `{"person_info": "\"{}\""}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var claims map[string]any
		if json.Unmarshal(data, &claims) != nil {
			return
		}
		r := Parse(claims)
		exercise(r)

		first, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		var again Response
		if err := json.Unmarshal(first, &again); err != nil {
			t.Fatalf("UnmarshalJSON of our own output: %v", err)
		}
		second, _ := json.Marshal(&again)
		if !bytes.Equal(first, second) {
			t.Fatalf("round trip changed the response:\n%s\n%s", first, second)
		}
	})
}

// exercise calls every accessor on r, typed and generic.
func exercise(r *Response) {
	p, e, c := r.PersonProfile(), r.EntityProfile(), r.CorppassProfile()
	_ = p.RegAdd.Lines()
	_ = p.RegAdd.String()
	_ = p.MobileNo.String() + p.MobileNo.E164()
	for _, f := range []Field{p.DOB, p.Name, p.CPFBalances.OA, p.OwnerPrivate, c.EmailVerified, e.RegistrationDate, e.PrimaryActivity} {
		_, _ = f.Date()
		_, _ = f.Int()
		_, _ = f.Float()
		_, _ = f.Bool()
		_ = f.Member("edition")
		_ = f.SourceCode().String() + f.ClassificationCode().String()
	}
	for _, h := range p.HDBOwnership {
		_ = h.Address.String()
	}
	for _, w := range p.CPFHousingWithdrawals {
		_ = w.Address.String()
	}
	_ = e.Address.String()
	_ = r.Blocks()
	for _, d := range []Data{r.Person, r.Entity, r.Corppass, r.Auth, r.TPAuth} {
		for _, l := range d.Leaves() {
			_ = l.Key() + l.Field.String()
		}
		_ = d.EffectiveSource()
		_ = d.Authorisations()
		_ = d.Appointments()
		_ = d.Shareholders()
		for _, k := range d.Keys() {
			_ = d.Kind(k)
			_ = Label(k)
		}
	}
}
