package myinfo

import (
	"encoding/json"
	"reflect"
	"testing"
)

// personInfoResponse is a representative personal-Myinfo /userinfo claim map:
// a scalar field, two coded fields, an unavailable field, and two nested objects
// (phone, address), alongside the standard iss/aud/sub/iat claims.
func personInfoResponse() map[string]any {
	return map[string]any{
		"iss": "https://stg-id.singpass.gov.sg/fapi",
		"sub": "s=S1234567D",
		"aud": "client-123",
		"iat": float64(1746678089),
		"person_info": map[string]any{
			"name":        map[string]any{"value": "TAN XIAO HUI", "source": "1", "classification": "C", "lastupdated": "2024-09-26"},
			"nationality": map[string]any{"code": "SG", "desc": "SINGAPORE CITIZEN", "source": "1", "classification": "C", "lastupdated": "2024-09-26"},
			"sex":         map[string]any{"code": "F", "desc": "FEMALE", "source": "1", "classification": "C", "lastupdated": "2024-09-26"},
			"email":       map[string]any{"unavailable": true, "source": "2", "classification": "C", "lastupdated": "2024-09-26"},
			"mobileno": map[string]any{
				"source": "2", "classification": "C", "lastupdated": "2024-09-26",
				"prefix":   map[string]any{"value": "+"},
				"areacode": map[string]any{"value": "65"},
				"nbr":      map[string]any{"value": "91234567"},
			},
			"regadd": map[string]any{
				"type": "SG", "source": "1", "classification": "C", "lastupdated": "2024-09-26",
				"block": map[string]any{"value": "123"}, "street": map[string]any{"value": "BEDOK NORTH AVE 1"},
				"floor": map[string]any{"value": "12"}, "unit": map[string]any{"value": "34"},
				"postal": map[string]any{"value": "460123"},
			},
		},
	}
}

func TestMyinfoScalarAndCodedFields(t *testing.T) {
	m := Parse(personInfoResponse())

	if !m.Person.Present() {
		t.Fatal("Person block should be present")
	}
	if got := m.Person.Field("name").Value(); got != "TAN XIAO HUI" {
		t.Errorf("name Value() = %q, want TAN XIAO HUI", got)
	}
	if got := m.Person.Field("name").String(); got != "TAN XIAO HUI" {
		t.Errorf("name String() = %q, want TAN XIAO HUI", got)
	}
	if got := m.Person.Field("name").Source(); got != "1" {
		t.Errorf("name Source() = %q, want 1", got)
	}
	if got := m.Person.Field("name").LastUpdated(); got != "2024-09-26" {
		t.Errorf("name LastUpdated() = %q, want 2024-09-26", got)
	}

	// Coded field: Value is empty, Code/Desc set, String falls back to Desc.
	nat := m.Person.Field("nationality")
	if nat.Value() != "" {
		t.Errorf("nationality Value() = %q, want empty", nat.Value())
	}
	if nat.Code() != "SG" || nat.Desc() != "SINGAPORE CITIZEN" {
		t.Errorf("nationality code/desc = %q/%q, want SG/SINGAPORE CITIZEN", nat.Code(), nat.Desc())
	}
	if got := nat.String(); got != "SINGAPORE CITIZEN" {
		t.Errorf("nationality String() = %q, want SINGAPORE CITIZEN (desc fallback)", got)
	}
	if !nat.Available() {
		t.Error("nationality should be Available()")
	}
}

func TestMyinfoTypedSourceAndClassification(t *testing.T) {
	m := Parse(personInfoResponse())

	// name: source "1" → government-verified (authoritative), classification "C".
	name := m.Person.Field("name")
	if got := name.SourceCode(); got != SourceGovernmentVerified {
		t.Errorf("name SourceCode() = %v, want SourceGovernmentVerified", got)
	}
	if !name.SourceCode().Authoritative() {
		t.Error("government-verified source should be Authoritative()")
	}
	if got := name.SourceCode().String(); got != "government-verified" {
		t.Errorf("name SourceCode().String() = %q, want government-verified", got)
	}
	if got := name.ClassificationCode(); got != ClassificationConfidential || !got.Confidential() {
		t.Errorf("name ClassificationCode() = %v, want ClassificationConfidential/Confidential", got)
	}

	// email: source "2" → user-provided, NOT authoritative.
	email := m.Person.Field("email")
	if got := email.SourceCode(); got != SourceUserProvided {
		t.Errorf("email SourceCode() = %v, want SourceUserProvided", got)
	}
	if email.SourceCode().Authoritative() {
		t.Error("user-provided source should not be Authoritative()")
	}

	// Absent source/classification → the zero (unknown) typed values.
	bare := Field{m: map[string]any{"value": "x"}, present: true}
	if bare.SourceCode() != SourceUnknown || bare.ClassificationCode() != ClassificationUnknown {
		t.Errorf("bare field typed codes = %v/%v, want Unknown/Unknown", bare.SourceCode(), bare.ClassificationCode())
	}
	if bare.SourceCode().Authoritative() || bare.ClassificationCode().Confidential() {
		t.Error("unknown source/classification should be neither authoritative nor confidential")
	}
}

func TestMyinfoUnavailableAndAbsent(t *testing.T) {
	m := Parse(personInfoResponse())

	email := m.Person.Field("email")
	if !email.Present() {
		t.Error("email key is present in the response")
	}
	if !email.Unavailable() {
		t.Error("email should report Unavailable()")
	}
	if email.Available() {
		t.Error("email should not be Available()")
	}
	if got := email.String(); got != "" {
		t.Errorf("unavailable email String() = %q, want empty", got)
	}

	// A field the response never carried: zero Field, all accessors safe.
	absent := m.Person.Field("passportnumber")
	if absent.Present() || absent.Available() || absent.String() != "" {
		t.Errorf("absent field should be zero: present=%v available=%v str=%q", absent.Present(), absent.Available(), absent.String())
	}
}

func TestMyinfoNestedObjects(t *testing.T) {
	m := Parse(personInfoResponse())

	mob := m.Person.Object("mobileno")
	if !mob.Present() {
		t.Fatal("mobileno object should be present")
	}
	if got := mob.Field("nbr").Value(); got != "91234567" {
		t.Errorf("mobileno.nbr = %q, want 91234567", got)
	}
	if got := mob.Field("areacode").Value(); got != "65" {
		t.Errorf("mobileno.areacode = %q, want 65", got)
	}

	reg := m.Person.Object("regadd")
	if got := reg.Field("postal").Value(); got != "460123" {
		t.Errorf("regadd.postal = %q, want 460123", got)
	}

	// Object over an absent key is the zero Data. (A leaf field's envelope is
	// itself an object, so Object over a leaf is Present — harmless, and there
	// is no reliable signal to distinguish the two map shapes.)
	if m.Person.Object("nope").Present() {
		t.Error("Object() over an absent key should not be Present()")
	}
}

func TestMyinfoList(t *testing.T) {
	all := map[string]any{
		"person_info": map[string]any{
			"vehicles": []any{
				map[string]any{"vehicleno": map[string]any{"value": "SGX1234A"}},
				map[string]any{"vehicleno": map[string]any{"value": "SGY5678B"}},
			},
		},
	}
	m := Parse(all)
	vs := m.Person.List("vehicles")
	if len(vs) != 2 {
		t.Fatalf("List(vehicles) len = %d, want 2", len(vs))
	}
	if got := vs[0].Field("vehicleno").Value(); got != "SGX1234A" {
		t.Errorf("vehicles[0].vehicleno = %q, want SGX1234A", got)
	}
	if m.Person.List("name") != nil {
		t.Error("List() over a non-array should be nil")
	}
}

func TestMyinfoBusinessDoubleEncodedBlocks(t *testing.T) {
	// Corppass Myinfo Business delivers blocks as stringified JSON (double-
	// encoded). Parse must unwrap them so the accessor sees real objects.
	// Shapes match the real Corppass Myinfo Business /userinfo: entity data under
	// basic_profile (underscore), auth_info as Result_Set.ESrvc_Result[].
	all := map[string]any{
		"sub":         "client-123", // Corppass sub == client_id deviation
		"entity_info": `{"basic_profile":{"name":{"value":"ACME PTE LTD","source":"1","classification":"C","lastupdated":"2024-09-26"},"uen":{"value":"201912345A"}}}`,
		"auth_info":   `{"Result_Set":{"ESrvc_Row_Count":1,"ESrvc_Result":[{"CPESrvcID":"DEMO-SVC","Auth_Result_Set":{"Row_Count":1,"Row":[{"CPRole":"Admin","StartDate":"2024-01-01"}]}}]}}`,
	}
	m := Parse(all)

	if !m.Entity.Present() {
		t.Fatal("entity_info should be present after unwrapping")
	}
	bp := m.Entity.Object("basic_profile")
	if got := bp.Field("name").Value(); got != "ACME PTE LTD" {
		t.Errorf("basic_profile.name = %q, want ACME PTE LTD", got)
	}
	if got := bp.Field("uen").Value(); got != "201912345A" {
		t.Errorf("uen = %q, want 201912345A", got)
	}

	if !m.Auth.Present() {
		t.Fatal("auth_info should be present after unwrapping")
	}
	svcs := m.Auth.Object("Result_Set").List("ESrvc_Result")
	if len(svcs) != 1 || svcs[0].Field("CPESrvcID").Value() != "DEMO-SVC" {
		t.Fatalf("auth_info ESrvc_Result not unwrapped correctly: %+v", svcs)
	}
	rows := svcs[0].Object("Auth_Result_Set").List("Row")
	if len(rows) != 1 || rows[0].Field("CPRole").Value() != "Admin" {
		t.Errorf("auth_info role not unwrapped correctly: %+v", rows)
	}

	// Personal blocks are absent here.
	if m.Person.Present() {
		t.Error("person_info should be absent")
	}
}

func TestMyinfoBlocksAndRaw(t *testing.T) {
	m := Parse(personInfoResponse())

	blocks := m.Blocks()
	if len(blocks) != 1 || blocks[0] != "person_info" {
		t.Errorf("Blocks() = %v, want [person_info]", blocks)
	}

	// Raw exposes the full response, including the standard claims.
	if m.Raw()["iss"] != "https://stg-id.singpass.gov.sg/fapi" {
		t.Errorf("Raw() missing iss: %v", m.Raw()["iss"])
	}
	if _, ok := m.Raw()["person_info"]; !ok {
		t.Error("Raw() should include person_info")
	}
}

func TestMyinfoNilSafe(t *testing.T) {
	var m *Response
	if m.Raw() != nil || m.Blocks() != nil {
		t.Error("nil *Response accessors should return nil")
	}

	// Zero Data / Field are fully usable.
	var d Data
	if d.Present() || d.Has("x") || d.Keys() != nil || d.Field("x").Present() || d.Object("x").Present() || d.List("x") != nil {
		t.Error("zero Data accessors should be safe and empty")
	}
}

// TestResponseJSONRoundTrip checks a Response survives JSON encoding — how a
// stored session keeps the person data — with every block and accessor intact.
func TestResponseJSONRoundTrip(t *testing.T) {
	orig := Parse(personInfoResponse())
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var back Response
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Person.Field("name").String(); got != "TAN XIAO HUI" {
		t.Errorf("name after round trip = %q", got)
	}
	if got := back.Person.Object("regadd").Field("postal").String(); got != "460123" {
		t.Errorf("postal after round trip = %q", got)
	}
	if !reflect.DeepEqual(orig.Blocks(), back.Blocks()) {
		t.Errorf("blocks = %v, want %v", back.Blocks(), orig.Blocks())
	}

	var nilResp *Response
	if b, _ := json.Marshal(nilResp); string(b) != "null" {
		t.Errorf("nil Response marshals to %s, want null", b)
	}
}
