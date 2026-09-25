package singpass

import (
	"reflect"
	"testing"
)

// TestIDTokenAccessors covers the typed id_token claim accessors: issuer, the
// string-or-array aud, the amr array (both []any and native []string forms), the
// Singpass sub_type, the "…:loa:N" acr parsing, the Corppass act actor object, and
// sub_attributes — plus nil-safety on an absent claim and a nil receiver.
func TestIDTokenAccessors(t *testing.T) {
	// A Corppass Myinfo Business-shaped id_token: entity subject, an acting user,
	// entity descriptors, single-string aud, amr as a JSON []any.
	corppass := &Identity{Claims: map[string]any{
		"iss":      "https://stg-id.corppass.gov.sg",
		"aud":      "client-xyz",
		"sub_type": "entity",
		"acr":      "https://www.singpass.gov.sg/assurance/loa:2",
		"amr":      []any{"pwd", "otp"},
		"act":      map[string]any{"sub": "s=S1234567D,u=user", "sub_type": "user"},
		"sub_attributes": map[string]any{
			"entity_name":       "ACME PTE LTD",
			"entity_reg_number": "200012345A",
		},
	}}

	if got := corppass.Issuer(); got != "https://stg-id.corppass.gov.sg" {
		t.Errorf("Issuer() = %q", got)
	}
	if got := corppass.Audience(); !reflect.DeepEqual(got, []string{"client-xyz"}) {
		t.Errorf("Audience() = %v, want [client-xyz]", got)
	}
	if got := corppass.SubjectType(); got != "entity" {
		t.Errorf("SubjectType() = %q, want entity", got)
	}
	if got := corppass.AssuranceContext(); got != "https://www.singpass.gov.sg/assurance/loa:2" {
		t.Errorf("AssuranceContext() = %q", got)
	}
	if got := corppass.AssuranceLevel(); got != "2" {
		t.Errorf("AssuranceLevel() = %q, want 2", got)
	}
	if got := corppass.AuthMethods(); !reflect.DeepEqual(got, []string{"pwd", "otp"}) {
		t.Errorf("AuthMethods() = %v, want [pwd otp]", got)
	}
	act := corppass.ActingParty()
	if act == nil || act.Subject != "s=S1234567D,u=user" || act.SubjectType != "user" {
		t.Errorf("ActingParty() = %+v", act)
	}
	sa := corppass.SubjectAttributes()
	if sa["entity_name"] != "ACME PTE LTD" || sa["entity_reg_number"] != "200012345A" {
		t.Errorf("SubjectAttributes() = %+v", sa)
	}

	// aud as a JSON array and amr as a native []string (the shape AsMap yields).
	multi := &Identity{Claims: map[string]any{
		"aud": []any{"aud-a", "", "aud-b"}, // empties dropped
		"amr": []string{"pwd"},
	}}
	if got := multi.Audience(); !reflect.DeepEqual(got, []string{"aud-a", "aud-b"}) {
		t.Errorf("Audience() = %v, want [aud-a aud-b]", got)
	}
	if got := multi.AuthMethods(); !reflect.DeepEqual(got, []string{"pwd"}) {
		t.Errorf("AuthMethods() = %v, want [pwd]", got)
	}

	// A personal Login id_token: no act, no sub_attributes, acr not in loa form.
	personal := &Identity{Claims: map[string]any{
		"sub_type": "user",
		"acr":      "urn:custom:context",
	}}
	if personal.ActingParty() != nil {
		t.Errorf("ActingParty() should be nil without an act claim")
	}
	if personal.SubjectAttributes() != nil {
		t.Errorf("SubjectAttributes() should be nil without the claim")
	}
	if got := personal.AssuranceLevel(); got != "" {
		t.Errorf("AssuranceLevel() = %q, want empty for non-loa acr", got)
	}

	// Nil-safety: a nil receiver and an empty-claims Identity never panic.
	var nilID *Identity
	if nilID.Issuer() != "" || nilID.Audience() != nil || nilID.AuthMethods() != nil ||
		nilID.SubjectType() != "" || nilID.AssuranceLevel() != "" ||
		nilID.ActingParty() != nil || nilID.SubjectAttributes() != nil {
		t.Errorf("nil Identity accessors should return zero values")
	}
	empty := &Identity{}
	if empty.Issuer() != "" || empty.Audience() != nil || empty.ActingParty() != nil {
		t.Errorf("empty Identity accessors should return zero values")
	}
}
