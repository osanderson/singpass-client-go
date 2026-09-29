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
		"act":      map[string]any{"sub": "s=S1234567D,u=user", "sub_type": "user", "sub_attributes": map[string]any{"name": "JOHN TAN"}},
		"sub_attributes": map[string]any{
			"entity_name":       "ACME PTE LTD",
			"entity_reg_number": "200012345A",
		},
	}}

	act := corppass.ActingParty()
	if act == nil {
		t.Fatal("ActingParty() = nil")
	}
	sa := corppass.SubjectAttributes()
	checkAll(t,
		check{"Issuer()", corppass.Issuer(), "https://stg-id.corppass.gov.sg"},
		check{"Audience()", corppass.Audience(), []string{"client-xyz"}},
		check{"SubjectType()", corppass.SubjectType(), "entity"},
		check{"AssuranceContext()", corppass.AssuranceContext(), "https://www.singpass.gov.sg/assurance/loa:2"},
		check{"AssuranceLevel()", corppass.AssuranceLevel(), "2"},
		check{"AuthMethods()", corppass.AuthMethods(), []string{"pwd", "otp"}},
		check{"ActingParty().Subject", act.Subject, "s=S1234567D,u=user"},
		check{"ActingParty().SubjectType", act.SubjectType, "user"},
		check{"ActingParty().Attributes.Name", act.Attributes.Name, "JOHN TAN"},
		check{"SubjectAttributes().EntityName", sa.EntityName, "ACME PTE LTD"},
		check{"SubjectAttributes().EntityRegNumber", sa.EntityRegNumber, "200012345A"},
		check{`SubjectAttributes().Raw["entity_name"]`, sa.Raw["entity_name"], "ACME PTE LTD"},
	)

	// aud as a JSON array and amr as a native []string (the shape AsMap yields).
	multi := &Identity{Claims: map[string]any{
		"aud": []any{"aud-a", "", "aud-b"}, // empties dropped
		"amr": []string{"pwd"},
	}}
	// A personal Login id_token: no act, no sub_attributes, acr not in loa form.
	personal := &Identity{Claims: map[string]any{
		"sub_type": "user",
		"acr":      "urn:custom:context",
	}}
	checkAll(t,
		check{"multi Audience()", multi.Audience(), []string{"aud-a", "aud-b"}},
		check{"multi AuthMethods()", multi.AuthMethods(), []string{"pwd"}},
		check{"personal ActingParty() is nil", personal.ActingParty() == nil, true},
		check{"personal SubjectAttributes().Present()", personal.SubjectAttributes().Present(), false},
		check{"personal AssuranceLevel() for a non-loa acr", personal.AssuranceLevel(), ""},
	)

	// Nil-safety: a nil receiver and an empty-claims Identity never panic, and
	// return zero values.
	var nilID *Identity
	empty := &Identity{}
	checkAll(t,
		check{"nil Issuer()", nilID.Issuer(), ""},
		check{"nil Audience()", nilID.Audience(), []string(nil)},
		check{"nil AuthMethods()", nilID.AuthMethods(), []string(nil)},
		check{"nil SubjectType()", nilID.SubjectType(), ""},
		check{"nil AssuranceLevel()", nilID.AssuranceLevel(), ""},
		check{"nil ActingParty() is nil", nilID.ActingParty() == nil, true},
		check{"nil SubjectAttributes().Present()", nilID.SubjectAttributes().Present(), false},
		check{"empty Issuer()", empty.Issuer(), ""},
		check{"empty Audience()", empty.Audience(), []string(nil)},
		check{"empty ActingParty() is nil", empty.ActingParty() == nil, true},
	)
}

// TestSubjectAttributesSingpassPerson checks the typed person fields, using the
// Singpass spec's example, and that unmodelled members stay reachable via Raw.
func TestSubjectAttributesSingpassPerson(t *testing.T) {
	id := &Identity{Claims: map[string]any{
		"sub_attributes": map[string]any{
			"account_type": "standard", "identity_number": "S1234567G", "identity_coi": "SG",
			"name": "JOHN DOE", "email": "johndoe@example.com", "mobileno": "91231234",
			"future_field": "kept",
		},
	}}
	a := id.SubjectAttributes()
	want := SubjectAttributes{
		AccountType: "standard", IdentityNumber: "S1234567G", IdentityCOI: "SG",
		Name: "JOHN DOE", Email: "johndoe@example.com", MobileNo: "91231234",
	}
	raw := a.Raw
	a.Raw = nil
	if !reflect.DeepEqual(a, want) {
		t.Errorf("SubjectAttributes() = %+v, want %+v", a, want)
	}
	if raw["future_field"] != "kept" {
		t.Error("Raw should keep members the struct doesn't model")
	}
}
