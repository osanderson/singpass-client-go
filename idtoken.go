package singpass

import (
	"strconv"
	"strings"
)

// This file adds typed accessors over the validated id_token claims that FAPIgo
// hands us in Identity.Claims. The claims themselves have already been signature-,
// issuer-, audience-, nonce- and expiry-validated before we read them here — these
// accessors just encapsulate the Singpass/Corppass claim *shapes* (aud being a
// string or an array; amr's array; the Corppass "act" actor object; "sub_type";
// "sub_attributes"; the "…:loa:N" acr) so an integrator need not re-parse the raw
// map by hand. Every accessor is nil-safe on both the receiver and an absent claim.

// Issuer returns the id_token "iss" — the OP that issued the token (the FAPI
// issuer, already validated). Empty when absent.
func (id *Identity) Issuer() string {
	if id == nil {
		return ""
	}
	return asString(id.Claims["iss"])
}

// Audience returns the id_token "aud" — the client_id(s) the token was issued to.
// OIDC permits aud to be a single string or an array of strings; this normalises
// both to a slice (and tolerates FAPIgo's AsMap handing back a native []string).
// Empty values are dropped; nil when the claim is absent.
func (id *Identity) Audience() []string {
	if id == nil {
		return nil
	}
	return stringSliceClaim(id.Claims["aud"])
}

// AuthMethods returns the "amr" authentication-methods references (how the user
// authenticated), or nil when absent. Like Audience it accepts both a []string
// (as AsMap yields) and a JSON []any.
func (id *Identity) AuthMethods() []string {
	if id == nil {
		return nil
	}
	return stringSliceClaim(id.Claims["amr"])
}

// SubjectType returns the Singpass "sub_type" — "user" for a person, "entity" for
// an organisation login (Corppass Myinfo Business). Empty when the claim is absent.
func (id *Identity) SubjectType() string {
	if id == nil {
		return ""
	}
	return asString(id.Claims["sub_type"])
}

// AssuranceContext returns the raw "acr" authentication-context-class the OP
// asserted (e.g. a "…:loa:2" string). Empty when absent. Use AssuranceLevel for
// the parsed Level of Assurance.
func (id *Identity) AssuranceContext() string {
	if id == nil {
		return ""
	}
	return asString(id.Claims["acr"])
}

// AssuranceLevel extracts the Level of Assurance from a Singpass/Corppass acr of
// the form "…:loa:N" — returning the value after "loa:" (e.g. "2"). Empty when acr
// is absent or not in that form.
func (id *Identity) AssuranceLevel() string {
	acr := id.AssuranceContext()
	if i := strings.LastIndex(acr, "loa:"); i >= 0 {
		return acr[i+len("loa:"):]
	}
	return ""
}

// SubjectAttributes are the "sub_attributes" descriptor claims about a subject,
// with the members Singpass and Corppass define as typed fields. Which fields
// are set depends on the subject and the granted scopes; unset fields are "".
//
// For a person (Singpass Login / Myinfo, or the acting person in a Corppass
// login) Singpass releases each item with its scope: user.identity gives
// AccountType, IdentityNumber and IdentityCOI; the name, email and mobileno
// scopes give Name, Email and MobileNo. For a Corppass entity the Entity* fields
// describe the organisation.
type SubjectAttributes struct {
	AccountType    string // account_type: "standard" (citizen / PR) or "foreign"
	IdentityNumber string // identity_number: NRIC, FIN or foreign ID number
	IdentityCOI    string // identity_coi: the ID's country of issuance, e.g. "SG"
	Name           string // name
	Email          string // email
	MobileNo       string // mobileno (absent for foreign account holders)

	EntityType      string // entity_type: "UEN", "NON-UEN" or "GSTN"
	EntityRegNumber string // entity_reg_number, e.g. the UEN
	EntityCOI       string // entity_coi: country of incorporation
	EntityName      string // entity_name
	EntityUENStatus string // entity_uen_status: "Registered", "Deregistered", "Withdrawn"

	// Raw is the claim as sent, including any member not modelled above; nil
	// when the token carries no sub_attributes.
	Raw map[string]any
}

// Present reports whether the token carried the sub_attributes claim.
func (a SubjectAttributes) Present() bool { return a.Raw != nil }

func parseSubjectAttributes(v any) SubjectAttributes {
	m, _ := v.(map[string]any)
	return SubjectAttributes{
		AccountType:     asString(m["account_type"]),
		IdentityNumber:  asString(m["identity_number"]),
		IdentityCOI:     asString(m["identity_coi"]),
		Name:            asString(m["name"]),
		Email:           asString(m["email"]),
		MobileNo:        asString(m["mobileno"]),
		EntityType:      asString(m["entity_type"]),
		EntityRegNumber: asString(m["entity_reg_number"]),
		EntityCOI:       asString(m["entity_coi"]),
		EntityName:      asString(m["entity_name"]),
		EntityUENStatus: asString(m["entity_uen_status"]),
		Raw:             m,
	}
}

// ActingParty is the "act" (actor) claim: for Corppass, the person who
// authenticated on behalf of the entity, distinct from the entity Subject.
type ActingParty struct {
	Subject     string // act.sub — the acting person's Singpass identifier
	SubjectType string // act.sub_type — typically "user"
	// Attributes is act.sub_attributes, describing the person: Corppass sends
	// AccountType, IdentityNumber, IdentityCOI and Name.
	Attributes SubjectAttributes
}

// ActingParty returns the "act" actor claim, or nil when the token carries none
// (personal Login / Myinfo, where the subject is the person themselves).
func (id *Identity) ActingParty() *ActingParty {
	if id == nil {
		return nil
	}
	act, ok := id.Claims["act"].(map[string]any)
	if !ok {
		return nil
	}
	return &ActingParty{
		Subject:     asString(act["sub"]),
		SubjectType: asString(act["sub_type"]),
		Attributes:  parseSubjectAttributes(act["sub_attributes"]),
	}
}

// SubjectAttributes returns the "sub_attributes" claim about the subject: a
// Singpass person's identity details released by the granted scopes, or a
// Corppass entity's details. The zero value (Present false) when the claim is
// absent.
func (id *Identity) SubjectAttributes() SubjectAttributes {
	if id == nil {
		return SubjectAttributes{}
	}
	return parseSubjectAttributes(id.Claims["sub_attributes"])
}

// stringSliceClaim normalises a claim that OIDC allows to be a single string or an
// array of strings into a slice, dropping empty entries. It accepts a plain string,
// a []string (as FAPIgo's AsMap hands back for typed claims like aud / amr) and a
// JSON-decoded []any; anything else yields nil.
func stringSliceClaim(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		var out []string
		for _, s := range t {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// asString coerces a decoded JSON scalar claim to a string: strings pass through;
// JSON numbers (float64) are formatted without a trailing ".0"; bools render as
// "true"/"false"; anything else (or nil) yields "".
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}
