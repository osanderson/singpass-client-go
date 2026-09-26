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

// ActingParty is the "act" (actor) claim: for Corppass, the person who
// authenticated on behalf of the entity, distinct from the entity Subject.
type ActingParty struct {
	Subject     string // act.sub — the acting person's Singpass identifier
	SubjectType string // act.sub_type — typically "user"
	// Attributes is act.sub_attributes, describing the person: Corppass sends
	// account_type, identity_number, identity_coi and name. Nil when absent.
	Attributes map[string]any
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
	attrs, _ := act["sub_attributes"].(map[string]any)
	return &ActingParty{
		Subject:     asString(act["sub"]),
		SubjectType: asString(act["sub_type"]),
		Attributes:  attrs,
	}
}

// SubjectAttributes returns the "sub_attributes" descriptor claims about the
// subject. For a Singpass person they are released per scope — user.identity
// gives account_type, identity_number and identity_coi; name, email and
// mobileno give the same-named item. For a Corppass entity they are the
// entity's type, registration number, country, name and UEN status. Its members
// are flow-specific, so it is returned as the raw object for the caller to
// read; nil when the claim is absent.
func (id *Identity) SubjectAttributes() map[string]any {
	if id == nil {
		return nil
	}
	sa, _ := id.Claims["sub_attributes"].(map[string]any)
	return sa
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
