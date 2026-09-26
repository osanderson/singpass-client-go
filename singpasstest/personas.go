package singpasstest

import (
	"encoding/json"
	"strings"
)

// Persona is a test user the fake authorization server can sign in. The data is
// fictitious but shaped like real Singpass / Corppass responses.
type Persona struct {
	// Name is shown on the sign-in page.
	Name string
	// Subject is the id_token "sub": a Singpass UUID for a person, or — on
	// Corppass, where the subject is the organisation — its registration
	// number (UEN).
	Subject string
	// SubjectType is the id_token "sub_type". Empty means "user" on Singpass
	// and "entity" on Corppass.
	SubjectType string
	// SubAttributes is the id_token "sub_attributes". On Singpass each item is
	// released only with its scope, as Singpass does: user.identity gives
	// account_type, identity_number and identity_coi; the name, email and
	// mobileno scopes give the same-named item. On Corppass they describe the
	// entity (entity_type, entity_reg_number, entity_coi, entity_name,
	// entity_uen_status) and are always sent.
	SubAttributes map[string]any
	// Act is the Corppass "act" claim: the person acting for the entity.
	Act *Actor
	// ACR and AMR are the id_token's "acr" and "amr". Empty ACR means
	// "urn:singpass:authentication:loa:2"; nil AMR means ["pwd", "otp-sms"].
	ACR string
	AMR []string
	// UserInfo holds the /userinfo data blocks for Myinfo clients: for
	// Singpass a "person_info" object; for Corppass any of "entity_info",
	// "person_info", "corppass_info", "auth_info" and "tp_auth_info". "sub",
	// "iss" and "aud" are set by the server.
	UserInfo map[string]any
}

// Actor is the person in a Corppass "act" claim.
type Actor struct {
	// Subject is the person's Singpass UUID.
	Subject string
	// SubjectType is "act.sub_type"; empty means "user".
	SubjectType string
	// SubAttributes describe the person: account_type, identity_number,
	// identity_coi and name.
	SubAttributes map[string]any
}

// singpassScopeAttributes maps a Singpass scope to the sub_attributes items it
// releases.
var singpassScopeAttributes = map[string][]string{
	"user.identity": {"account_type", "identity_number", "identity_coi"},
	"name":          {"name"},
	"email":         {"email"},
	"mobileno":      {"mobileno"},
}

// idTokenClaims builds the Singpass/Corppass-specific id_token claims for p
// under the granted scopes.
func (p Persona) idTokenClaims(issuer Issuer, scope []string) (map[string]json.RawMessage, error) {
	claims := map[string]any{}
	subType := p.SubjectType
	if subType == "" {
		subType = "user"
		if issuer == Corppass {
			subType = "entity"
		}
	}
	claims["sub_type"] = subType

	attrs := p.SubAttributes
	if issuer == Singpass {
		attrs = map[string]any{}
		for _, sc := range scope {
			for _, k := range singpassScopeAttributes[strings.TrimSpace(sc)] {
				if v, ok := p.SubAttributes[k]; ok {
					attrs[k] = v
				}
			}
		}
	}
	if len(attrs) > 0 {
		claims["sub_attributes"] = attrs
	}
	if p.Act != nil {
		act := map[string]any{"sub": p.Act.Subject, "sub_type": p.Act.SubjectType}
		if p.Act.SubjectType == "" {
			act["sub_type"] = "user"
		}
		if len(p.Act.SubAttributes) > 0 {
			act["sub_attributes"] = p.Act.SubAttributes
		}
		claims["act"] = act
	}

	out := make(map[string]json.RawMessage, len(claims))
	for k, v := range claims {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[k] = raw
	}
	return out, nil
}

func (p Persona) acr() string {
	if p.ACR == "" {
		return "urn:singpass:authentication:loa:2"
	}
	return p.ACR
}

func (p Persona) amr() []string {
	if p.AMR == nil {
		return []string{"pwd", "otp-sms"}
	}
	return p.AMR
}

// field builds a Myinfo leaf envelope with government-verified provenance.
func field(value any) map[string]any {
	return map[string]any{"value": value, "source": "1", "classification": "C", "lastupdated": "2026-01-15"}
}

// coded builds a Myinfo coded envelope (code + human description).
func coded(code, desc string) map[string]any {
	return map[string]any{"code": code, "desc": desc, "source": "1", "classification": "C", "lastupdated": "2026-01-15"}
}

// DefaultPersonas returns the built-in test users for issuer: two Singpass
// citizens (one with a vehicle, one whose email Myinfo can't provide), or one
// Corppass user acting for a company.
func DefaultPersonas(issuer Issuer) []Persona {
	if issuer == Corppass {
		return []Persona{{
			Name:    "Lim Wei Ming for Harbourfront Trading Pte. Ltd.",
			Subject: "201912345K",
			SubAttributes: map[string]any{
				"entity_type": "UEN", "entity_reg_number": "201912345K", "entity_coi": "SG",
				"entity_name": "HARBOURFRONT TRADING PTE. LTD.", "entity_uen_status": "Registered",
			},
			Act: &Actor{
				Subject: "1d8e6a9c-3b44-4f0e-9d2a-5c7b1e8f2a60",
				SubAttributes: map[string]any{
					"account_type": "standard", "identity_number": "S7812345J", "identity_coi": "SG", "name": "LIM WEI MING",
				},
			},
			UserInfo: map[string]any{
				"entity_info": map[string]any{
					"basic_profile": map[string]any{
						"name":                field("HARBOURFRONT TRADING PTE. LTD."),
						"registration_number": field("201912345K"),
						"uen_status":          coded("R", "REGISTERED"),
						"company_type":        coded("P", "PRIVATE COMPANY LIMITED BY SHARES"),
					},
					"address": map[string]any{
						"source": "1", "classification": "C", "lastupdated": "2026-01-15",
						"block": field("10"), "street": field("HARBOURFRONT AVENUE"),
						"floor": field("08"), "unit": field("01"), "postal": field("098632"),
						"country": coded("SG", "SINGAPORE"),
					},
					"appointments": []any{map[string]any{
						"source": "1", "classification": "C", "lastupdated": "2026-01-15",
						"position":               coded("D", "DIRECTOR"),
						"appointment_date":       field("2019-06-01"),
						"individual_appointment": map[string]any{"name": field("LIM WEI MING")},
					}},
				},
				"auth_info": map[string]any{
					"Result_Set": map[string]any{
						"ESrvc_Row_Count": 1,
						"ESrvc_Result": []any{map[string]any{
							"CPESrvcID": "SINGPASSTEST-ESERVICE",
							"Auth_Result_Set": map[string]any{
								"Row_Count": 1,
								"Row": []any{map[string]any{
									"CPEntID_SUB": "", "CPRole": "Approver",
									"StartDate": "2024-01-01", "EndDate": "9999-12-31",
									"Parameter": []any{},
								}},
							},
						}},
					},
				},
			},
		}}
	}
	return []Persona{
		{
			Name:    "Tan Xiao Hui",
			Subject: "a9865837-7bd7-46ac-bef4-42a76a946424",
			SubAttributes: map[string]any{
				"account_type": "standard", "identity_number": "S9812381D", "identity_coi": "SG",
				"name": "TAN XIAO HUI", "email": "tan.xiaohui@example.com", "mobileno": "97399245",
			},
			UserInfo: map[string]any{"person_info": map[string]any{
				"uinfin":            field("S9812381D"),
				"name":              field("TAN XIAO HUI"),
				"sex":               coded("F", "FEMALE"),
				"race":              coded("CN", "CHINESE"),
				"nationality":       coded("SG", "SINGAPORE CITIZEN"),
				"residentialstatus": coded("C", "CITIZEN"),
				"dob":               field("1998-06-06"),
				"email":             map[string]any{"value": "tan.xiaohui@example.com", "source": "2", "classification": "C", "lastupdated": "2026-01-15"},
				"mobileno": map[string]any{
					"source": "2", "classification": "C", "lastupdated": "2026-01-15",
					"prefix": map[string]any{"value": "+"}, "areacode": map[string]any{"value": "65"},
					"nbr": map[string]any{"value": "97399245"},
				},
				"regadd": map[string]any{
					"type": "SG", "source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"block": map[string]any{"value": "102"}, "street": map[string]any{"value": "BEDOK NORTH AVENUE 4"},
					"floor": map[string]any{"value": "09"}, "unit": map[string]any{"value": "128"},
					"postal":  map[string]any{"value": "460102"},
					"country": map[string]any{"code": "SG", "desc": "SINGAPORE"},
				},
				"vehicles": []any{map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"vehicleno": map[string]any{"value": "SBA1234A"},
					"make":      map[string]any{"value": "TOYOTA"},
					"model":     map[string]any{"value": "COROLLA ALTIS"},
				}},
			}},
		},
		{
			Name:    "Muhammad Hafiz",
			Subject: "5f2c7e10-8a3d-4b9e-a1c6-0d4e2f9b7c35",
			SubAttributes: map[string]any{
				"account_type": "standard", "identity_number": "S8012345F", "identity_coi": "SG",
				"name": "MUHAMMAD HAFIZ BIN ISMAIL",
			},
			UserInfo: map[string]any{"person_info": map[string]any{
				"uinfin":            field("S8012345F"),
				"name":              field("MUHAMMAD HAFIZ BIN ISMAIL"),
				"sex":               coded("M", "MALE"),
				"race":              coded("MY", "MALAY"),
				"nationality":       coded("SG", "SINGAPORE CITIZEN"),
				"residentialstatus": coded("C", "CITIZEN"),
				"dob":               field("1980-11-23"),
				"email":             map[string]any{"unavailable": true, "source": "2", "classification": "C", "lastupdated": "2026-01-15"},
				"regadd": map[string]any{
					"type": "SG", "source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"block": map[string]any{"value": "55"}, "street": map[string]any{"value": "JURONG WEST STREET 42"},
					"floor": map[string]any{"value": "12"}, "unit": map[string]any{"value": "305"},
					"postal":  map[string]any{"value": "640055"},
					"country": map[string]any{"code": "SG", "desc": "SINGAPORE"},
				},
			}},
		},
	}
}
