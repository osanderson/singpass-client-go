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
	// number (UEN). At most 255 printable ASCII characters (OIDC Core §2):
	// NewServer refuses any other.
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
	claims := map[string]any{"sub_type": p.subjectType(issuer)}
	if attrs := p.grantedAttributes(issuer, scope); len(attrs) > 0 {
		claims["sub_attributes"] = attrs
	}
	if p.Act != nil {
		claims["act"] = p.Act.claim()
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

// claim is the act claim for a: the acting person, with sub_type "user"
// unless set.
func (a *Actor) claim() map[string]any {
	act := map[string]any{"sub": a.Subject, "sub_type": a.SubjectType}
	if a.SubjectType == "" {
		act["sub_type"] = "user"
	}
	if len(a.SubAttributes) > 0 {
		act["sub_attributes"] = a.SubAttributes
	}
	return act
}

// subjectType is p's sub_type: as set, or else "user" on Singpass and
// "entity" on Corppass.
func (p Persona) subjectType(issuer Issuer) string {
	switch {
	case p.SubjectType != "":
		return p.SubjectType
	case issuer == Corppass:
		return "entity"
	default:
		return "user"
	}
}

// grantedAttributes are the sub_attributes the id_token carries: on Singpass
// only those the granted scopes release, on Corppass all of them.
func (p Persona) grantedAttributes(issuer Issuer, scope []string) map[string]any {
	if issuer != Singpass {
		return p.SubAttributes
	}
	attrs := map[string]any{}
	for _, sc := range scope {
		for _, k := range singpassScopeAttributes[strings.TrimSpace(sc)] {
			if v, ok := p.SubAttributes[k]; ok {
				attrs[k] = v
			}
		}
	}
	return attrs
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

// DefaultPersonas returns the built-in test users for issuer. On Singpass:
// Tan Xiao Hui, a citizen with a vehicle and CPF contribution history;
// Muhammad Hafiz, a citizen whose email Myinfo can't provide, with CPF
// balances, income tax (NOA), an HDB flat, a driving licence and a child; and
// Priya Raman, a foreigner on an Employment Pass, with no CPF account. On
// Corppass: one user acting for a company, with its profile, capital and
// financials.
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
						"type":                coded("LC", "LOCAL COMPANY"),
						"company_type":        coded("P", "PRIVATE COMPANY LIMITED BY SHARES"),
						"registration_date":   field("2019-04-01"),
						"primary_activity": map[string]any{
							"code": "46900", "desc": "WHOLESALE TRADE OF A VARIETY OF GOODS WITHOUT A DOMINANT PRODUCT", "edition": "2025",
							"source": "1", "classification": "C", "lastupdated": "2026-01-15",
						},
					},
					"capitals": []any{map[string]any{
						"source": "1", "classification": "C", "lastupdated": "2026-01-15",
						"share_type": coded("ORD", "ORDINARY"), "share_allotted_number": field(100000),
						"issued_amount": field(100000), "paid_up_amount": field(100000),
						"currency": coded("SGD", "SINGAPORE, DOLLARS"),
					}},
					"financials": []any{map[string]any{
						"source": "1", "classification": "C", "lastupdated": "2026-01-15",
						"current_period_start_date": field("2025-01-01"), "current_period_end_date": field("2025-12-31"),
						"is_audited": field("Y"), "currency": coded("SGD", "SINGAPORE, DOLLARS"),
						"company_financial": map[string]any{
							"revenue": field(2480000.5), "profit_loss_before_tax": field(310000), "profit_loss_after_tax": field(257300),
						},
					}},
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
				"corppass_info": map[string]any{"email": "lim.weiming@harbourfront.example", "email_verified": true},
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
				"uinfin":        field("S9812381D"),
				"partialuinfin": field("****381D"),
				"name":          field("TAN XIAO HUI"),
				"employment":    map[string]any{"value": "ACME ENGINEERING PTE LTD", "source": "2", "classification": "C", "lastupdated": "2026-01-15"},
				"cpfcontributions": map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-09-10",
					"history": []any{
						map[string]any{"month": map[string]any{"value": "2026-07"}, "date": map[string]any{"value": "2026-08-12"}, "amount": map[string]any{"value": 1554}, "employer": map[string]any{"value": "ACME ENGINEERING PTE LTD"}},
						map[string]any{"month": map[string]any{"value": "2026-08"}, "date": map[string]any{"value": "2026-09-10"}, "amount": map[string]any{"value": 1554}, "employer": map[string]any{"value": "ACME ENGINEERING PTE LTD"}},
					},
				},
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
				"marital":           coded("2", "MARRIED"),
				"marriagedate":      field("2008-06-14"),
				"hdbtype":           coded("114", "4-ROOM FLAT (HDB)"),
				"occupation":        coded("2512", "SOFTWARE DEVELOPER"),
				"employment":        field("JURONG LOGISTICS PTE LTD"),
				"cpfbalances": map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-09-01",
					"oa": field(48210.55), "sa": field(61890.2), "ma": field(52004.9), "ra": field(0),
				},
				"noa-basic": map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-05-01",
					"yearofassessment": field("2026"), "amount": field(96500),
				},
				"noa": map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-05-01",
					"yearofassessment": field("2026"), "amount": field(96500), "category": field("ORIGINAL"),
					"employment": field(96500), "trade": field(0), "rent": field(0), "interest": field(0), "taxclearance": field("N"),
				},
				"noahistory-basic": map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-05-01",
					"noas": []any{
						map[string]any{"yearofassessment": field("2026"), "amount": field(96500)},
						map[string]any{"yearofassessment": field("2025"), "amount": field(91200)},
					},
				},
				"hdbownership": []any{map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"address": map[string]any{
						"type": "SG", "block": field("55"), "street": field("JURONG WEST STREET 42"),
						"floor": field("12"), "unit": field("305"), "postal": field("640055"), "country": coded("SG", "SINGAPORE"),
					},
					"hdbtype": coded("114", "4-ROOM FLAT (HDB)"), "noofowners": field(2),
					"dateofpurchase": field("2009-03-01"), "leasecommencementdate": field("2008-11-01"), "termoflease": field(99),
					"purchaseprice": field(318000), "loangranted": field(250000), "outstandingloanbalance": field(61240.8),
					"monthlyloaninstalment": field(1120), "balanceloanrepayment": map[string]any{"years": field(4), "months": field(8)},
				}},
				"drivinglicence": map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"totaldemeritpoints": field(0), "comstatus": coded("Y", "ELIGIBLE"),
					"qdl": map[string]any{
						"validity": coded("V", "VALID"), "expirydate": field("2045-11-23"),
						"classes": []any{map[string]any{"class": field("3"), "issuedate": field("2001-04-10")}},
					},
				},
				"childrenbirthrecords": []any{map[string]any{
					"source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"name": field("NUR AISYAH BINTE MUHAMMAD HAFIZ"), "birthcertno": field("T1012345B"), "dob": field("2010-02-18"),
					"sex": coded("F", "FEMALE"), "race": coded("MY", "MALAY"), "lifestatus": coded("A", "ALIVE"),
					"sgcitizenatbirthind": field("Y"),
				}},
				"regadd": map[string]any{
					"type": "SG", "source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"block": map[string]any{"value": "55"}, "street": map[string]any{"value": "JURONG WEST STREET 42"},
					"floor": map[string]any{"value": "12"}, "unit": map[string]any{"value": "305"},
					"postal":  map[string]any{"value": "640055"},
					"country": map[string]any{"code": "SG", "desc": "SINGAPORE"},
				},
			}},
		},
		{
			Name:    "Priya Raman (Employment Pass holder)",
			Subject: "c3e8a1d2-6f47-4b0c-9e35-2a7d8b1f4c90",
			SubAttributes: map[string]any{
				"account_type": "standard", "identity_number": "G1234567X", "identity_coi": "IN",
				"name": "PRIYA RAMAN",
			},
			UserInfo: map[string]any{"person_info": map[string]any{
				"uinfin":             field("G1234567X"),
				"partialuinfin":      field("****567X"),
				"name":               field("PRIYA RAMAN"),
				"sex":                coded("F", "FEMALE"),
				"race":               coded("IN", "INDIAN"),
				"nationality":        coded("IN", "INDIAN"),
				"birthcountry":       coded("IN", "INDIA"),
				"dob":                field("1992-08-30"),
				"passtype":           coded("EP", "EMPLOYMENT PASS"),
				"passstatus":         field("LIVE"),
				"passexpirydate":     field("2028-04-30"),
				"passportnumber":     field("Z1234567"),
				"passportexpirydate": field("2031-01-15"),
				"employment":         field("MARINA ANALYTICS PTE LTD"),
				"email":              map[string]any{"value": "priya.raman@example.com", "source": "2", "classification": "C", "lastupdated": "2026-01-15"},
				"regadd": map[string]any{
					"type": "SG", "source": "1", "classification": "C", "lastupdated": "2026-01-15",
					"block": field("8"), "street": field("MARINA BOULEVARD"), "building": field("MARINA ONE RESIDENCES"),
					"floor": field("21"), "unit": field("04"), "postal": field("018981"), "country": coded("SG", "SINGAPORE"),
				},
				// A foreigner has no CPF account: Myinfo marks it unavailable.
				"cpfbalances": map[string]any{"unavailable": true, "source": "3", "classification": "C", "lastupdated": "2026-01-15"},
			}},
		},
	}
}
