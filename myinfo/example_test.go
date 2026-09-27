package myinfo_test

import (
	"fmt"

	"github.com/osanderson/singpass-client-go/myinfo"
)

// Reading person data. In an app the Response comes from
// singpass.Identity.Myinfo; Parse builds the same view from any decoded
// /userinfo claims, e.g. in tests.
func ExampleParse() {
	m := myinfo.Parse(map[string]any{
		"sub": "a9865837-7bd7-46ac-bef4-42a76a946424",
		"person_info": map[string]any{
			"name":        map[string]any{"value": "TAN XIAO HUI", "source": "1", "classification": "C"},
			"nationality": map[string]any{"code": "SG", "desc": "SINGAPORE CITIZEN", "source": "1"},
			"email":       map[string]any{"unavailable": true, "source": "2"},
			"regadd": map[string]any{
				"type": "SG", "source": "1",
				"block":  map[string]any{"value": "123"},
				"street": map[string]any{"value": "BEDOK NORTH AVE 1"},
				"postal": map[string]any{"value": "460123"},
			},
		},
	})

	p := m.Person
	fmt.Println(p.Field("name").String())
	fmt.Println(p.Field("name").SourceCode(), p.Field("name").SourceCode().Authoritative())
	fmt.Println(p.Field("nationality").Code(), "/", p.Field("nationality").String())
	fmt.Println("email available:", p.Field("email").Available())
	addr := p.Object("regadd")
	fmt.Println(addr.Field("block").String(), addr.Field("street").String(), addr.Field("postal").String())
	fmt.Println("missing field is safe:", p.Field("dob").Present())
	// Output:
	// TAN XIAO HUI
	// government-verified true
	// SG / SINGAPORE CITIZEN
	// email available: false
	// 123 BEDOK NORTH AVE 1 460123
	// missing field is safe: false
}

// Myinfo Business returns several blocks, some as double-encoded JSON
// strings; Parse unwraps them, and Authorisations flattens Corppass auth_info.
func ExampleData_Authorisations() {
	m := myinfo.Parse(map[string]any{
		"entity_info": `{"basic_profile":{"name":{"value":"TAN ENTERPRISES PTE. LTD."}}}`,
		"auth_info": map[string]any{
			"Result_Set": map[string]any{
				"ESrvc_Result": []any{map[string]any{
					"CPESrvcID": "MYAPP-ESERVICE",
					"Auth_Result_Set": map[string]any{
						"Row": []any{map[string]any{
							"CPRole": "Approver", "StartDate": "2024-01-01", "EndDate": "9999-12-31",
						}},
					},
				}},
			},
		},
	})

	fmt.Println(m.Blocks())
	fmt.Println(m.Entity.Object("basic_profile").Field("name").String())
	for _, a := range m.Auth.Authorisations() {
		fmt.Println(a.ESrvcID, a.Role, a.StartDate, "to", a.EndDate)
	}
	// Output:
	// [entity_info auth_info]
	// TAN ENTERPRISES PTE. LTD.
	// MYAPP-ESERVICE Approver 2024-01-01 to 9999-12-31
}

// The typed profile names the common items, so there are no keys to look up.
// Each item is still a Field, with its code and provenance.
func ExampleResponse_PersonProfile() {
	m := myinfo.Parse(map[string]any{"person_info": map[string]any{
		"uinfin": map[string]any{"value": "S9812381D", "source": "1"},
		"name":   map[string]any{"value": "TAN XIAO HUI", "source": "1"},
		"sex":    map[string]any{"code": "F", "desc": "FEMALE", "source": "1"},
		"dob":    map[string]any{"value": "1998-06-06", "source": "1"},
		"mobileno": map[string]any{
			"source": "2",
			"prefix": map[string]any{"value": "+"}, "areacode": map[string]any{"value": "65"},
			"nbr": map[string]any{"value": "97399245"},
		},
		"regadd": map[string]any{
			"type": "SG", "source": "1",
			"block": map[string]any{"value": "102"}, "street": map[string]any{"value": "BEDOK NORTH AVENUE 4"},
			"floor": map[string]any{"value": "09"}, "unit": map[string]any{"value": "128"},
			"postal":  map[string]any{"value": "460102"},
			"country": map[string]any{"code": "SG", "desc": "SINGAPORE"},
		},
		"cpfbalances": map[string]any{"source": "1", "oa": map[string]any{"value": 1581.48}},
	}})

	p := m.PersonProfile()
	fmt.Println(p.UINFIN.String(), p.Name.String(), p.Sex.Code())
	dob, _ := p.DOB.Date()
	fmt.Println(dob.Format("2 Jan 2006"))
	fmt.Println(p.MobileNo.E164(), p.MobileNo.Data.SourceCode())
	for _, line := range p.RegAdd.Lines() {
		fmt.Println(line)
	}
	oa, _ := p.CPFBalances.OA.Float()
	fmt.Printf("OA %.2f\n", oa)
	fmt.Println("email available:", p.Email.Available())
	// Output:
	// S9812381D TAN XIAO HUI F
	// 6 Jun 1998
	// +6597399245 user-provided
	// 102 BEDOK NORTH AVENUE 4
	// #09-128
	// SINGAPORE 460102
	// OA 1581.48
	// email available: false
}
