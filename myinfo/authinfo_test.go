package myinfo

import "testing"

// authInfoBlock builds an auth_info block in the bespoke Corppass shape
// (Result_Set.ESrvc_Result[].Auth_Result_Set.Row[]) with the given e-services,
// each mapping to a list of rows. A row is {CPEntID_SUB, CPRole, StartDate,
// EndDate, Parameter}.
func authInfoBlock(esrvcs []map[string]any) map[string]any {
	return map[string]any{
		"Result_Set": map[string]any{
			"ESrvc_Row_Count": float64(len(esrvcs)),
			"ESrvc_Result":    toAnySlice(esrvcs),
		},
	}
}

func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func esrvc(id string, rows ...map[string]any) map[string]any {
	return map[string]any{
		"CPESrvcID": id,
		"Auth_Result_Set": map[string]any{
			"Row_Count": float64(len(rows)),
			"Row":       toAnySlice(rows),
		},
	}
}

// TestAuthorisations covers the Corppass auth_info accessor: the sample-shaped
// single-e-service/single-row response (empty Role/Subject/Parameter), a
// multi-e-service multi-row case (flatten + CPESrvcID tagging), an absent block,
// and a wrong-shape block — the last two returning nil.
func TestAuthorisations(t *testing.T) {
	// Sample from a live staging response: one e-service, one row, empty
	// Role/Subject, empty Parameter, open-ended EndDate.
	sample := Parse(map[string]any{
		"aud": "client-xyz",
		"auth_info": authInfoBlock([]map[string]any{
			esrvc("STG-T09LL1904A-MIBV3-MYINFI-UVBH8S", map[string]any{
				"CPEntID_SUB": "",
				"CPRole":      "",
				"StartDate":   "2026-08-25",
				"EndDate":     "9999-12-31",
				"Parameter":   []any{},
			}),
		}),
	})
	got := sample.Auth.Authorisations()
	if len(got) != 1 {
		t.Fatalf("sample: got %d authorisations, want 1: %+v", len(got), got)
	}
	a := got[0]
	checkAll(t,
		check{"ESrvcID", a.ESrvcID, "STG-T09LL1904A-MIBV3-MYINFI-UVBH8S"},
		check{"StartDate", a.StartDate, "2026-08-25"},
		check{"EndDate", a.EndDate, "9999-12-31"},
		check{"Role", a.Role, ""},
		check{"Subject", a.Subject, ""},
		check{"Parameters", len(a.Parameters), 0},
	)

	// Two e-services: the first with two rows, the second with one. Flattened to
	// three authorisations, each tagged with its parent CPESrvcID.
	multi := Parse(map[string]any{
		"auth_info": authInfoBlock([]map[string]any{
			esrvc("SVC-A",
				map[string]any{"CPRole": "Admin", "CPEntID_SUB": "S1234567D", "StartDate": "2024-01-01", "EndDate": "9999-12-31"},
				map[string]any{"CPRole": "Preparer", "StartDate": "2024-02-01", "EndDate": "9999-12-31"},
			),
			esrvc("SVC-B",
				map[string]any{"CPRole": "Approver", "StartDate": "2023-06-01", "EndDate": "2025-06-01"},
			),
		}),
	})
	ma := multi.Auth.Authorisations()
	if len(ma) != 3 {
		t.Fatalf("multi: got %d authorisations, want 3: %+v", len(ma), ma)
	}
	checkAll(t,
		check{"row0 ESrvcID", ma[0].ESrvcID, "SVC-A"},
		check{"row0 Role", ma[0].Role, "Admin"},
		check{"row0 Subject", ma[0].Subject, "S1234567D"},
		check{"row1 ESrvcID", ma[1].ESrvcID, "SVC-A"},
		check{"row1 Role", ma[1].Role, "Preparer"},
		check{"row2 ESrvcID", ma[2].ESrvcID, "SVC-B"},
		check{"row2 Role", ma[2].Role, "Approver"},
		check{"row2 EndDate", ma[2].EndDate, "2025-06-01"},
	)

	// An absent block, and one of the wrong shape (a plain object, not
	// Result_Set/ESrvc_Result), give nil.
	wrong := Parse(map[string]any{
		"auth_info": map[string]any{"something": map[string]any{"value": "x"}},
	})
	checkAll(t,
		check{"absent auth_info", Parse(map[string]any{"aud": "x"}).Auth.Authorisations() == nil, true},
		check{"wrong-shape auth_info", wrong.Auth.Authorisations() == nil, true},
	)
}
