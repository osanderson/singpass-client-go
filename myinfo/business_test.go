package myinfo

import (
	"testing"
)

// Shaped as Corppass's entity_info OpenAPI specification defines each item.
func entityResponse() *Response {
	v := func(x any) map[string]any { return map[string]any{"value": x} }
	c := func(code, desc string) map[string]any { return map[string]any{"code": code, "desc": desc} }
	return Parse(map[string]any{"entity_info": map[string]any{
		"basic_profile": map[string]any{
			"name": v("HARBOURFRONT TRADING PTE. LTD."), "registration_number": v("201912345K"),
			"type": c("LC", "LOCAL COMPANY"), "company_type": c("P", "PRIVATE COMPANY LIMITED BY SHARES"),
			"uen_status": c("R", "REGISTERED"), "country_of_incorporation": c("SG", "SINGAPORE"),
			"registration_date": v("2019-04-01"),
			"primary_activity":  map[string]any{"code": "46900", "desc": "WHOLESALE TRADE OF A VARIETY OF GOODS", "edition": "2025"},
		},
		"capitals": []any{map[string]any{
			"share_type": c("ORD", "ORDINARY"), "share_allotted_number": v(100000.0),
			"issued_amount": v(100000.0), "paid_up_amount": v(100000.0), "currency": c("SGD", "SINGAPORE, DOLLARS"),
		}},
		"financials": []any{map[string]any{
			"current_period_start_date": v("2024-01-01"), "current_period_end_date": v("2024-12-31"),
			"is_audited": v("Y"), "currency": c("SGD", "SINGAPORE, DOLLARS"),
			"company_financial": map[string]any{"revenue": v(2500000.0), "profit_loss_after_tax": v(-12500.5)},
		}},
		"licences": []any{map[string]any{
			"licence_number": v("L123"), "licence_name": v("IMPORT LICENCE"),
			"issuance_agency": c("SC", "SINGAPORE CUSTOMS"), "expiry_date": v("2027-03-31"),
		}},
		"history": map[string]any{
			"previous_names":                []any{map[string]any{"previous_name": v("HARBOURFRONT PTE. LTD."), "previous_name_effective_date": v("2021-06-01")}},
			"previous_registration_numbers": []any{map[string]any{"previous_registration_number": v("53123456A")}},
		},
		"builders":    []any{map[string]any{"licence": c("GB1", "GENERAL BUILDER CLASS 1"), "licence_expiry_date": v("2028-01-01")}},
		"contractors": []any{map[string]any{"workhead": c("CW01", "GENERAL BUILDING"), "workhead_financial_grade": v("B1")}},
		"grants":      []any{map[string]any{"type": c("PSG", "PRODUCTIVITY SOLUTIONS GRANT"), "status": c("A", "APPROVED"), "approved_amount": v(15000.0)}},
		"shareholders": []any{map[string]any{
			"allocation": v(100000.0), "share_type": c("ORD", "ORDINARY"),
			"individual_shareholder": map[string]any{"name": v("LIM WEI MING")},
		}},
	}})
}

func TestEntityProfileComplete(t *testing.T) {
	e := entityResponse().EntityProfile()
	h := e.History
	checkAll(t,
		check{"Capitals", len(e.Capitals), 1},
		check{"Financials", len(e.Financials), 1},
		check{"Licences", len(e.Licences), 1},
		check{"PreviousNames", len(h.PreviousNames), 1},
		check{"PreviousRegistrationNumbers", len(h.PreviousRegistrationNumbers), 1},
		check{"Builders", len(e.Builders), 1},
		check{"Contractors", len(e.Contractors), 1},
		check{"Grants", len(e.Grants), 1},
		check{"Shareholders", len(e.Shareholders), 1},
	)
	if t.Failed() {
		return
	}
	f := e.Financials[0]
	checkAll(t,
		check{"RegistrationNumber", e.RegistrationNumber.String(), "201912345K"},
		check{"Type", e.Type.Code(), "LC"},
		check{"CountryOfIncorporation", e.CountryOfIncorporation.Code(), "SG"},
		check{"RegistrationDate", dateOf(e.RegistrationDate), "2019-04-01"},
		check{"PrimaryActivity", e.PrimaryActivity.Code(), "46900"},
		check{"PrimaryActivity edition", e.PrimaryActivity.Member("edition"), "2025"},
		check{"SecondaryActivity present", e.SecondaryActivity.Present(), false},
		check{"capital PaidUpAmount", floatOf(e.Capitals[0].PaidUpAmount), 100000.0},
		check{"capital Currency", e.Capitals[0].Currency.Code(), "SGD"},
		check{"financial Revenue", floatOf(f.Company.Revenue), 2500000.0},
		check{"financial ProfitLossAfterTax", floatOf(f.Company.ProfitLossAfterTax), -12500.5},
		check{"financial IsAudited", f.IsAudited.String(), "Y"},
		check{"financial Group present", f.Group.Revenue.Present(), false},
		check{"licence IssuanceAgency", e.Licences[0].IssuanceAgency.Code(), "SC"},
		check{"licence LicenceName", e.Licences[0].LicenceName.String(), "IMPORT LICENCE"},
		check{"previous name", h.PreviousNames[0].Name.String(), "HARBOURFRONT PTE. LTD."},
		check{"previous registration number", h.PreviousRegistrationNumbers[0].String(), "53123456A"},
		check{"contractor WorkheadFinancialGrade", e.Contractors[0].WorkheadFinancialGrade.String(), "B1"},
		check{"grant ApprovedAmount", floatOf(e.Grants[0].ApprovedAmount), 15000.0},
		check{"grant Status", e.Grants[0].Status.Code(), "A"},
		check{"shareholder allocation", floatOf(e.Shareholders[0].Data.Field("allocation")), 100000.0},
		check{"shareholder Allocation", e.Shareholders[0].Allocation, "100000"},
	)
}

func TestEntityProfileAbsentDatasets(t *testing.T) {
	e := Parse(map[string]any{"entity_info": map[string]any{"basic_profile": map[string]any{"name": map[string]any{"value": "X"}}}}).EntityProfile()
	if e.Capitals != nil || e.Financials != nil || e.Licences != nil || e.Grants != nil || e.History.PreviousNames != nil || e.History.Data.Present() {
		t.Error("absent datasets should be empty")
	}
	var f Field
	if f.Member("edition") != "" {
		t.Error("zero Field Member")
	}
}
