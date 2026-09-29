package myinfo

import (
	"testing"
	"time"
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

	if e.RegistrationNumber.String() != "201912345K" || e.Type.Code() != "LC" || e.CountryOfIncorporation.Code() != "SG" {
		t.Errorf("basic profile = %q %q %q", e.RegistrationNumber.String(), e.Type.Code(), e.CountryOfIncorporation.Code())
	}
	if d, ok := e.RegistrationDate.Date(); !ok || !d.Equal(time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("RegistrationDate = %v", d)
	}
	if e.PrimaryActivity.Code() != "46900" || e.PrimaryActivity.Member("edition") != "2025" || e.SecondaryActivity.Present() {
		t.Errorf("activities = %q %q", e.PrimaryActivity.Code(), e.PrimaryActivity.Member("edition"))
	}

	if len(e.Capitals) != 1 {
		t.Fatalf("Capitals = %d", len(e.Capitals))
	}
	if paid, _ := e.Capitals[0].PaidUpAmount.Float(); paid != 100000 || e.Capitals[0].Currency.Code() != "SGD" {
		t.Errorf("capital = %+v", e.Capitals[0])
	}
	if len(e.Financials) != 1 {
		t.Fatalf("Financials = %d", len(e.Financials))
	}
	f := e.Financials[0]
	rev, _ := f.Company.Revenue.Float()
	pat, _ := f.Company.ProfitLossAfterTax.Float()
	if rev != 2500000 || pat != -12500.5 || f.IsAudited.String() != "Y" || f.Group.Revenue.Present() {
		t.Errorf("financial = %+v", f)
	}
	if len(e.Licences) != 1 || e.Licences[0].IssuanceAgency.Code() != "SC" || e.Licences[0].LicenceName.String() != "IMPORT LICENCE" {
		t.Errorf("licences = %+v", e.Licences)
	}
	h := e.History
	if len(h.PreviousNames) != 1 || h.PreviousNames[0].Name.String() != "HARBOURFRONT PTE. LTD." || len(h.PreviousRegistrationNumbers) != 1 || h.PreviousRegistrationNumbers[0].String() != "53123456A" {
		t.Errorf("history = %+v", h)
	}
	if len(e.Builders) != 1 || len(e.Contractors) != 1 || e.Contractors[0].WorkheadFinancialGrade.String() != "B1" {
		t.Errorf("builders/contractors = %+v / %+v", e.Builders, e.Contractors)
	}
	if amt, _ := e.Grants[0].ApprovedAmount.Float(); len(e.Grants) != 1 || amt != 15000 || e.Grants[0].Status.Code() != "A" {
		t.Errorf("grants = %+v", e.Grants)
	}
	if n, ok := e.Shareholders[0].Data.Field("allocation").Float(); !ok || n != 100000 || e.Shareholders[0].Allocation != "100000" {
		t.Errorf("shareholder allocation = %v / %q", n, e.Shareholders[0].Allocation)
	}
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
