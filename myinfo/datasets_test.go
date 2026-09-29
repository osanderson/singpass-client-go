package myinfo

import (
	"testing"
	"time"
)

// Shaped as Singpass's person_info OpenAPI specification defines each item.
func datasetsResponse() *Response {
	v := func(x any) map[string]any { return map[string]any{"value": x} }
	c := func(code, desc string) map[string]any { return map[string]any{"code": code, "desc": desc} }
	meta := map[string]any{"source": "1", "classification": "C", "lastupdated": "2026-01-15"}
	with := func(m map[string]any) map[string]any {
		for k, x := range meta {
			m[k] = x
		}
		return m
	}
	return Parse(map[string]any{"person_info": map[string]any{
		"noa-basic": with(map[string]any{"yearofassessment": v("2025"), "amount": v(84500.0)}),
		"noa": with(map[string]any{
			"yearofassessment": v("2025"), "amount": v(84500.0), "category": v("ORIGINAL"),
			"employment": v(80000.0), "trade": v(0.0), "rent": v(4500.0), "interest": v(0.0), "taxclearance": v("N"),
		}),
		"noahistory-basic": with(map[string]any{"noas": []any{
			map[string]any{"yearofassessment": v("2025"), "amount": v(84500.0)},
			map[string]any{"yearofassessment": v("2024"), "amount": v(79000.0)},
		}}),
		"vehicles": []any{with(map[string]any{
			"vehicleno": v("SBA1234A"), "make": v("TOYOTA"), "model": v("COROLLA ALTIS"),
			"status": c("1", "LIVE"), "coeexpirydate": v("2031-05-20"), "enginecapacity": v(1598),
			"openmarketvalue": v(21500.5),
		})},
		"hdbownership": []any{with(map[string]any{
			"address": map[string]any{"type": "SG", "block": v("102"), "street": v("BEDOK NORTH AVENUE 4"),
				"floor": v("9"), "unit": v("128"), "postal": v("460102"), "country": c("SG", "SINGAPORE")},
			"hdbtype": c("114", "4-ROOM FLAT (HDB)"), "noofowners": v(2), "dateofpurchase": v("2015-03-01"),
			"purchaseprice": v(420000.0), "outstandingloanbalance": v(185000.25),
			"balanceloanrepayment": map[string]any{"years": v(12), "months": v(4)},
		})},
		"drivinglicence": with(map[string]any{
			"totaldemeritpoints": v(0), "comstatus": c("Y", "ELIGIBLE"),
			"qdl": map[string]any{"validity": c("V", "VALID"), "expirydate": v("2060-06-06"),
				"classes": []any{map[string]any{"class": v("3"), "issuedate": v("2018-01-01")}}},
			"suspension": map[string]any{"startdate": v(""), "enddate": v("")},
		}),
	}})
}

func TestPersonDatasets(t *testing.T) {
	p := datasetsResponse().PersonProfile()

	if x, ok := p.NOABasic.Amount.Float(); !ok || x != 84500 || p.NOABasic.YearOfAssessment.String() != "2025" {
		t.Errorf("NOABasic = %v, %v", x, p.NOABasic.YearOfAssessment.String())
	}
	if p.NOA.Category.String() != "ORIGINAL" || p.NOA.TaxClearance.String() != "N" {
		t.Errorf("NOA = %+v", p.NOA)
	}
	if rent, _ := p.NOA.Rent.Float(); rent != 4500 {
		t.Errorf("NOA rent = %v", rent)
	}
	if len(p.NOAHistoryBasic) != 2 || p.NOAHistoryBasic[1].YearOfAssessment.String() != "2024" || p.NOAHistory != nil {
		t.Errorf("NOA history = %+v / %+v", p.NOAHistoryBasic, p.NOAHistory)
	}

	if len(p.Vehicles) != 1 {
		t.Fatalf("Vehicles = %d", len(p.Vehicles))
	}
	veh := p.Vehicles[0]
	coe, _ := veh.COEExpiryDate.Date()
	cc, _ := veh.EngineCapacity.Int()
	omv, _ := veh.OpenMarketValue.Float()
	if veh.VehicleNo.String() != "SBA1234A" || veh.Status.Code() != "1" || !coe.Equal(time.Date(2031, 5, 20, 0, 0, 0, 0, time.UTC)) || cc != 1598 || omv != 21500.5 {
		t.Errorf("vehicle = %+v", veh)
	}
	if veh.Data.SourceCode() != SourceGovernmentVerified {
		t.Error("vehicle provenance lost")
	}

	if len(p.HDBOwnership) != 1 {
		t.Fatalf("HDBOwnership = %d", len(p.HDBOwnership))
	}
	h := p.HDBOwnership[0]
	owners, _ := h.NoOfOwners.Int()
	years, _ := h.BalanceLoanRepayment.Years.Int()
	if h.Address.String() != "102 BEDOK NORTH AVENUE 4, #09-128, SINGAPORE 460102" || h.HDBType.String() != "4-ROOM FLAT (HDB)" || owners != 2 || years != 12 {
		t.Errorf("HDB ownership = %q %q %d %d", h.Address.String(), h.HDBType.String(), owners, years)
	}

	dl := p.DrivingLicence
	if dl.QDL.Validity.Code() != "V" || len(dl.QDL.Classes) != 1 || dl.QDL.Classes[0].Class.String() != "3" || dl.COMStatus.Code() != "Y" {
		t.Errorf("driving licence = %+v", dl)
	}
	if dl.Suspension.StartDate.Available() || len(dl.PDL.Classes) != 0 {
		t.Error("empty suspension / absent PDL should read as empty")
	}
}

func TestDatasetsAbsent(t *testing.T) {
	p := Parse(map[string]any{"person_info": map[string]any{"name": map[string]any{"value": "X"}}}).PersonProfile()
	if p.NOABasic.Data.Present() || p.Vehicles != nil || p.HDBOwnership != nil || p.DrivingLicence.Data.Present() || p.NOAHistory != nil {
		t.Error("absent datasets should be empty")
	}
}
