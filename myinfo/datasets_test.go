package myinfo

import (
	"testing"
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
	checkAll(t,
		check{"NOAHistoryBasic", len(p.NOAHistoryBasic), 2},
		check{"Vehicles", len(p.Vehicles), 1},
		check{"HDBOwnership", len(p.HDBOwnership), 1},
		check{"QDL classes", len(p.DrivingLicence.QDL.Classes), 1},
	)
	if t.Failed() {
		return
	}
	veh, h, dl := p.Vehicles[0], p.HDBOwnership[0], p.DrivingLicence
	checkAll(t,
		check{"NOABasic.Amount", floatOf(p.NOABasic.Amount), 84500.0},
		check{"NOABasic.YearOfAssessment", p.NOABasic.YearOfAssessment.String(), "2025"},
		check{"NOA.Category", p.NOA.Category.String(), "ORIGINAL"},
		check{"NOA.TaxClearance", p.NOA.TaxClearance.String(), "N"},
		check{"NOA.Rent", floatOf(p.NOA.Rent), 4500.0},
		check{"NOAHistoryBasic[1].YearOfAssessment", p.NOAHistoryBasic[1].YearOfAssessment.String(), "2024"},
		check{"NOAHistory", p.NOAHistory == nil, true},

		check{"vehicle VehicleNo", veh.VehicleNo.String(), "SBA1234A"},
		check{"vehicle Status", veh.Status.Code(), "1"},
		check{"vehicle COEExpiryDate", dateOf(veh.COEExpiryDate), "2031-05-20"},
		check{"vehicle EngineCapacity", intOf(veh.EngineCapacity), int64(1598)},
		check{"vehicle OpenMarketValue", floatOf(veh.OpenMarketValue), 21500.5},
		check{"vehicle provenance", veh.Data.SourceCode(), SourceGovernmentVerified},

		check{"HDB Address", h.Address.String(), "102 BEDOK NORTH AVENUE 4, #09-128, SINGAPORE 460102"},
		check{"HDB HDBType", h.HDBType.String(), "4-ROOM FLAT (HDB)"},
		check{"HDB NoOfOwners", intOf(h.NoOfOwners), int64(2)},
		check{"HDB BalanceLoanRepayment.Years", intOf(h.BalanceLoanRepayment.Years), int64(12)},

		check{"QDL Validity", dl.QDL.Validity.Code(), "V"},
		check{"QDL class", dl.QDL.Classes[0].Class.String(), "3"},
		check{"COMStatus", dl.COMStatus.Code(), "Y"},
		// An empty suspension and an absent PDL read as empty.
		check{"Suspension.StartDate available", dl.Suspension.StartDate.Available(), false},
		check{"PDL classes", len(dl.PDL.Classes), 0},
	)
}

func TestDatasetsAbsent(t *testing.T) {
	p := Parse(map[string]any{"person_info": map[string]any{"name": map[string]any{"value": "X"}}}).PersonProfile()
	if p.NOABasic.Data.Present() || p.Vehicles != nil || p.HDBOwnership != nil || p.DrivingLicence.Data.Present() || p.NOAHistory != nil {
		t.Error("absent datasets should be empty")
	}
}
