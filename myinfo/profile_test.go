package myinfo

import (
	"reflect"
	"testing"
)

func TestFieldConversions(t *testing.T) {
	f := func(v any) Field { return Field{m: map[string]any{"value": v}, present: true} }
	var zero Field
	checkAll(t,
		check{"Date(1998-06-06)", dateOf(f("1998-06-06")), "1998-06-06"},
		check{"Date(2024-03)", dateOf(f("2024-03")), "2024-03-01"},
		check{"Date(1965)", dateOf(f("1965")), "1965-01-01"},
		check{"Date(1998-6-6)", dateOf(f("1998-6-6")), nil},
		check{`Date("")`, dateOf(f("")), nil},
		check{"Date(not a date)", dateOf(f("not a date")), nil},
		check{"Int(1000)", intOf(f(1000.0)), int64(1000)},
		check{`Int("42")`, intOf(f("42")), int64(42)},
		check{"Int(1.5)", intOf(f(1.5)), nil},
		check{"Float(1581.48)", floatOf(f(1581.48)), 1581.48},
		check{"zero Field Float", floatOf(zero), nil},
		check{"zero Field Date", dateOf(zero), nil},
	)
}

func TestAddressLines(t *testing.T) {
	v := func(s string) map[string]any { return map[string]any{"value": s} }
	for name, tc := range map[string]struct {
		addr map[string]any
		want []string
	}{
		"sg full": {map[string]any{
			"type": "SG", "block": v("10"), "street": v("HARBOURFRONT AVENUE"), "building": v("KEPPEL BAY TOWER"),
			"floor": v("08"), "unit": v("01"), "postal": v("098632"), "country": map[string]any{"code": "SG", "desc": "SINGAPORE"},
		}, []string{"10 HARBOURFRONT AVENUE", "#08-01 KEPPEL BAY TOWER", "SINGAPORE 098632"}},
		"one-digit floor padded": {map[string]any{
			"type": "SG", "block": v("18"), "street": v("HAVELOCK ROAD"), "floor": v("2"), "unit": v("123"), "postal": v("597642"),
		}, []string{"18 HAVELOCK ROAD", "#02-123", "SINGAPORE 597642"}},
		"basement floor as sent": {map[string]any{
			"type": "SG", "block": v("1"), "street": v("RAFFLES PLACE"), "floor": v("B1"), "unit": v("05"), "postal": v("048616"),
		}, []string{"1 RAFFLES PLACE", "#B1-05", "SINGAPORE 048616"}},
		"sg landed, no country": {map[string]any{
			"type": "SG", "block": v("7"), "street": v("JALAN KAYU"), "postal": v("799000"),
		}, []string{"7 JALAN KAYU", "SINGAPORE 799000"}},
		"unformatted": {map[string]any{
			"type": "Unformatted", "line1": v("1 MAIN STREET"), "line2": v("LONDON SW1A 1AA"),
			"country": map[string]any{"code": "GB", "desc": "UNITED KINGDOM"},
		}, []string{"1 MAIN STREET", "LONDON SW1A 1AA", "UNITED KINGDOM"}},
	} {
		a := Data{m: map[string]any{"regadd": tc.addr}}.Address("regadd")
		if !a.Present() {
			t.Errorf("%s: not present", name)
		}
		if got := a.Lines(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: Lines = %q, want %q", name, got, tc.want)
		}
	}
	if a := (Data{}).Address("regadd"); a.Present() || a.Lines() != nil || a.String() != "" {
		t.Error("absent address should be empty")
	}
}

func TestPhone(t *testing.T) {
	d := Data{m: map[string]any{"mobileno": map[string]any{
		"prefix": map[string]any{"value": "+"}, "areacode": map[string]any{"value": "65"}, "nbr": map[string]any{"value": "97399245"},
	}}}
	p := d.Phone("mobileno")
	if p.String() != "+65 97399245" || p.E164() != "+6597399245" || !p.Available() {
		t.Errorf("Phone = %q / %q", p.String(), p.E164())
	}
	bare := Data{m: map[string]any{"mobileno": map[string]any{"nbr": map[string]any{"value": "97399245"}}}}.Phone("mobileno")
	if bare.String() != "97399245" || bare.E164() != "" {
		t.Errorf("bare Phone = %q / %q", bare.String(), bare.E164())
	}
	if p := (Data{}).Phone("mobileno"); p.Present() || p.Available() || p.String() != "" {
		t.Error("absent phone should be empty")
	}
}

func TestProfiles(t *testing.T) {
	var nilResp *Response
	if p := nilResp.PersonProfile(); p.Data.Present() || p.Name.Present() {
		t.Error("nil Response PersonProfile not empty")
	}
	if e := nilResp.EntityProfile(); e.Data.Present() || e.Appointments != nil {
		t.Error("nil Response EntityProfile not empty")
	}

	m := Parse(map[string]any{
		"person_info": map[string]any{
			"name":        map[string]any{"value": "LIM WEI MING"},
			"nationality": map[string]any{"code": "SG", "desc": "SINGAPORE CITIZEN"},
			"cpfbalances": map[string]any{"source": "1", "ma": map[string]any{"value": 20000}},
		},
		// Corppass sends blocks double-encoded.
		"entity_info": `{"basic_profile":{"name":{"value":"HARBOURFRONT TRADING PTE. LTD."},` +
			`"uen_status":{"code":"R","desc":"REGISTERED"},"company_type":{"code":"P","desc":"PRIVATE COMPANY LIMITED BY SHARES"}},` +
			`"address":{"type":"SG","block":{"value":"10"},"street":{"value":"HARBOURFRONT AVENUE"},"postal":{"value":"098632"}},` +
			`"appointments":[{"position":{"code":"D","desc":"DIRECTOR"},"individual_appointment":{"name":{"value":"LIM WEI MING"}}}]}`,
	})
	p := m.PersonProfile()
	if p.Name.String() != "LIM WEI MING" || p.Nationality.Code() != "SG" || !p.Data.Present() {
		t.Errorf("PersonProfile = %+v", p)
	}
	if ma, ok := p.CPFBalances.MA.Float(); !ok || ma != 20000 || p.CPFBalances.Data.SourceCode() != SourceGovernmentVerified {
		t.Errorf("CPF MA = %v, %v", ma, ok)
	}
	if p.Email.Present() || p.RegAdd.Present() || p.MobileNo.Present() {
		t.Error("absent items should be empty")
	}

	e := m.EntityProfile()
	if e.Name.String() != "HARBOURFRONT TRADING PTE. LTD." || e.UENStatus.Code() != "R" || e.CompanyType.Code() != "P" {
		t.Errorf("EntityProfile basic = %+v", e)
	}
	if e.Address.String() != "10 HARBOURFRONT AVENUE, SINGAPORE 098632" {
		t.Errorf("entity address = %q", e.Address.String())
	}
	if len(e.Appointments) != 1 || e.Appointments[0].Appointee.Name != "LIM WEI MING" {
		t.Errorf("Appointments = %+v", e.Appointments)
	}
}
