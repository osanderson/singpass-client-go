package myinfo

import (
	"reflect"
	"testing"
	"time"
)

func TestFieldConversions(t *testing.T) {
	f := func(v any) Field { return Field{m: map[string]any{"value": v}, present: true} }
	for _, tc := range []struct {
		value any
		date  string // "" = not a date
	}{
		{"1998-06-06", "1998-06-06"},
		{"2024-03", "2024-03-01"},
		{"1965", "1965-01-01"},
		{"1998-6-6", ""},
		{"", ""},
		{"not a date", ""},
	} {
		got, ok := f(tc.value).Date()
		if tc.date == "" {
			if ok {
				t.Errorf("Date(%v) = %v, want not ok", tc.value, got)
			}
			continue
		}
		want, _ := time.Parse(time.DateOnly, tc.date)
		if !ok || !got.Equal(want) {
			t.Errorf("Date(%v) = %v, %v; want %v", tc.value, got, ok, want)
		}
	}

	if n, ok := f(1000.0).Int(); !ok || n != 1000 {
		t.Errorf("Int(1000) = %d, %v", n, ok)
	}
	if n, ok := f("42").Int(); !ok || n != 42 {
		t.Errorf(`Int("42") = %d, %v`, n, ok)
	}
	if _, ok := f(1.5).Int(); ok {
		t.Error("Int(1.5) ok")
	}
	if x, ok := f(1581.48).Float(); !ok || x != 1581.48 {
		t.Errorf("Float(1581.48) = %v, %v", x, ok)
	}
	var zero Field
	if _, ok := zero.Float(); ok {
		t.Error("zero Field Float ok")
	}
	if _, ok := zero.Date(); ok {
		t.Error("zero Field Date ok")
	}
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
