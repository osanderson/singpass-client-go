package main

import (
	"reflect"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/examples/demo/internal/demoapp"
	"github.com/osanderson/singpass-client-go/myinfo"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// Every typed profile field is placed in a section, so a field the library
// adds can't be left off the page.
func TestSectionsCoverProfiles(t *testing.T) {
	for _, tc := range []struct {
		profile  any
		sections []profileSection
		skip     []string
	}{
		{myinfo.PersonProfile{}, personSections, []string{"Data"}},
		{myinfo.EntityProfile{}, entitySections, []string{"Data", "BasicProfile"}},
		{myinfo.CorppassProfile{}, corppassSections, []string{"Data"}},
	} {
		placed := map[string]bool{}
		for _, s := range tc.sections {
			for _, f := range s.fields {
				if _, ok := reflect.TypeOf(tc.profile).FieldByName(f); !ok {
					t.Errorf("%T has no field %s", tc.profile, f)
				}
				placed[f] = true
			}
		}
		typ := reflect.TypeOf(tc.profile)
		for i := range typ.NumField() {
			if name := typ.Field(i).Name; !placed[name] && !contains(tc.skip, name) {
				t.Errorf("%T.%s isn't in any section", tc.profile, name)
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sectionByTitle(secs []demoapp.Section, title string) *demoapp.Section {
	for i := range secs {
		if secs[i].Title == title {
			return &secs[i]
		}
	}
	return nil
}

func TestTypedSectionsPerson(t *testing.T) {
	hafiz := singpasstest.DefaultPersonas(singpasstest.Singpass)[1]
	id := &singpass.Identity{Myinfo: myinfo.Parse(hafiz.UserInfo)}
	secs := typedSections(id)
	for _, title := range []string{"Identity", "Contact", "Family", "Housing and property", "CPF", "Income tax", "Vehicles and driving"} {
		if sectionByTitle(secs, title) == nil {
			t.Errorf("no %q section", title)
		}
	}
	identity := sectionByTitle(secs, "Identity")
	var dob *demoapp.Highlight
	for i := range identity.Rows {
		if identity.Rows[i].Label == "Date of birth" {
			dob = &identity.Rows[i]
		}
	}
	if dob == nil || dob.Value != "1980-11-23" || dob.Hint != "p.DOB" || dob.NoteKind != "gov" {
		t.Errorf("date of birth row = %+v", dob)
	}
	housing := sectionByTitle(secs, "Housing and property")
	if len(housing.Tables) != 1 || housing.Tables[0].Hint != "p.HDBOwnership[i]" || !strings.Contains(strings.Join(housing.Tables[0].Rows[0].Cells, " "), "#12-305") {
		t.Errorf("HDB ownership table = %+v", housing.Tables)
	}
	tax := sectionByTitle(secs, "Income tax")
	for _, g := range tax.Groups {
		for _, r := range g.Rows {
			if r.Hint == "p.NOA.Employment" && r.Label != "Employment" {
				t.Errorf("NOA employment income labelled %q", r.Label)
			}
		}
	}
	cpf := sectionByTitle(secs, "CPF")
	if len(cpf.Groups) == 0 || cpf.Groups[0].Hint != "p.CPFBalances" || cpf.Groups[0].Rows[0].Hint != "p.CPFBalances.OA" || cpf.Groups[0].Rows[0].Value != "48,210.55" {
		t.Errorf("CPF balances group = %+v", cpf.Groups)
	}
	if rows, total := untypedItems(id.Myinfo); len(rows) != 0 || total == 0 {
		t.Errorf("untyped = %v of %d, want none", rows, total)
	}
}

func TestTypedSectionsBusiness(t *testing.T) {
	lim := singpasstest.DefaultPersonas(singpasstest.Corppass)[0]
	id := &singpass.Identity{Myinfo: myinfo.Parse(lim.UserInfo)}
	secs := typedSections(id)
	entity := sectionByTitle(secs, "Entity")
	if entity == nil || entity.Rows[0].Hint != "e.Name" {
		t.Fatalf("entity section = %+v", entity)
	}
	for _, title := range []string{"People", "Capital and financials", "Corppass account", "Authorisations"} {
		if sectionByTitle(secs, title) == nil {
			t.Errorf("no %q section", title)
		}
	}
	fin := sectionByTitle(secs, "Capital and financials")
	var financials *demoapp.Table
	for i := range fin.Tables {
		if fin.Tables[i].Hint == "e.Financials[i]" {
			financials = &fin.Tables[i]
		}
	}
	if financials == nil || !strings.Contains(strings.Join(financials.Rows[0].Cells, " "), "Revenue: 2,480,000.50") {
		t.Errorf("financials table = %+v", financials)
	}
}

func TestUntypedItems(t *testing.T) {
	m := myinfo.Parse(map[string]any{"person_info": map[string]any{
		"name":       map[string]any{"value": "X"},
		"newdataset": map[string]any{"source": "1", "score": map[string]any{"value": "42"}},
	}})
	rows, total := untypedItems(m)
	if total != 2 || len(rows) != 1 || rows[0].Label != "person_info.newdataset" || rows[0].Value != "score=42" {
		t.Errorf("untyped = %+v (total %d)", rows, total)
	}
}

func TestLabel(t *testing.T) {
	for name, want := range map[string]string{
		"HanyuPinyinName": "Hanyu pinyin name", "CPFBalances": "CPF balances", "HDBType": "HDB type",
		"DOB": "Date of birth", "COEExpiryDate": "COE expiry date", "VehicleNo": "Vehicle no", "IULabelNo": "IU label no",
	} {
		if got := label(name); got != want {
			t.Errorf("label(%q) = %q, want %q", name, got, want)
		}
	}
}
