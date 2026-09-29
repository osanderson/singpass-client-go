package main

import (
	"reflect"
	"sort"
	"strings"
	"unicode"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/examples/demo/internal/demoapp"
	"github.com/osanderson/singpass-client-go/myinfo"
)

// The profile page renders Myinfo data through the typed profiles —
// PersonProfile, EntityProfile and CorppassProfile — the way an integrator
// should read it. It walks the profile structs by reflection, so every typed
// item appears, labelled from its Go field name, with the accessor path that
// reads it; the groups below only arrange them into sections.

// profileSection is a page section: a title and the profile fields in it.
type profileSection struct {
	title  string
	fields []string
}

var personSections = []profileSection{
	{"Identity", []string{"Name", "UINFIN", "PartialUINFIN", "AliasName", "HanyuPinyinName", "HanyuPinyinAliasName", "MarriedName",
		"Sex", "Race", "SecondaryRace", "Dialect", "DOB", "BirthCountry", "Nationality", "ResidentialStatus"}},
	{"Contact", []string{"Email", "MobileNo", "RegAdd"}},
	{"Work and passes", []string{"Occupation", "Employment", "EmploymentSector", "PassType", "PassStatus", "PassExpiryDate", "PassportNumber", "PassportExpiryDate"}},
	{"Family", []string{"Marital", "MarriageDate", "DivorceDate", "CountryOfMarriage", "MarriageCertNo", "ChildrenBirthRecords", "SponsoredChildrenRecords"}},
	{"Housing and property", []string{"HousingType", "HDBType", "OwnerPrivate", "HDBOwnership"}},
	{"CPF", []string{"CPFBalances", "CPFContributions", "CPFEmployers", "CPFHousingWithdrawals", "CPFInvestmentScheme"}},
	{"Income tax", []string{"NOABasic", "NOA", "NOAHistoryBasic", "NOAHistory"}},
	{"Vehicles and driving", []string{"Vehicles", "DrivingLicence", "LTAVocationalLicences"}},
	{"Education", []string{"AcademicQualifications"}},
	{"Government schemes", []string{"CHAS", "MerdekaGenEligible", "PioneerGenEligible"}},
}

var entitySections = []profileSection{
	{"Entity", []string{"Name", "RegistrationNumber", "Type", "CompanyType", "Constitution", "UENStatus",
		"CountryOfIncorporation", "RegistrationDate", "ExpiryDate", "PrimaryActivity", "SecondaryActivity", "Address"}},
	{"People", []string{"Appointments", "Shareholders"}},
	{"Capital and financials", []string{"Capitals", "Financials"}},
	{"Licences and registrations", []string{"Licences", "Builders", "Contractors", "Grants"}},
	{"History", []string{"History"}},
}

var corppassSections = []profileSection{{"Corppass account", []string{"Email", "EmailVerified"}}}

var (
	fieldType   = reflect.TypeFor[myinfo.Field]()
	addressType = reflect.TypeFor[myinfo.Address]()
	phoneType   = reflect.TypeFor[myinfo.Phone]()
	dataType    = reflect.TypeFor[myinfo.Data]()
)

// typedSections renders the Myinfo data in id through the typed profiles.
func typedSections(id *singpass.Identity) []demoapp.Section {
	m := id.Myinfo
	var out []demoapp.Section
	add := func(secs []profileSection, profile any, root, prefix string) {
		v := reflect.ValueOf(profile)
		for _, s := range secs {
			sec := demoapp.Section{Title: prefix + s.title}
			for _, name := range s.fields {
				l := label(name)
				if name == "Employment" && root == "p" {
					l = "Employer" // the person's employer; NOA.Employment is income
				}
				renderField(&sec, v.FieldByName(name), l, root+"."+name)
			}
			if len(sec.Rows) > 0 || len(sec.Groups) > 0 || len(sec.Tables) > 0 {
				out = append(out, sec)
			}
		}
	}
	e := m.EntityProfile()
	if e.Data.Present() {
		add(entitySections, e, "e", "")
	}
	if p := m.PersonProfile(); p.Data.Present() {
		prefix := ""
		if e.Data.Present() {
			prefix = "Person: "
		}
		add(personSections, p, "p", prefix)
	}
	if c := m.CorppassProfile(); c.Data.Present() {
		add(corppassSections, c, "c", "")
	}
	if a := m.Auth; a.Present() {
		if s := authSection("Authorisations", a); len(s.Tables) > 0 {
			out = append(out, s)
		}
	}
	if tp := m.TPAuth; tp.Present() {
		if s := authSection("Third-party authorisations", tp); len(s.Tables) > 0 {
			out = append(out, s)
		}
	}
	for i := range out {
		out[i].Anchor = anchorize(out[i].Title)
	}
	return out
}

// renderField adds the profile field v to sec: a row, a group or a table.
func renderField(sec *demoapp.Section, v reflect.Value, name, path string) {
	switch {
	case v.Type() == fieldType, v.Type() == addressType, v.Type() == phoneType:
		if row, ok := valueRow(v, name, path); ok {
			sec.Rows = append(sec.Rows, row)
		}
	case v.Kind() == reflect.Struct:
		g := demoapp.Group{Title: name, Hint: path}
		groupRows(&g, v, "", path)
		if d := v.FieldByName("Data"); d.IsValid() && d.Type() == dataType {
			setBadge(&g.Badge, &g.BadgeKind, d.Interface().(myinfo.Data).EffectiveSource())
		}
		if len(g.Rows) > 0 || len(g.Tables) > 0 {
			sec.Groups = append(sec.Groups, g)
		}
	case v.Kind() == reflect.Slice && v.Type().Elem() == fieldType:
		var vals []string
		for i := range v.Len() {
			if f := v.Index(i).Interface().(myinfo.Field); f.Available() {
				vals = append(vals, f.String())
			}
		}
		if len(vals) > 0 {
			sec.Rows = append(sec.Rows, demoapp.Highlight{Label: name, Value: strings.Join(vals, ", "), Hint: path})
		}
	case v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Struct:
		if t, ok := table(v, name, path+"[i]"); ok {
			sec.Tables = append(sec.Tables, t)
		}
	}
}

// groupRows adds a struct's fields to g: values as rows (nested structs
// flattened as "Parent › Child"), and record lists as tables.
func groupRows(g *demoapp.Group, v reflect.Value, labelPrefix, path string) {
	for i := range v.NumField() {
		sf := v.Type().Field(i)
		fv := v.Field(i)
		if !sf.IsExported() || sf.Type == dataType {
			continue
		}
		name, p := joinName(labelPrefix, label(sf.Name)), path+"."+sf.Name
		switch {
		case fv.Type() == fieldType, fv.Type() == addressType, fv.Type() == phoneType:
			if row, ok := valueRow(fv, name, p); ok {
				g.Rows = append(g.Rows, row)
			}
		case fv.Kind() == reflect.Struct:
			groupRows(g, fv, name, p)
		case fv.Kind() == reflect.Slice && fv.Type().Elem().Kind() == reflect.Struct:
			if t, ok := table(fv, name, p+"[i]"); ok {
				g.Tables = append(g.Tables, t)
			}
		}
	}
}

// table renders a list of typed records: one column per field any record
// has, one row per record.
func table(v reflect.Value, name, path string) (demoapp.Table, bool) {
	if v.Len() == 0 {
		return demoapp.Table{}, false
	}
	elem := v.Type().Elem()
	t := demoapp.Table{Title: name, Hint: path}
	var cols []int
	for i := range elem.NumField() {
		sf := elem.Field(i)
		if !sf.IsExported() || sf.Type == dataType {
			continue
		}
		for r := range v.Len() {
			if cell(v.Index(r).Field(i), label(sf.Name)) != "" {
				cols = append(cols, i)
				t.Columns = append(t.Columns, label(sf.Name))
				break
			}
		}
	}
	if len(cols) == 0 {
		return demoapp.Table{}, false
	}
	var records []myinfo.Data
	for r := range v.Len() {
		row := demoapp.TableRow{}
		for _, i := range cols {
			row.Cells = append(row.Cells, cell(v.Index(r).Field(i), label(elem.Field(i).Name)))
		}
		t.Rows = append(t.Rows, row)
		if d := v.Index(r).FieldByName("Data"); d.IsValid() && d.Type() == dataType {
			records = append(records, d.Interface().(myinfo.Data))
		}
	}
	setBadge(&t.Badge, &t.BadgeKind, myinfo.CommonSource(records...))
	return t, true
}

// valueRow renders a Field, Address or Phone as a row, with its provenance.
func valueRow(v reflect.Value, name, path string) (demoapp.Highlight, bool) {
	row := demoapp.Highlight{Label: name, Hint: path}
	var src myinfo.Source
	switch x := v.Interface().(type) {
	case myinfo.Field:
		if x.Unavailable() {
			row.Note = "unavailable"
			return row, true
		}
		if !x.Available() {
			return row, false
		}
		row.Value = fieldText(x, name+" "+path)
		src = x.SourceCode()
		row.Updated = x.LastUpdated()
		row.Confidential = x.ClassificationCode().Confidential()
	case myinfo.Address:
		row.Value = strings.Join(x.Lines(), " / ")
		src = x.Data.EffectiveSource()
	case myinfo.Phone:
		if !x.Available() {
			return row, false
		}
		row.Value = x.String()
		if e := x.E164(); e != "" && e != row.Value {
			row.Value += " (" + e + ")"
		}
		src = x.Data.EffectiveSource()
	}
	if row.Value == "" {
		return row, false
	}
	setBadge(&row.Note, &row.NoteKind, src)
	return row, true
}

// cell renders one table cell: a value, a formatted address or phone, a
// flattened nested struct, or a list of them.
func cell(v reflect.Value, name string) string {
	switch x := v.Interface().(type) {
	case myinfo.Field:
		if x.Available() {
			return fieldText(x, name)
		}
		return ""
	case myinfo.Address:
		return x.String()
	case myinfo.Phone:
		return x.String()
	case string:
		return x
	case bool:
		return map[bool]string{true: "Yes", false: "No"}[x]
	}
	switch v.Kind() {
	case reflect.Struct:
		var parts []string
		for i := range v.NumField() {
			sf := v.Type().Field(i)
			if !sf.IsExported() || sf.Type == dataType {
				continue
			}
			if c := cell(v.Field(i), label(sf.Name)); c != "" && c != "No" {
				parts = append(parts, label(sf.Name)+": "+c)
			}
		}
		return strings.Join(parts, "; ")
	case reflect.Slice:
		var parts []string
		for i := range v.Len() {
			if c := cell(v.Index(i), name); c != "" {
				parts = append(parts, c)
			}
		}
		return strings.Join(parts, " | ")
	}
	return ""
}

// fieldText renders a Field's value: a coded item as "DESC (CODE)", a boolean
// as Yes/No, and an amount thousands-separated. context is the field's label
// and accessor path, which say whether it is money.
func fieldText(f myinfo.Field, context string) string {
	if f.Code() != "" && f.Desc() != "" && f.Code() != f.Desc() {
		return f.Desc() + " (" + f.Code() + ")"
	}
	if b, ok := f.Bool(); ok && (f.Value() == "true" || f.Value() == "false") {
		return map[bool]string{true: "Yes", false: "No"}[b]
	}
	return formatAmount(context, f.String())
}

// untypedItems lists the returned items the typed profiles don't read: top-
// level items that aren't in Singpass's or Corppass's data catalogues, such
// as ones a newer Myinfo release adds. It also returns how many items were
// returned in all.
func untypedItems(m *myinfo.Response) (rows []demoapp.Highlight, total int) {
	person, business := map[string]bool{}, map[string]bool{}
	for _, s := range myinfo.AllScopes() {
		item, _, _ := strings.Cut(s, ".")
		person[item] = true
	}
	for _, s := range myinfo.AllBusinessScopes() {
		if rest, ok := strings.CutPrefix(s, "entity."); ok {
			item, _, _ := strings.Cut(rest, ".")
			business[item] = true
		}
	}
	check := func(block string, d myinfo.Data, known func(string) bool) {
		for _, k := range d.Keys() {
			if d.Kind(k) == myinfo.KindScalar {
				continue // envelope metadata
			}
			total++
			if known(k) {
				continue
			}
			var vals []string
			if d.Kind(k) == myinfo.KindLeaf {
				vals = append(vals, d.Field(k).String())
			} else {
				for _, l := range d.Object(k).Leaves() {
					vals = append(vals, strings.Join(l.Path, ".")+"="+l.Field.String())
				}
			}
			rows = append(rows, demoapp.Highlight{Label: block + "." + k, Value: strings.Join(vals, "; ")})
		}
	}
	check("person_info", m.Person, func(k string) bool { return person[k] })
	check("entity_info", m.Entity, func(k string) bool { return business[k] })
	check("corppass_info", m.Corppass, func(k string) bool { return k == "email" || k == "email_verified" })
	sort.Slice(rows, func(i, j int) bool { return rows[i].Label < rows[j].Label })
	return rows, total
}

// setBadge sets a provenance badge from s, when it is known.
func setBadge(text, kind *string, s myinfo.Source) {
	if s != myinfo.SourceUnknown {
		*text, *kind = s.String(), sourceKind(s)
	}
}

// labelOverrides are the Go field names whose split form isn't the label.
var labelOverrides = map[string]string{
	"UINFIN": "NRIC / FIN", "PartialUINFIN": "Masked NRIC / FIN", "DOB": "Date of birth", "TOB": "Time of birth",
	"RegAdd": "Registered address", "MobileNo": "Mobile number",
	"NOA": "Notice of Assessment (detailed)", "NOABasic": "Notice of Assessment (basic)",
	"NOAHistory": "NOA history (detailed)", "NOAHistoryBasic": "NOA history (basic)",
	"OA": "Ordinary Account", "SA": "Special Account", "MA": "MediSave Account", "RA": "Retirement Account",
	"SGCitizenAtBirth": "Singapore citizen at birth", "CHAS": "CHAS card", "UENStatus": "UEN status",
	"RegistrationNumber": "UEN", "COMStatus": "Certificate of Merit", "QDL": "Qualified licence", "PDL": "Provisional licence",
	"MerdekaGenEligible": "Merdeka Generation", "PioneerGenEligible": "Pioneer Generation",
}

// label turns a Go field name into a display label: "HanyuPinyinName" →
// "Hanyu pinyin name", "CPFBalances" → "CPF balances".
func label(name string) string {
	if l, ok := labelOverrides[name]; ok {
		return l
	}
	var words []string
	rs := []rune(name)
	start := 0
	for i := 1; i < len(rs); i++ {
		if unicode.IsUpper(rs[i]) && (unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]))) {
			words = append(words, string(rs[start:i]))
			start = i
		}
	}
	words = append(words, string(rs[start:]))
	for i, w := range words {
		if i > 0 && strings.ToUpper(w) != w {
			words[i] = strings.ToLower(w)
		}
	}
	return strings.Join(words, " ")
}

func joinName(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + " › " + name
}
