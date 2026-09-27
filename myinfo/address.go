package myinfo

import "strings"

// Address is a Myinfo address object — a person's regadd, or a Myinfo Business
// entity's address — with its parts as Fields. Myinfo sends one of two shapes:
// a structured Singapore address (Type "SG": block, building, floor, unit,
// street, postal, country) or an unformatted one (line1, line2), usually for an
// overseas address. The zero Address is valid: Present is false and Lines is
// empty.
type Address struct {
	// Type is the address format as sent: "SG" for a structured address, or
	// "Unformatted". Empty when the object doesn't declare one.
	Type string

	Block    Field // block
	Building Field // building
	Floor    Field // floor
	Unit     Field // unit
	Street   Field // street
	Postal   Field // postal
	Country  Field // country (coded, e.g. SG / SINGAPORE)

	Line1 Field // line1, for an unformatted address
	Line2 Field // line2, for an unformatted address

	// Data is the address object itself: its provenance (Data.SourceCode —
	// Myinfo declares it on the address, not on each part) and any part not
	// modelled here.
	Data Data
}

// Address returns the address object at key, e.g. p.Address("regadd") for a
// person or id.Myinfo.Entity.Address("address") for a Myinfo Business entity.
func (d Data) Address(key string) Address {
	a := d.Object(key)
	if !a.Present() {
		return Address{}
	}
	return Address{
		Type:     asString(a.m["type"]),
		Block:    a.Field("block"),
		Building: a.Field("building"),
		Floor:    a.Field("floor"),
		Unit:     a.Field("unit"),
		Street:   a.Field("street"),
		Postal:   a.Field("postal"),
		Country:  a.Field("country"),
		Line1:    a.Field("line1"),
		Line2:    a.Field("line2"),
		Data:     a,
	}
}

// Present reports whether the address was in the response.
func (a Address) Present() bool { return a.Data.Present() }

// Lines formats the address for a mailing label, in the usual Singapore
// order: "102 BEDOK NORTH AVENUE 4", "#09-128 BUILDING NAME",
// "SINGAPORE 460102". An unformatted address gives its lines as sent,
// followed by the country when there is one. Empty parts are skipped, and the
// text keeps Myinfo's case.
func (a Address) Lines() []string {
	var lines []string
	add := func(parts ...string) {
		if l := joinNonEmpty(" ", parts...); l != "" {
			lines = append(lines, l)
		}
	}
	country := a.Country.String()
	if a.Line1.Available() || a.Line2.Available() {
		add(a.Line1.String())
		add(a.Line2.String())
		add(country)
		return lines
	}
	add(a.Block.String(), a.Street.String())
	unit := ""
	if f, u := a.Floor.String(), a.Unit.String(); f != "" && u != "" {
		unit = "#" + f + "-" + u
	} else if u != "" {
		unit = "#" + u
	}
	add(unit, a.Building.String())
	if country == "" && strings.EqualFold(a.Type, "SG") {
		country = "SINGAPORE"
	}
	add(country, a.Postal.String())
	return lines
}

// String is Lines joined with ", " — the address on one line.
func (a Address) String() string { return strings.Join(a.Lines(), ", ") }

// Phone is a Myinfo phone number object, such as a person's mobileno, with
// its parts as Fields.
type Phone struct {
	Prefix   Field // prefix, e.g. "+"
	AreaCode Field // areacode, e.g. "65"
	Number   Field // nbr, e.g. "97399245"

	// Data is the phone object itself, for its provenance (Data.SourceCode).
	Data Data
}

// Phone returns the phone number object at key, e.g. p.Phone("mobileno").
func (d Data) Phone(key string) Phone {
	p := d.Object(key)
	if !p.Present() {
		return Phone{}
	}
	return Phone{Prefix: p.Field("prefix"), AreaCode: p.Field("areacode"), Number: p.Field("nbr"), Data: p}
}

// Present reports whether the phone number was in the response.
func (p Phone) Present() bool { return p.Data.Present() }

// Available reports whether there is a number to use.
func (p Phone) Available() bool { return p.Number.Available() }

// String returns the number for display, e.g. "+65 97399245", or just the
// number when Myinfo sends no area code.
func (p Phone) String() string {
	if p.AreaCode.String() == "" {
		return p.Number.String()
	}
	return joinNonEmpty(" ", p.Prefix.String()+p.AreaCode.String(), p.Number.String())
}

// E164 returns the number in E.164 form, e.g. "+6597399245", or "" when
// Myinfo sends no area code or number.
func (p Phone) E164() string {
	cc, n := strings.TrimPrefix(p.AreaCode.String(), "+"), p.Number.String()
	if cc == "" || n == "" {
		return ""
	}
	return "+" + cc + n
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}
