package myinfo

// Party is the person or organisation in a Myinfo Business appointment or
// shareholding. Corppass nests it under individual_* or entity_*; Party
// flattens both shapes. Values are Field.String() — the coded description
// where Corppass sends a code.
type Party struct {
	// Individual is true for a person (individual_appointment /
	// individual_shareholder), false for an entity.
	Individual bool
	Name       string
	// For a person.
	IDNumber    string // id_number
	IDType      string // id_type
	Nationality string // nationality
	// For an entity.
	RegistrationNumber string // registration_number
	Type               string // type
}

// Appointment is one entity_info appointments record (a director, secretary,
// …), with its party flattened.
type Appointment struct {
	Position        string // position
	Designation     string // designation
	Category        string // category
	AppointmentDate string // appointment_date
	Appointee       Party
	// Data is the raw record, for provenance (Data.EffectiveSource) and any
	// field not modelled here.
	Data Data
}

// Shareholder is one entity_info shareholders record, with its party
// flattened.
type Shareholder struct {
	Allocation string // allocation: number of shares
	ShareType  string // share_type
	Currency   string // currency
	Category   string // category
	Holder     Party
	// Data is the raw record, for provenance and any field not modelled here.
	Data Data
}

// Appointments returns the appointments in a Myinfo Business entity_info
// block (id.Myinfo.Entity), or nil when there are none.
func (d Data) Appointments() []Appointment {
	var out []Appointment
	for _, r := range d.List("appointments") {
		if !r.Present() {
			continue
		}
		out = append(out, Appointment{
			Position:        r.Field("position").String(),
			Designation:     r.Field("designation").String(),
			Category:        r.Field("category").String(),
			AppointmentDate: r.Field("appointment_date").String(),
			Appointee:       party(r, "individual_appointment", "entity_appointment"),
			Data:            r,
		})
	}
	return out
}

// Shareholders returns the shareholders in a Myinfo Business entity_info
// block (id.Myinfo.Entity), or nil when there are none.
func (d Data) Shareholders() []Shareholder {
	var out []Shareholder
	for _, r := range d.List("shareholders") {
		if !r.Present() {
			continue
		}
		out = append(out, Shareholder{
			Allocation: r.Field("allocation").String(),
			ShareType:  r.Field("share_type").String(),
			Currency:   r.Field("currency").String(),
			Category:   r.Field("category").String(),
			Holder:     party(r, "individual_shareholder", "entity_shareholder"),
			Data:       r,
		})
	}
	return out
}

// party reads the individual or entity party object of a record.
func party(r Data, individualKey, entityKey string) Party {
	if p := r.Object(individualKey); p.Present() {
		return Party{
			Individual:  true,
			Name:        p.Field("name").String(),
			IDNumber:    p.Field("id_number").String(),
			IDType:      p.Field("id_type").String(),
			Nationality: p.Field("nationality").String(),
		}
	}
	p := r.Object(entityKey)
	return Party{
		Name:               p.Field("name").String(),
		RegistrationNumber: p.Field("registration_number").String(),
		Type:               p.Field("type").String(),
	}
}
