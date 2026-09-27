package myinfo

import (
	"reflect"
	"strings"
	"testing"
)

func TestLeaves(t *testing.T) {
	m := Parse(map[string]any{"person_info": map[string]any{
		"name":   map[string]any{"value": "TAN XIAO HUI", "source": "1"},
		"email":  map[string]any{"unavailable": true, "source": "2"},
		"regadd": map[string]any{"source": "1", "postal": map[string]any{"value": "460123"}},
		"vehicles": []any{
			map[string]any{"source": "1", "make": map[string]any{"value": "TOYOTA"}},
		},
	}})
	var got []string
	for _, l := range m.Person.Leaves() {
		got = append(got, strings.Join(l.Path, ".")+"="+l.Field.String())
	}
	want := []string{"email=", "name=TAN XIAO HUI", "regadd.postal=460123", "vehicles.0.make=TOYOTA"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Leaves = %v, want %v", got, want)
	}
	if l := m.Person.Leaves()[2]; l.Key() != "postal" {
		t.Errorf("Key() = %q", l.Key())
	}
	var zero Data
	if zero.Leaves() != nil {
		t.Error("zero Data has leaves")
	}
}

func TestEffectiveSource(t *testing.T) {
	m := Parse(map[string]any{"person_info": map[string]any{
		// Grouped dataset: source on the container, {value}-only leaves.
		"regadd": map[string]any{"source": "1", "postal": map[string]any{"value": "460123"}},
		"name":   map[string]any{"value": "TAN", "source": "1"},
		// Uniform leaves, no container source.
		"cpfbalances": map[string]any{
			"oa": map[string]any{"value": "100", "source": "1"},
			"sa": map[string]any{"value": "200", "source": "1"},
		},
		// Mixed leaves.
		"contact": map[string]any{
			"email":    map[string]any{"value": "a@b", "source": "2"},
			"mobileno": map[string]any{"value": "9", "source": "4"},
		},
	}})
	p := m.Person
	for key, want := range map[string]Source{
		"regadd":      SourceGovernmentVerified, // declared by the container
		"cpfbalances": SourceGovernmentVerified, // uniform leaves
		"contact":     SourceUnknown,            // mixed
	} {
		if got := p.Object(key).EffectiveSource(); got != want {
			t.Errorf("%s: EffectiveSource = %v, want %v", key, got, want)
		}
	}
	// The block mixes government-verified with the mixed "contact" object's
	// user-provided items, so it has no single source.
	if got := p.EffectiveSource(); got != SourceUnknown {
		t.Errorf("block EffectiveSource = %v, want unknown", got)
	}
	if got := CommonSource(p.Object("regadd"), p.Object("cpfbalances")); got != SourceGovernmentVerified {
		t.Errorf("CommonSource = %v", got)
	}
	if got := CommonSource(p.Object("regadd"), p.Object("contact").Object("email")); got != SourceUnknown {
		t.Errorf("CommonSource of differing items = %v", got)
	}
}

func TestLabel(t *testing.T) {
	for key, want := range map[string]string{
		"hdbownership":      "HDB ownership",
		"noa-basic":         "NOA basic (Notice of Assessment)",
		"uinfin":            "UINFIN",
		"entity_reg_number": "Entity reg number",
		"appointment_date":  "Appointment date",
		"name":              "Name",
		"":                  "",
	} {
		if got := Label(key); got != want {
			t.Errorf("Label(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestAppointmentsAndShareholders(t *testing.T) {
	entity := Parse(map[string]any{"entity_info": map[string]any{
		"appointments": []any{
			map[string]any{
				"source": "1", "position": map[string]any{"code": "D", "desc": "DIRECTOR"},
				"appointment_date": map[string]any{"value": "2019-06-01"},
				"individual_appointment": map[string]any{
					"name": map[string]any{"value": "LIM WEI MING"}, "id_number": map[string]any{"value": "S7812345J"},
					"id_type": map[string]any{"code": "NRIC", "desc": "NRIC"}, "nationality": map[string]any{"code": "SG", "desc": "SINGAPORE CITIZEN"},
				},
			},
			map[string]any{
				"position": map[string]any{"value": "SECRETARY"},
				"entity_appointment": map[string]any{
					"name": map[string]any{"value": "CORPSEC PTE LTD"}, "registration_number": map[string]any{"value": "200011111A"},
				},
			},
		},
		"shareholders": []any{map[string]any{
			"allocation": map[string]any{"value": 1000}, "share_type": map[string]any{"desc": "ORDINARY"},
			"entity_shareholder": map[string]any{"name": map[string]any{"value": "HOLDCO PTE LTD"}},
		}},
	}}).Entity

	a := entity.Appointments()
	if len(a) != 2 {
		t.Fatalf("Appointments = %d, want 2", len(a))
	}
	if a[0].Position != "DIRECTOR" || a[0].AppointmentDate != "2019-06-01" || !a[0].Appointee.Individual ||
		a[0].Appointee.Name != "LIM WEI MING" || a[0].Appointee.IDNumber != "S7812345J" || a[0].Appointee.Nationality != "SINGAPORE CITIZEN" {
		t.Errorf("individual appointment = %+v", a[0])
	}
	if a[0].Data.EffectiveSource() != SourceGovernmentVerified {
		t.Error("record Data should keep its provenance")
	}
	if a[1].Appointee.Individual || a[1].Appointee.Name != "CORPSEC PTE LTD" || a[1].Appointee.RegistrationNumber != "200011111A" {
		t.Errorf("entity appointment = %+v", a[1])
	}

	s := entity.Shareholders()
	if len(s) != 1 || s[0].Allocation != "1000" || s[0].ShareType != "ORDINARY" || s[0].Holder.Individual || s[0].Holder.Name != "HOLDCO PTE LTD" {
		t.Errorf("Shareholders = %+v", s)
	}

	var none Data
	if none.Appointments() != nil || none.Shareholders() != nil {
		t.Error("absent block should have no records")
	}
}
