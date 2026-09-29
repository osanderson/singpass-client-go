package main

import (
	"fmt"
	"strings"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/examples/demo/internal/demoapp"
	"github.com/osanderson/singpass-client-go/myinfo"
)

// summary builds the Summary card from the typed profiles — PersonProfile and
// EntityProfile — rather than by key, showing each row's accessor call so the
// card doubles as a reference for the typed API. It returns nil when the
// response has no data the profiles model.
func summary(id *singpass.Identity) []demoapp.Highlight {
	if id.Myinfo == nil {
		return nil
	}
	var rows []demoapp.Highlight
	add := func(label, value, hint string, source myinfo.Source) {
		if value == "" {
			return
		}
		h := demoapp.Highlight{Label: label, Value: value, Hint: hint}
		if source != myinfo.SourceUnknown {
			h.Note, h.NoteKind = source.String(), sourceKind(source)
		}
		rows = append(rows, h)
	}
	field := func(label string, f myinfo.Field, hint string) {
		if f.Available() {
			add(label, f.String(), hint, f.SourceCode())
		}
	}

	e := id.Myinfo.EntityProfile()
	if e.Data.Present() {
		field("Entity", e.Name, "e.Name.String()")
		if e.RegistrationNumber.Available() {
			field("UEN", e.RegistrationNumber, "e.RegistrationNumber.String()")
		} else {
			add("UEN", id.SubjectAttributes().EntityRegNumber, "id.SubjectAttributes().EntityRegNumber", myinfo.SourceUnknown)
		}
		field("Entity type", e.Type, "e.Type.String()")
		field("Company type", e.CompanyType, "e.CompanyType.String()")
		field("UEN status", e.UENStatus, "e.UENStatus.String()")
		if d, ok := e.RegistrationDate.Date(); ok {
			add("Registered", d.Format("2 January 2006"), "e.RegistrationDate.Date()", e.RegistrationDate.SourceCode())
		}
		if a := e.PrimaryActivity; a.Available() {
			add("Primary activity", a.String()+" (SSIC "+a.Code()+")", "e.PrimaryActivity.String(), .Code()", a.SourceCode())
		}
		for _, c := range e.Capitals {
			if x, ok := c.PaidUpAmount.Float(); ok {
				add("Paid-up capital", sgd(x)+" "+c.ShareType.String(), "e.Capitals[i].PaidUpAmount.Float()", c.Data.SourceCode())
			}
		}
		if len(e.Financials) > 0 {
			f := e.Financials[0]
			if x, ok := f.Company.Revenue.Float(); ok {
				period := ""
				if end, ok := f.CurrentPeriodEndDate.Date(); ok {
					period = " (FY to " + end.Format("Jan 2006") + ")"
				}
				add("Revenue"+period, sgd(x), "e.Financials[0].Company.Revenue.Float()", f.Data.SourceCode())
			}
		}
		add("Address", e.Address.String(), "e.Address.String()", e.Address.Data.EffectiveSource())
		if n := len(e.Appointments); n > 0 {
			add("Appointments", partyList(n, func(i int) (string, myinfo.Party) {
				return e.Appointments[i].Position, e.Appointments[i].Appointee
			}), "e.Appointments", myinfo.CommonSource(appointmentData(e.Appointments)...))
		}
		if n := len(e.Shareholders); n > 0 {
			add("Shareholders", partyList(n, func(i int) (string, myinfo.Party) {
				return e.Shareholders[i].Allocation + " " + e.Shareholders[i].ShareType, e.Shareholders[i].Holder
			}), "e.Shareholders", myinfo.SourceUnknown)
		}
	}

	p := id.Myinfo.PersonProfile()
	if p.Data.Present() {
		field("Name", p.Name, "p.Name.String()")
		field("UINFIN", p.UINFIN, "p.UINFIN.String()")
		if p.Sex.Available() {
			add("Sex", codeAndDesc(p.Sex), "p.Sex.Code(), p.Sex.String()", p.Sex.SourceCode())
		}
		if dob, ok := p.DOB.Date(); ok {
			add("Date of birth", dob.Format("2 January 2006"), "p.DOB.Date()", p.DOB.SourceCode())
		}
		field("Nationality", p.Nationality, "p.Nationality.String()")
		field("Residential status", p.ResidentialStatus, "p.ResidentialStatus.String()")
		field("Email", p.Email, "p.Email.String()")
		if p.MobileNo.Available() {
			value := p.MobileNo.String()
			if e164 := p.MobileNo.E164(); e164 != "" && e164 != value {
				value += " (" + e164 + ")"
			}
			add("Mobile", value, "p.MobileNo.String(), p.MobileNo.E164()", p.MobileNo.Data.EffectiveSource())
		}
		add("Registered address", strings.Join(p.RegAdd.Lines(), " / "), "p.RegAdd.Lines()", p.RegAdd.Data.EffectiveSource())
		field("Housing type", p.HousingType, "p.HousingType.String()")
		field("HDB type", p.HDBType, "p.HDBType.String()")
		if x, ok := p.NOABasic.Amount.Float(); ok {
			add("Assessable income (YA "+p.NOABasic.YearOfAssessment.String()+")", sgd(x), "p.NOABasic.Amount.Float()", p.NOABasic.Data.SourceCode())
		}
		for i, v := range p.Vehicles {
			if i == 3 {
				break
			}
			value := strings.TrimSpace(v.VehicleNo.String() + " " + v.Make.String() + " " + v.Model.String())
			if coe, ok := v.COEExpiryDate.Date(); ok {
				value += ", COE to " + coe.Format("2 Jan 2006")
			}
			add("Vehicle", value, "p.Vehicles[i].VehicleNo, .Make, .Model, .COEExpiryDate.Date()", v.Data.SourceCode())
		}
		for _, h := range p.HDBOwnership {
			add("HDB flat owned", strings.TrimSpace(h.HDBType.String()+", "+h.Address.String()), "p.HDBOwnership[i].HDBType, .Address", h.Data.SourceCode())
		}
		for _, acct := range []struct {
			label string
			f     myinfo.Field
			hint  string
		}{
			{"CPF Ordinary Account", p.CPFBalances.OA, "p.CPFBalances.OA.Float()"},
			{"CPF Special Account", p.CPFBalances.SA, "p.CPFBalances.SA.Float()"},
			{"CPF MediSave Account", p.CPFBalances.MA, "p.CPFBalances.MA.Float()"},
			{"CPF Retirement Account", p.CPFBalances.RA, "p.CPFBalances.RA.Float()"},
		} {
			if x, ok := acct.f.Float(); ok {
				add(acct.label, sgd(x), acct.hint, p.CPFBalances.Data.EffectiveSource())
			}
		}
	}
	return rows
}

// codeAndDesc shows a coded field as "FEMALE (F)".
func codeAndDesc(f myinfo.Field) string {
	if c := f.Code(); c != "" && c != f.String() {
		return f.String() + " (" + c + ")"
	}
	return f.String()
}

// partyList summarises records as "n: ROLE NAME; ROLE NAME…", listing the first three.
func partyList(n int, at func(int) (string, myinfo.Party)) string {
	var parts []string
	for i := 0; i < n && i < 3; i++ {
		role, party := at(i)
		parts = append(parts, strings.TrimSpace(role+" "+party.Name))
	}
	s := fmt.Sprintf("%d: %s", n, strings.Join(parts, "; "))
	if n > 3 {
		s += "; …"
	}
	return s
}

func appointmentData(as []myinfo.Appointment) []myinfo.Data {
	out := make([]myinfo.Data, len(as))
	for i, a := range as {
		out[i] = a.Data
	}
	return out
}

// sgd formats an amount as "S$1,581.48".
func sgd(x float64) string {
	s := fmt.Sprintf("%.2f", x)
	intPart, frac := s[:len(s)-3], s[len(s)-3:]
	neg := strings.HasPrefix(intPart, "-")
	intPart = strings.TrimPrefix(intPart, "-")
	var b strings.Builder
	for i, r := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := "S$" + b.String() + frac
	if neg {
		out = "-" + out
	}
	return out
}
