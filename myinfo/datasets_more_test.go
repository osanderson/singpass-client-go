package myinfo

import (
	"os"
	"regexp"
	"testing"
)

// Every person-data item in Singpass's catalogue is read by PersonProfile, so
// a catalogue update that adds an item fails here until it is modelled.
func TestPersonProfileCoversCatalogue(t *testing.T) {
	src, err := os.ReadFile("profile.go")
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]bool{}
	for _, m := range regexp.MustCompile(`p\.(?:Field|Object|List|Phone|Address)\("([^"]+)"\)|childRecords\(p, "([^"]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		read[m[1]+m[2]] = true
	}
	for item := range catalogue {
		if !read[item] {
			t.Errorf("PersonProfile doesn't read %q", item)
		}
	}
}

func TestRemainingPersonDatasets(t *testing.T) {
	v := func(x any) map[string]any { return map[string]any{"value": x} }
	c := func(code, desc string) map[string]any { return map[string]any{"code": code, "desc": desc} }
	p := Parse(map[string]any{"person_info": map[string]any{
		"partialuinfin": v("****381D"), "employment": v("ACME PTE LTD"), "marriagedate": v("2020-02-20"),
		"countryofmarriage": c("SG", "SINGAPORE"), "ownerprivate": v(false),
		"merdekagen": map[string]any{"eligibility": v(true)},
		"chas":       map[string]any{"cardtype": c("G", "GREEN"), "expirydate": v("2027-12-31")},
		"cpfinvestmentscheme": map[string]any{
			"account": map[string]any{"agentbankcode": v("DBS"), "invbankacctno": v("1234")}, "sdsnetshareholdingqty": v(500),
		},
		"cpfcontributions": map[string]any{"history": []any{
			map[string]any{"month": v("2026-07"), "date": v("2026-08-10"), "amount": v(1480.0), "employer": v("ACME PTE LTD")},
			map[string]any{"month": v("2026-08"), "date": v("2026-09-10"), "amount": v(1480.0), "employer": v("ACME PTE LTD")},
		}},
		"cpfemployers": map[string]any{"history": []any{map[string]any{"month": v("2026-08"), "employer": v("ACME PTE LTD")}}},
		"cpfhousingwithdrawal": map[string]any{"withdrawaldetails": []any{map[string]any{
			"address":                map[string]any{"type": "SG", "block": v("102"), "street": v("BEDOK NORTH AVENUE 4"), "postal": v("460102")},
			"principalwithdrawalamt": v(98000.5), "accruedinterestamt": v(4200.0),
		}}},
		"ltavocationallicences": map[string]any{"tdvl": map[string]any{"licencename": v("TAXI DRIVER"), "status": c("V", "VALID"), "expirydate": v("2028-01-01")}},
		"academicqualifications": map[string]any{
			"transcripts": []any{map[string]any{"name": v("GCE O-LEVEL"), "yearattained": v("2014"), "results": []any{
				map[string]any{"subject": v("MATHEMATICS"), "level": v("O"), "grade": v("A1")},
			}}},
			"certificates": []any{map[string]any{"name": v("cert.pdf"), "opencertificateindicator": v(true), "opencertificate": map[string]any{"id": v("oc-1")}}},
		},
		"childrenbirthrecords": []any{map[string]any{
			"name": v("TAN AH KOW"), "dob": v("2020-05-05"), "birthcertno": v("T2012345A"), "sgcitizenatbirthind": v("Y"),
			"vaccinationrequirements": []any{map[string]any{"requirement": c("1M3", "MEASLES"), "fulfilled": v(true)}},
		}},
		"sponsoredchildrenrecords": []any{map[string]any{"name": v("LIM MEI"), "nric": v("S1234567A"), "nationality": c("SG", "SINGAPORE CITIZEN")}},
	}}).PersonProfile()

	if p.PartialUINFIN.String() != "****381D" || p.Employment.String() != "ACME PTE LTD" || p.CountryOfMarriage.Code() != "SG" {
		t.Errorf("scalars = %q %q %q", p.PartialUINFIN.String(), p.Employment.String(), p.CountryOfMarriage.Code())
	}
	if d, ok := p.MarriageDate.Date(); !ok || d.Year() != 2020 {
		t.Errorf("MarriageDate = %v", d)
	}
	if b, ok := p.OwnerPrivate.Bool(); !ok || b {
		t.Errorf("OwnerPrivate = %v, %v", b, ok)
	}
	if b, ok := p.MerdekaGenEligible.Bool(); !ok || !b || p.PioneerGenEligible.Present() {
		t.Errorf("generation schemes = %v / %v", b, p.PioneerGenEligible.Present())
	}
	if p.CHAS.CardType.Code() != "G" || p.CPFInvestmentScheme.AgentBankCode.String() != "DBS" {
		t.Errorf("CHAS / CPFIS = %+v / %+v", p.CHAS, p.CPFInvestmentScheme)
	}
	if n, _ := p.CPFInvestmentScheme.SDSNetShareholdingQty.Int(); n != 500 {
		t.Errorf("SDS qty = %d", n)
	}
	if len(p.CPFContributions) != 2 || p.CPFContributions[1].Month.String() != "2026-08" || len(p.CPFEmployers) != 1 {
		t.Errorf("CPF history = %+v / %+v", p.CPFContributions, p.CPFEmployers)
	}
	if amt, _ := p.CPFContributions[0].Amount.Float(); amt != 1480 {
		t.Errorf("contribution amount = %v", amt)
	}
	if len(p.CPFHousingWithdrawals) != 1 || p.CPFHousingWithdrawals[0].Address.String() != "102 BEDOK NORTH AVENUE 4, SINGAPORE 460102" {
		t.Errorf("housing withdrawals = %+v", p.CPFHousingWithdrawals)
	}
	if p.LTAVocationalLicences.TDVL.Status.Code() != "V" || p.LTAVocationalLicences.PDVL.LicenceName.Present() {
		t.Errorf("vocational licences = %+v", p.LTAVocationalLicences)
	}
	aq := p.AcademicQualifications
	if len(aq.Transcripts) != 1 || aq.Transcripts[0].Results[0].Grade.String() != "A1" || len(aq.Certificates) != 1 || aq.Certificates[0].OpenCertificateID.String() != "oc-1" {
		t.Errorf("academic qualifications = %+v", aq)
	}
	if len(p.ChildrenBirthRecords) != 1 || p.ChildrenBirthRecords[0].BirthCertNo.String() != "T2012345A" || len(p.ChildrenBirthRecords[0].VaccinationRequirements) != 1 {
		t.Errorf("children = %+v", p.ChildrenBirthRecords)
	}
	if ok, _ := p.ChildrenBirthRecords[0].VaccinationRequirements[0].Fulfilled.Bool(); !ok {
		t.Error("vaccination fulfilled")
	}
	if len(p.SponsoredChildrenRecords) != 1 || p.SponsoredChildrenRecords[0].NRIC.String() != "S1234567A" {
		t.Errorf("sponsored children = %+v", p.SponsoredChildrenRecords)
	}
}

func TestCorppassProfile(t *testing.T) {
	// corppass_info carries bare values, not Myinfo envelopes.
	c := Parse(map[string]any{"corppass_info": map[string]any{"email": "john@corppass.gov.sg", "email_verified": true}}).CorppassProfile()
	if c.Email.String() != "john@corppass.gov.sg" {
		t.Errorf("Email = %q", c.Email.String())
	}
	if b, ok := c.EmailVerified.Bool(); !ok || !b {
		t.Errorf("EmailVerified = %v, %v", b, ok)
	}
	var nilResp *Response
	if nilResp.CorppassProfile().Email.Present() {
		t.Error("nil Response")
	}
}
