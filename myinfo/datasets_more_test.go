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

	checkAll(t,
		check{"CPFContributions", len(p.CPFContributions), 2},
		check{"CPFEmployers", len(p.CPFEmployers), 1},
		check{"CPFHousingWithdrawals", len(p.CPFHousingWithdrawals), 1},
		check{"Transcripts", len(p.AcademicQualifications.Transcripts), 1},
		check{"Certificates", len(p.AcademicQualifications.Certificates), 1},
		check{"ChildrenBirthRecords", len(p.ChildrenBirthRecords), 1},
		check{"SponsoredChildrenRecords", len(p.SponsoredChildrenRecords), 1},
	)
	if t.Failed() {
		return
	}
	aq, child := p.AcademicQualifications, p.ChildrenBirthRecords[0]
	checkAll(t,
		check{"PartialUINFIN", p.PartialUINFIN.String(), "****381D"},
		check{"Employment", p.Employment.String(), "ACME PTE LTD"},
		check{"CountryOfMarriage", p.CountryOfMarriage.Code(), "SG"},
		check{"MarriageDate", dateOf(p.MarriageDate), "2020-02-20"},
		check{"OwnerPrivate", boolOf(p.OwnerPrivate), false},
		check{"MerdekaGenEligible", boolOf(p.MerdekaGenEligible), true},
		check{"PioneerGenEligible present", p.PioneerGenEligible.Present(), false},
		check{"CHAS.CardType", p.CHAS.CardType.Code(), "G"},
		check{"CPFInvestmentScheme.AgentBankCode", p.CPFInvestmentScheme.AgentBankCode.String(), "DBS"},
		check{"SDSNetShareholdingQty", intOf(p.CPFInvestmentScheme.SDSNetShareholdingQty), int64(500)},
		check{"CPFContributions[1].Month", p.CPFContributions[1].Month.String(), "2026-08"},
		check{"CPFContributions[0].Amount", floatOf(p.CPFContributions[0].Amount), 1480.0},
		check{"CPFHousingWithdrawals[0].Address", p.CPFHousingWithdrawals[0].Address.String(), "102 BEDOK NORTH AVENUE 4, SINGAPORE 460102"},
		check{"TDVL.Status", p.LTAVocationalLicences.TDVL.Status.Code(), "V"},
		check{"PDVL present", p.LTAVocationalLicences.PDVL.LicenceName.Present(), false},
		check{"Transcripts[0].Results[0].Grade", aq.Transcripts[0].Results[0].Grade.String(), "A1"},
		check{"Certificates[0].OpenCertificateID", aq.Certificates[0].OpenCertificateID.String(), "oc-1"},
		check{"child BirthCertNo", child.BirthCertNo.String(), "T2012345A"},
		check{"child VaccinationRequirements", len(child.VaccinationRequirements), 1},
		check{"SponsoredChildrenRecords[0].NRIC", p.SponsoredChildrenRecords[0].NRIC.String(), "S1234567A"},
	)
	if len(child.VaccinationRequirements) == 1 {
		checkAll(t, check{"vaccination fulfilled", boolOf(child.VaccinationRequirements[0].Fulfilled), true})
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
