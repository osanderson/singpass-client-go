package myinfo

// The remaining person_info datasets, modelled on Singpass's person-data
// OpenAPI specification: CPF records, health and generation schemes, LTA
// vocational licences, education, and children.

// CHAS is the person's Community Health Assist Scheme card.
type CHAS struct {
	CardType   Field // cardtype (coded), e.g. the card tier
	Indicator  Field // indicator (coded)
	Name       Field // name
	IssueDate  Field // issuedate
	ExpiryDate Field // expirydate

	Data Data
}

// CPFInvestmentScheme is the person's CPF Investment Scheme account.
type CPFInvestmentScheme struct {
	AgentBankCode          Field // account.agentbankcode
	InvestmentBankAcctNo   Field // account.invbankacctno
	SAQParticipationStatus Field // saqparticipationstatus (coded): Self-Awareness Questionnaire
	SDSNetShareholdingQty  Field // sdsnetshareholdingqty: Special Discounted Shares held

	Data Data
}

// CPFContribution is one month of CPF contribution history.
type CPFContribution struct {
	Month    Field // month: YYYY-MM the contribution is for
	Date     Field // date: when it was paid
	Amount   Field // amount
	Employer Field // employer
}

// CPFEmployer is one month of CPF employer history.
type CPFEmployer struct {
	Month    Field // month: YYYY-MM
	Employer Field // employer
}

// CPFHousingWithdrawal is the CPF used for one property.
type CPFHousingWithdrawal struct {
	Address                            Address // address
	PrincipalWithdrawalAmount          Field   // principalwithdrawalamt
	AccruedInterestAmount              Field   // accruedinterestamt
	MonthlyInstalmentAmount            Field   // monthlyinstalmentamt
	TotalAmountOfCPFAllowedForProperty Field   // totalamountofcpfallowedforproperty

	Data Data
}

// LTAVocationalLicences are the person's LTA vocational licences, one per
// type.
type LTAVocationalLicences struct {
	TDVL VocationalLicence // tdvl: taxi driver
	PDVL VocationalLicence // pdvl: private hire car driver
	BDVL VocationalLicence // bdvl: bus driver (private-hire, school and excursion buses)
	BAVL VocationalLicence // bavl: bus attendant
	ODVL VocationalLicence // odvl: omnibus driver (public buses, for a Public Transport Operator's drivers)

	Data Data
}

// VocationalLicence is one LTA vocational licence.
type VocationalLicence struct {
	LicenceName             Field // licencename
	VocationalLicenceNumber Field // vocationallicencenumber
	Status                  Field // status (coded)
	ExpiryDate              Field // expirydate
}

// AcademicQualifications are the person's Singapore-Cambridge examination
// results and uploaded certificates.
type AcademicQualifications struct {
	Transcripts  []Transcript  // transcripts
	Certificates []Certificate // certificates

	Data Data
}

// Transcript is one qualification's results, e.g. GCE O-Level.
type Transcript struct {
	Name             Field        // name of the qualification
	YearAttained     Field        // yearattained
	ExplanatoryNotes Field        // explanatorynotes: a URL
	Results          []ExamResult // results
}

// ExamResult is one subject's result.
type ExamResult struct {
	Subject    Field // subject
	Level      Field // level
	Grade      Field // grade
	SubSubject Field // subsubject, if any
	SubGrade   Field // subgrade, if any
}

// Certificate is an electronic certificate the person uploaded.
type Certificate struct {
	Name                     Field // name: file name
	Content                  Field // content: the file, Base64-encoded
	OpenCertificateIndicator Field // opencertificateindicator: whether it is an OpenCerts certificate
	OpenCertificateID        Field // opencertificate.id
	OpenCertificatePrimary   Field // opencertificate.primary
}

// ChildRecord is a child's record: a locally registered birth
// (childrenbirthrecords) or a sponsored child (sponsoredchildrenrecords).
// BirthCertNo, TOB and SGCitizenAtBirth are for birth records; NRIC,
// Nationality, BirthCountry and SCPRGrantDate for sponsored children.
type ChildRecord struct {
	Name                 Field // name
	AliasName            Field // aliasname
	HanyuPinyinName      Field // hanyupinyinname
	HanyuPinyinAliasName Field // hanyupinyinaliasname
	MarriedName          Field // marriedname
	Sex                  Field // sex (coded)
	Race                 Field // race (coded)
	SecondaryRace        Field // secondaryrace (coded)
	Dialect              Field // dialect (coded)
	DOB                  Field // dob
	LifeStatus           Field // lifestatus (coded)

	BirthCertNo      Field // birthcertno
	TOB              Field // tob: time of birth, for a child under 21
	SGCitizenAtBirth Field // sgcitizenatbirthind: Y or N

	NRIC          Field // nric
	Nationality   Field // nationality (coded)
	BirthCountry  Field // birthcountry (coded)
	SCPRGrantDate Field // scprgrantdate: citizenship or PR grant date

	VaccinationRequirements []VaccinationRequirement // vaccinationrequirements

	Data Data
}

// VaccinationRequirement is one of a child's vaccination requirements.
type VaccinationRequirement struct {
	Requirement Field // requirement (coded)
	Fulfilled   Field // fulfilled: read with Field.Bool
}

// CorppassProfile is a typed view of a Myinfo Business corppass_info block:
// the acting user's Corppass account.
type CorppassProfile struct {
	Email         Field // email: the Corppass account's registered email
	EmailVerified Field // email_verified: read with Field.Bool

	Data Data
}

// CorppassProfile returns the typed view of the corppass_info block. It is
// safe on a nil Response or a response without it: every item is then empty.
func (m *Response) CorppassProfile() CorppassProfile {
	var c Data
	if m != nil {
		c = m.Corppass
	}
	return CorppassProfile{Email: c.Field("email"), EmailVerified: c.Field("email_verified"), Data: c}
}

func chasFrom(d Data) CHAS {
	return CHAS{CardType: d.Field("cardtype"), Indicator: d.Field("indicator"), Name: d.Field("name"),
		IssueDate: d.Field("issuedate"), ExpiryDate: d.Field("expirydate"), Data: d}
}

func cpfInvestmentSchemeFrom(d Data) CPFInvestmentScheme {
	acct := d.Object("account")
	return CPFInvestmentScheme{
		AgentBankCode: acct.Field("agentbankcode"), InvestmentBankAcctNo: acct.Field("invbankacctno"),
		SAQParticipationStatus: d.Field("saqparticipationstatus"), SDSNetShareholdingQty: d.Field("sdsnetshareholdingqty"),
		Data: d,
	}
}

func cpfContributions(d Data) []CPFContribution {
	var out []CPFContribution
	for _, r := range records(d, "history") {
		out = append(out, CPFContribution{Month: r.Field("month"), Date: r.Field("date"), Amount: r.Field("amount"), Employer: r.Field("employer")})
	}
	return out
}

func cpfEmployers(d Data) []CPFEmployer {
	var out []CPFEmployer
	for _, r := range records(d, "history") {
		out = append(out, CPFEmployer{Month: r.Field("month"), Employer: r.Field("employer")})
	}
	return out
}

func cpfHousingWithdrawals(d Data) []CPFHousingWithdrawal {
	var out []CPFHousingWithdrawal
	for _, r := range records(d, "withdrawaldetails") {
		out = append(out, CPFHousingWithdrawal{
			Address:                            r.Address("address"),
			PrincipalWithdrawalAmount:          r.Field("principalwithdrawalamt"),
			AccruedInterestAmount:              r.Field("accruedinterestamt"),
			MonthlyInstalmentAmount:            r.Field("monthlyinstalmentamt"),
			TotalAmountOfCPFAllowedForProperty: r.Field("totalamountofcpfallowedforproperty"),
			Data:                               r,
		})
	}
	return out
}

func vocationalLicence(d Data) VocationalLicence {
	return VocationalLicence{LicenceName: d.Field("licencename"), VocationalLicenceNumber: d.Field("vocationallicencenumber"),
		Status: d.Field("status"), ExpiryDate: d.Field("expirydate")}
}

func ltaVocationalLicencesFrom(d Data) LTAVocationalLicences {
	return LTAVocationalLicences{
		TDVL: vocationalLicence(d.Object("tdvl")), PDVL: vocationalLicence(d.Object("pdvl")),
		BDVL: vocationalLicence(d.Object("bdvl")), BAVL: vocationalLicence(d.Object("bavl")),
		ODVL: vocationalLicence(d.Object("odvl")), Data: d,
	}
}

func academicQualificationsFrom(d Data) AcademicQualifications {
	out := AcademicQualifications{Data: d}
	for _, r := range records(d, "transcripts") {
		t := Transcript{Name: r.Field("name"), YearAttained: r.Field("yearattained"), ExplanatoryNotes: r.Field("explanatorynotes")}
		for _, res := range records(r, "results") {
			t.Results = append(t.Results, ExamResult{Subject: res.Field("subject"), Level: res.Field("level"), Grade: res.Field("grade"),
				SubSubject: res.Field("subsubject"), SubGrade: res.Field("subgrade")})
		}
		out.Transcripts = append(out.Transcripts, t)
	}
	for _, r := range records(d, "certificates") {
		oc := r.Object("opencertificate")
		out.Certificates = append(out.Certificates, Certificate{Name: r.Field("name"), Content: r.Field("content"),
			OpenCertificateIndicator: r.Field("opencertificateindicator"), OpenCertificateID: oc.Field("id"), OpenCertificatePrimary: oc.Field("primary")})
	}
	return out
}

func childRecords(p Data, key string) []ChildRecord {
	var out []ChildRecord
	for _, r := range records(p, key) {
		c := ChildRecord{
			Name: r.Field("name"), AliasName: r.Field("aliasname"), HanyuPinyinName: r.Field("hanyupinyinname"),
			HanyuPinyinAliasName: r.Field("hanyupinyinaliasname"), MarriedName: r.Field("marriedname"),
			Sex: r.Field("sex"), Race: r.Field("race"), SecondaryRace: r.Field("secondaryrace"), Dialect: r.Field("dialect"),
			DOB: r.Field("dob"), LifeStatus: r.Field("lifestatus"),
			BirthCertNo: r.Field("birthcertno"), TOB: r.Field("tob"), SGCitizenAtBirth: r.Field("sgcitizenatbirthind"),
			NRIC: r.Field("nric"), Nationality: r.Field("nationality"), BirthCountry: r.Field("birthcountry"), SCPRGrantDate: r.Field("scprgrantdate"),
			Data: r,
		}
		for _, v := range records(r, "vaccinationrequirements") {
			c.VaccinationRequirements = append(c.VaccinationRequirements, VaccinationRequirement{Requirement: v.Field("requirement"), Fulfilled: v.Field("fulfilled")})
		}
		out = append(out, c)
	}
	return out
}
