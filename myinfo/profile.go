package myinfo

// PersonProfile is a typed view of the common person_info items, so they can
// be found by name instead of by key. Each item is a Field, keeping its value,
// code and provenance; an item the response didn't carry — its scope wasn't
// requested, or Myinfo has no record — is the zero Field (Available false).
// Anything not modelled here is still reachable through Data.
//
// Read coded items (Sex, Race, Nationality, …) with Field.Code for the code
// and Field.String for its description, dates (DOB, …) with Field.Date and
// amounts with Field.Float. Request the matching scopes with Scopes, e.g.
// Scopes("openid", ItemName, ItemVehicles).
type PersonProfile struct {
	UINFIN               Field // uinfin: NRIC or FIN
	Name                 Field // name
	AliasName            Field // aliasname
	HanyuPinyinName      Field // hanyupinyinname
	HanyuPinyinAliasName Field // hanyupinyinaliasname
	MarriedName          Field // marriedname
	Sex                  Field // sex (coded)
	Race                 Field // race (coded)
	SecondaryRace        Field // secondaryrace (coded)
	Dialect              Field // dialect (coded)
	Nationality          Field // nationality (coded)
	DOB                  Field // dob: date of birth
	BirthCountry         Field // birthcountry (coded)
	ResidentialStatus    Field // residentialstatus (coded)
	Marital              Field // marital: marital status (coded)

	Email    Field   // email
	MobileNo Phone   // mobileno
	RegAdd   Address // regadd: registered address

	HousingType Field // housingtype (coded)
	HDBType     Field // hdbtype (coded)

	PassportNumber     Field // passportnumber
	PassportExpiryDate Field // passportexpirydate
	PassType           Field // passtype (coded), for a foreigner
	PassStatus         Field // passstatus
	PassExpiryDate     Field // passexpirydate

	Occupation       Field // occupation (coded)
	EmploymentSector Field // employmentsector

	CPFBalances CPFBalances // cpfbalances

	// Income tax, vehicles, property and driving: each read from its own
	// dataset, empty when its scopes weren't requested.
	NOABasic        NOA            // noa-basic: latest NOA, amount only
	NOA             NOA            // noa: latest NOA, detailed
	NOAHistoryBasic []NOA          // noahistory-basic: last two NOAs, amounts only
	NOAHistory      []NOA          // noahistory: last two NOAs, detailed
	Vehicles        []Vehicle      // vehicles
	HDBOwnership    []HDBOwnership // hdbownership
	DrivingLicence  DrivingLicence // drivinglicence

	// Data is the whole person_info block.
	Data Data
}

// CPFBalances is the person's CPF account balances; read each with
// Field.Float.
type CPFBalances struct {
	OA Field // oa: Ordinary Account
	SA Field // sa: Special Account
	MA Field // ma: MediSave Account
	RA Field // ra: Retirement Account

	// Data is the cpfbalances object, for its provenance.
	Data Data
}

// PersonProfile returns the typed view of the person_info block — Singpass
// Myinfo's person, or the logged-in person on Myinfo Business. It is safe on a
// nil Response or a response without person data: every item is then empty.
func (m *Response) PersonProfile() PersonProfile {
	var p Data
	if m != nil {
		p = m.Person
	}
	cpf := p.Object("cpfbalances")
	return PersonProfile{
		UINFIN:               p.Field("uinfin"),
		Name:                 p.Field("name"),
		AliasName:            p.Field("aliasname"),
		HanyuPinyinName:      p.Field("hanyupinyinname"),
		HanyuPinyinAliasName: p.Field("hanyupinyinaliasname"),
		MarriedName:          p.Field("marriedname"),
		Sex:                  p.Field("sex"),
		Race:                 p.Field("race"),
		SecondaryRace:        p.Field("secondaryrace"),
		Dialect:              p.Field("dialect"),
		Nationality:          p.Field("nationality"),
		DOB:                  p.Field("dob"),
		BirthCountry:         p.Field("birthcountry"),
		ResidentialStatus:    p.Field("residentialstatus"),
		Marital:              p.Field("marital"),
		Email:                p.Field("email"),
		MobileNo:             p.Phone("mobileno"),
		RegAdd:               p.Address("regadd"),
		HousingType:          p.Field("housingtype"),
		HDBType:              p.Field("hdbtype"),
		PassportNumber:       p.Field("passportnumber"),
		PassportExpiryDate:   p.Field("passportexpirydate"),
		PassType:             p.Field("passtype"),
		PassStatus:           p.Field("passstatus"),
		PassExpiryDate:       p.Field("passexpirydate"),
		Occupation:           p.Field("occupation"),
		EmploymentSector:     p.Field("employmentsector"),
		CPFBalances: CPFBalances{
			OA: cpf.Field("oa"), SA: cpf.Field("sa"), MA: cpf.Field("ma"), RA: cpf.Field("ra"),
			Data: cpf,
		},
		NOABasic:        noaFrom(p.Object("noa-basic")),
		NOA:             noaFrom(p.Object("noa")),
		NOAHistoryBasic: noaList(p.Object("noahistory-basic")),
		NOAHistory:      noaList(p.Object("noahistory")),
		Vehicles:        vehicles(p),
		HDBOwnership:    hdbOwnerships(p),
		DrivingLicence:  drivingLicenceFrom(p.Object("drivinglicence")),
		Data:            p,
	}
}

func vehicles(p Data) []Vehicle {
	var out []Vehicle
	for _, r := range p.List("vehicles") {
		if r.Present() {
			out = append(out, vehicleFrom(r))
		}
	}
	return out
}

func hdbOwnerships(p Data) []HDBOwnership {
	var out []HDBOwnership
	for _, r := range p.List("hdbownership") {
		if r.Present() {
			out = append(out, hdbOwnershipFrom(r))
		}
	}
	return out
}

// EntityProfile is a typed view of a Myinfo Business entity_info block,
// modelled on Corppass's entity_info OpenAPI specification: the basic
// profile, address, people and share capital, financial results, licences,
// registrations, grants and history. Each dataset is empty when its scopes
// weren't requested (see Scopes and the Entity constants). Anything not
// modelled is reachable through BasicProfile and Data.
type EntityProfile struct {
	Name                   Field   // basic_profile.name
	RegistrationNumber     Field   // basic_profile.registration_number: the UEN
	Type                   Field   // basic_profile.type (coded), e.g. LC local company
	CompanyType            Field   // basic_profile.company_type (coded), for LC and FC
	Constitution           Field   // basic_profile.constitution (coded), for BN and PF
	UENStatus              Field   // basic_profile.uen_status (coded)
	CountryOfIncorporation Field   // basic_profile.country_of_incorporation (coded)
	RegistrationDate       Field   // basic_profile.registration_date
	ExpiryDate             Field   // basic_profile.expiry_date
	PrimaryActivity        Field   // basic_profile.primary_activity: SSIC code (Member("edition") is its edition)
	SecondaryActivity      Field   // basic_profile.secondary_activity: SSIC code
	Address                Address // address

	Appointments []Appointment // appointments
	Shareholders []Shareholder // shareholders
	Capitals     []Capital     // capitals

	Financials  []Financial              // financials
	Licences    []BusinessLicence        // licences
	Builders    []BuilderLicence         // builders
	Contractors []ContractorRegistration // contractors
	Grants      []Grant                  // grants
	History     RegistrationHistory      // history

	// BasicProfile is the basic_profile object, and Data the whole
	// entity_info block.
	BasicProfile Data
	Data         Data
}

// EntityProfile returns the typed view of the entity_info block. It is safe
// on a nil Response or a response without entity data: every item is then
// empty.
func (m *Response) EntityProfile() EntityProfile {
	var e Data
	if m != nil {
		e = m.Entity
	}
	bp := e.Object("basic_profile")
	return EntityProfile{
		Name:                   bp.Field("name"),
		RegistrationNumber:     bp.Field("registration_number"),
		Type:                   bp.Field("type"),
		CompanyType:            bp.Field("company_type"),
		Constitution:           bp.Field("constitution"),
		UENStatus:              bp.Field("uen_status"),
		CountryOfIncorporation: bp.Field("country_of_incorporation"),
		RegistrationDate:       bp.Field("registration_date"),
		ExpiryDate:             bp.Field("expiry_date"),
		PrimaryActivity:        bp.Field("primary_activity"),
		SecondaryActivity:      bp.Field("secondary_activity"),
		Address:                e.Address("address"),
		Appointments:           e.Appointments(),
		Shareholders:           e.Shareholders(),
		Capitals:               capitals(e),
		Financials:             financials(e),
		Licences:               businessLicences(e),
		Builders:               builderLicences(e),
		Contractors:            contractorRegistrations(e),
		Grants:                 grants(e),
		History:                entityHistory(e),
		BasicProfile:           bp,
		Data:                   e,
	}
}
