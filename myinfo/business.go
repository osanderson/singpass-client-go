package myinfo

// Myinfo Business entity datasets, modelled on Corppass's entity_info OpenAPI
// specification. Amounts read with Field.Float, dates with Field.Date and
// coded items with Field.Code / Field.String; each record keeps its Data for
// provenance and anything not modelled.

// Capital is one entity_info capitals record: a class of share capital.
type Capital struct {
	ShareType           Field // share_type (coded)
	ShareAllottedNumber Field // share_allotted_number: number of shares allotted
	IssuedAmount        Field // issued_amount
	PaidUpAmount        Field // paid_up_amount
	Currency            Field // currency (coded), e.g. SGD

	Data Data
}

// Financial is one entity_info financials record: the figures for a
// financial period, for the company and, where it has one, its group.
type Financial struct {
	CurrentPeriodStartDate Field            // current_period_start_date
	CurrentPeriodEndDate   Field            // current_period_end_date
	IsAudited              Field            // is_audited
	Currency               Field            // currency (coded)
	Company                FinancialFigures // company_financial
	Group                  FinancialFigures // group_financial

	Data Data
}

// FinancialFigures are a company's or group's results for a period.
type FinancialFigures struct {
	Revenue             Field // revenue
	ProfitLossBeforeTax Field // profit_loss_before_tax
	ProfitLossAfterTax  Field // profit_loss_after_tax
	ShareCapital        Field // share_capital (group only)
}

// BusinessLicence is one entity_info licences record: a licence issued to
// the entity by a government agency.
type BusinessLicence struct {
	LicenceNumber  Field // licence_number
	LicenceName    Field // licence_name
	IssuanceAgency Field // issuance_agency (coded)
	IssueDate      Field // issue_date
	ExpiryDate     Field // expiry_date

	Data Data
}

// RegistrationHistory is the entity_info history: the entity's previous names and
// registration numbers.
type RegistrationHistory struct {
	PreviousNames               []PreviousName // previous_names
	PreviousRegistrationNumbers []Field        // previous_registration_numbers[].previous_registration_number

	Data Data
}

// PreviousName is a name the entity was registered under before.
type PreviousName struct {
	Name          Field // previous_name
	EffectiveDate Field // previous_name_effective_date
}

// BuilderLicence is one entity_info builders record (BCA builder licence).
type BuilderLicence struct {
	Licence           Field // licence (coded)
	LicenceExpiryDate Field // licence_expiry_date

	Data Data
}

// ContractorRegistration is one entity_info contractors record (BCA
// Contractors Registry workhead).
type ContractorRegistration struct {
	Workhead               Field // workhead (coded)
	CRSExpiryDate          Field // crs_expiry_date
	WorkheadFinancialGrade Field // workhead_financial_grade

	Data Data
}

// Grant is one entity_info grants record: a government grant application.
type Grant struct {
	Type                Field // type (coded)
	Status              Field // status (coded)
	FunctionalArea      Field // functional_area (coded)
	DevelopmentCategory Field // development_category (coded)
	ApprovedAmount      Field // approved_amount: SGD
	SubmittedOnDate     Field // submitted_on_date
	LastUpdatedDate     Field // last_updated_date

	Data Data
}

// records returns the present objects in the list at key.
func records(d Data, key string) []Data {
	var out []Data
	for _, r := range d.List(key) {
		if r.Present() {
			out = append(out, r)
		}
	}
	return out
}

func capitals(e Data) []Capital {
	var out []Capital
	for _, r := range records(e, "capitals") {
		out = append(out, Capital{
			ShareType: r.Field("share_type"), ShareAllottedNumber: r.Field("share_allotted_number"),
			IssuedAmount: r.Field("issued_amount"), PaidUpAmount: r.Field("paid_up_amount"),
			Currency: r.Field("currency"), Data: r,
		})
	}
	return out
}

func figures(d Data) FinancialFigures {
	return FinancialFigures{
		Revenue:             d.Field("revenue"),
		ProfitLossBeforeTax: d.Field("profit_loss_before_tax"),
		ProfitLossAfterTax:  d.Field("profit_loss_after_tax"),
		ShareCapital:        d.Field("share_capital"),
	}
}

func financials(e Data) []Financial {
	var out []Financial
	for _, r := range records(e, "financials") {
		out = append(out, Financial{
			CurrentPeriodStartDate: r.Field("current_period_start_date"),
			CurrentPeriodEndDate:   r.Field("current_period_end_date"),
			IsAudited:              r.Field("is_audited"),
			Currency:               r.Field("currency"),
			Company:                figures(r.Object("company_financial")),
			Group:                  figures(r.Object("group_financial")),
			Data:                   r,
		})
	}
	return out
}

func businessLicences(e Data) []BusinessLicence {
	var out []BusinessLicence
	for _, r := range records(e, "licences") {
		out = append(out, BusinessLicence{
			LicenceNumber: r.Field("licence_number"), LicenceName: r.Field("licence_name"),
			IssuanceAgency: r.Field("issuance_agency"), IssueDate: r.Field("issue_date"),
			ExpiryDate: r.Field("expiry_date"), Data: r,
		})
	}
	return out
}

func entityHistory(e Data) RegistrationHistory {
	h := e.Object("history")
	out := RegistrationHistory{Data: h}
	for _, r := range records(h, "previous_names") {
		out.PreviousNames = append(out.PreviousNames, PreviousName{Name: r.Field("previous_name"), EffectiveDate: r.Field("previous_name_effective_date")})
	}
	for _, r := range records(h, "previous_registration_numbers") {
		out.PreviousRegistrationNumbers = append(out.PreviousRegistrationNumbers, r.Field("previous_registration_number"))
	}
	return out
}

func builderLicences(e Data) []BuilderLicence {
	var out []BuilderLicence
	for _, r := range records(e, "builders") {
		out = append(out, BuilderLicence{Licence: r.Field("licence"), LicenceExpiryDate: r.Field("licence_expiry_date"), Data: r})
	}
	return out
}

func contractorRegistrations(e Data) []ContractorRegistration {
	var out []ContractorRegistration
	for _, r := range records(e, "contractors") {
		out = append(out, ContractorRegistration{
			Workhead: r.Field("workhead"), CRSExpiryDate: r.Field("crs_expiry_date"),
			WorkheadFinancialGrade: r.Field("workhead_financial_grade"), Data: r,
		})
	}
	return out
}

func grants(e Data) []Grant {
	var out []Grant
	for _, r := range records(e, "grants") {
		out = append(out, Grant{
			Type: r.Field("type"), Status: r.Field("status"), FunctionalArea: r.Field("functional_area"),
			DevelopmentCategory: r.Field("development_category"), ApprovedAmount: r.Field("approved_amount"),
			SubmittedOnDate: r.Field("submitted_on_date"), LastUpdatedDate: r.Field("last_updated_date"), Data: r,
		})
	}
	return out
}
