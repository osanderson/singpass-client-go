package myinfo

// NOA is a Notice of Assessment from IRAS: the latest one (noa-basic, noa) or
// one of the last two (noahistory-basic, noahistory). The basic items carry
// only YearOfAssessment and Amount; the detailed ones break the amount down.
// Read amounts with Field.Float (Singapore dollars).
type NOA struct {
	YearOfAssessment Field // yearofassessment: YYYY
	Amount           Field // amount: total assessable income
	Category         Field // category: ORIGINAL, AMENDED, ADDITIONAL or REPAYMENT (detailed)
	Employment       Field // employment: assessable income from employment (detailed)
	Trade            Field // trade (detailed)
	Rent             Field // rent (detailed)
	Interest         Field // interest (detailed)
	TaxClearance     Field // taxclearance: Y or N (detailed)

	// Data is the NOA object, for its provenance and any field not modelled.
	Data Data
}

func noaFrom(d Data) NOA {
	return NOA{
		YearOfAssessment: d.Field("yearofassessment"),
		Amount:           d.Field("amount"),
		Category:         d.Field("category"),
		Employment:       d.Field("employment"),
		Trade:            d.Field("trade"),
		Rent:             d.Field("rent"),
		Interest:         d.Field("interest"),
		TaxClearance:     d.Field("taxclearance"),
		Data:             d,
	}
}

func noaList(d Data) []NOA {
	var out []NOA
	for _, r := range d.List("noas") {
		if r.Present() {
			out = append(out, noaFrom(r))
		}
	}
	return out
}

// Vehicle is one vehicles record from LTA. Dates read with Field.Date,
// amounts (Singapore dollars) with Field.Float and counts and capacities with
// Field.Int. Data holds the rarer fields (emission rates, weights,
// attachments, VPC).
type Vehicle struct {
	VehicleNo                Field // vehicleno: registration number
	Type                     Field // type, e.g. MOTOR CAR
	Make                     Field // make
	Model                    Field // model
	Status                   Field // status (coded)
	YearOfManufacture        Field // yearofmanufacture
	FirstRegistrationDate    Field // firstregistrationdate
	OriginalRegistrationDate Field // originalregistrationdate
	EffectiveOwnership       Field // effectiveownership: date and time of ownership
	COECategory              Field // coecategory
	COEExpiryDate            Field // coeexpirydate
	RoadTaxExpiryDate        Field // roadtaxexpirydate
	QuotaPremium             Field // quotapremium
	OpenMarketValue          Field // openmarketvalue
	MinimumPARFBenefit       Field // minimumparfbenefit
	EngineCapacity           Field // enginecapacity: cc
	PowerRate                Field // powerrate: kW, for electric and hybrid vehicles
	Propellant               Field // propellant, e.g. Petrol
	PrimaryColour            Field // primarycolour
	SecondaryColour          Field // secondarycolour
	Scheme                   Field // scheme, e.g. REVISED OFF-PEAK CAR
	IULabelNo                Field // iulabelno: in-vehicle unit
	ChassisNo                Field // chassisno
	EngineNo                 Field // engineno
	MotorNo                  Field // motorno
	NoOfTransfers            Field // nooftransfers

	// Data is the vehicle record, for its provenance and the other fields.
	Data Data
}

func vehicleFrom(d Data) Vehicle {
	return Vehicle{
		VehicleNo:                d.Field("vehicleno"),
		Type:                     d.Field("type"),
		Make:                     d.Field("make"),
		Model:                    d.Field("model"),
		Status:                   d.Field("status"),
		YearOfManufacture:        d.Field("yearofmanufacture"),
		FirstRegistrationDate:    d.Field("firstregistrationdate"),
		OriginalRegistrationDate: d.Field("originalregistrationdate"),
		EffectiveOwnership:       d.Field("effectiveownership"),
		COECategory:              d.Field("coecategory"),
		COEExpiryDate:            d.Field("coeexpirydate"),
		RoadTaxExpiryDate:        d.Field("roadtaxexpirydate"),
		QuotaPremium:             d.Field("quotapremium"),
		OpenMarketValue:          d.Field("openmarketvalue"),
		MinimumPARFBenefit:       d.Field("minimumparfbenefit"),
		EngineCapacity:           d.Field("enginecapacity"),
		PowerRate:                d.Field("powerrate"),
		Propellant:               d.Field("propellant"),
		PrimaryColour:            d.Field("primarycolour"),
		SecondaryColour:          d.Field("secondarycolour"),
		Scheme:                   d.Field("scheme"),
		IULabelNo:                d.Field("iulabelno"),
		ChassisNo:                d.Field("chassisno"),
		EngineNo:                 d.Field("engineno"),
		MotorNo:                  d.Field("motorno"),
		NoOfTransfers:            d.Field("nooftransfers"),
		Data:                     d,
	}
}

// HDBOwnership is one hdbownership record: an HDB flat the person owns.
// Amounts (Singapore dollars) read with Field.Float, dates with Field.Date and
// counts and terms with Field.Int.
type HDBOwnership struct {
	Address                 Address // address
	HDBType                 Field   // hdbtype (coded), e.g. 4-ROOM FLAT (HDB)
	NoOfOwners              Field   // noofowners
	DateOfPurchase          Field   // dateofpurchase
	DateOfOwnershipTransfer Field   // dateofownershiptransfer
	LeaseCommencementDate   Field   // leasecommencementdate
	TermOfLease             Field   // termoflease: years
	PurchasePrice           Field   // purchaseprice
	LoanGranted             Field   // loangranted
	OriginalLoanRepayment   Field   // originalloanrepayment: years
	BalanceLoanRepayment    Term    // balanceloanrepayment
	MonthlyLoanInstalment   Field   // monthlyloaninstalment
	OutstandingInstalment   Field   // outstandinginstalment
	OutstandingLoanBalance  Field   // outstandingloanbalance

	// Data is the ownership record, for its provenance.
	Data Data
}

// Term is a length of time given in years and months, such as the
// remaining loan repayment period.
type Term struct {
	Years  Field // years
	Months Field // months
}

func hdbOwnershipFrom(d Data) HDBOwnership {
	bal := d.Object("balanceloanrepayment")
	return HDBOwnership{
		Address:                 d.Address("address"),
		HDBType:                 d.Field("hdbtype"),
		NoOfOwners:              d.Field("noofowners"),
		DateOfPurchase:          d.Field("dateofpurchase"),
		DateOfOwnershipTransfer: d.Field("dateofownershiptransfer"),
		LeaseCommencementDate:   d.Field("leasecommencementdate"),
		TermOfLease:             d.Field("termoflease"),
		PurchasePrice:           d.Field("purchaseprice"),
		LoanGranted:             d.Field("loangranted"),
		OriginalLoanRepayment:   d.Field("originalloanrepayment"),
		BalanceLoanRepayment:    Term{Years: bal.Field("years"), Months: bal.Field("months")},
		MonthlyLoanInstalment:   d.Field("monthlyloaninstalment"),
		OutstandingInstalment:   d.Field("outstandinginstalment"),
		OutstandingLoanBalance:  d.Field("outstandingloanbalance"),
		Data:                    d,
	}
}

// DrivingLicence is the person's driving licence record from the Traffic
// Police.
type DrivingLicence struct {
	QDL                Licence // qdl: qualified driving licence
	PDL                Licence // pdl: provisional driving licence
	TotalDemeritPoints Field   // totaldemeritpoints
	COMStatus          Field   // comstatus: Certificate of Merit (coded, Y or N)
	PhotoCardSerialNo  Field   // photocardserialno
	Suspension         Period  // suspension
	Disqualification   Period  // disqualification
	Revocation         Period  // revocation

	// Data is the drivinglicence object, for its provenance.
	Data Data
}

// Licence is a qualified or provisional driving licence.
type Licence struct {
	Validity   Field          // validity (coded): V valid, E expired, I invalid, N not held
	ExpiryDate Field          // expirydate
	Classes    []LicenceClass // classes
}

// LicenceClass is one class on a driving licence, e.g. 3 or 2B.
type LicenceClass struct {
	Class     Field // class
	IssueDate Field // issuedate
}

// Period is a start and end date, such as a licence suspension.
type Period struct {
	StartDate Field // startdate
	EndDate   Field // enddate
}

func licenceFrom(d Data) Licence {
	l := Licence{Validity: d.Field("validity"), ExpiryDate: d.Field("expirydate")}
	for _, c := range d.List("classes") {
		if c.Present() {
			l.Classes = append(l.Classes, LicenceClass{Class: c.Field("class"), IssueDate: c.Field("issuedate")})
		}
	}
	return l
}

func periodFrom(d Data) Period {
	return Period{StartDate: d.Field("startdate"), EndDate: d.Field("enddate")}
}

func drivingLicenceFrom(d Data) DrivingLicence {
	return DrivingLicence{
		QDL:                licenceFrom(d.Object("qdl")),
		PDL:                licenceFrom(d.Object("pdl")),
		TotalDemeritPoints: d.Field("totaldemeritpoints"),
		COMStatus:          d.Field("comstatus"),
		PhotoCardSerialNo:  d.Field("photocardserialno"),
		Suspension:         periodFrom(d.Object("suspension")),
		Disqualification:   periodFrom(d.Object("disqualification")),
		Revocation:         periodFrom(d.Object("revocation")),
		Data:               d,
	}
}
