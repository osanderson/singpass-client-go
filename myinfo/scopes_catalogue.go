// Code generated from the Singpass Myinfo data catalogue and person-data
// OpenAPI specification (docs.developer.singpass.gov.sg, retrieved
// 2026-09-29). Update both sources together.

package myinfo

// Item keys: the 53 person_info data items Myinfo defines, as keys into
// Response.Person and arguments to Scopes. Each item's scopes are listed by
// Scopes.
const (
	ItemAcademicQualifications   = "academicqualifications"   // Singapore-Cambridge Examination
	ItemAliasName                = "aliasname"                // Alias Name
	ItemBirthCountry             = "birthcountry"             // Country / Place of Birth
	ItemCHAS                     = "chas"                     // Community Health Assist Scheme
	ItemChildrenBirthRecords     = "childrenbirthrecords"     // Children Birth Records
	ItemCountryOfMarriage        = "countryofmarriage"        // Country/Place of Marriage
	ItemCPFBalances              = "cpfbalances"              // CPF Balances
	ItemCPFContributions         = "cpfcontributions"         // CPF Contribution History (up to 15 months)
	ItemCPFEmployers             = "cpfemployers"             // CPF Employers
	ItemCPFHousingWithdrawal     = "cpfhousingwithdrawal"     // CPF Housing Withdrawal
	ItemCPFInvestmentScheme      = "cpfinvestmentscheme"      // CPF Investment Scheme
	ItemDialect                  = "dialect"                  // Dialect
	ItemDivorceDate              = "divorcedate"              // Divorce Date
	ItemDOB                      = "dob"                      // Date of Birth
	ItemDrivingLicence           = "drivinglicence"           // Driving Licence
	ItemEmail                    = "email"                    // Email Address
	ItemEmployment               = "employment"               // Name of Employer
	ItemEmploymentSector         = "employmentsector"         // Employment Sector
	ItemHanyuPinyinAliasName     = "hanyupinyinaliasname"     // Hanyu Pinyin Alias Name
	ItemHanyuPinyinName          = "hanyupinyinname"          // Hanyu Pinyin Name
	ItemHDBOwnership             = "hdbownership"             // HDB Ownership
	ItemHDBType                  = "hdbtype"                  // Type of HDB
	ItemHousingType              = "housingtype"              // Type of Housing
	ItemLTAVocationalLicences    = "ltavocationallicences"    // LTA Vocational Licences
	ItemMarital                  = "marital"                  // Marital Status
	ItemMarriageCertNo           = "marriagecertno"           // Marriage Certificate Number
	ItemMarriageDate             = "marriagedate"             // Marriage Date
	ItemMarriedName              = "marriedname"              // Married Name
	ItemMerdekaGen               = "merdekagen"               // Merdeka Generation Eligibility
	ItemMobileNo                 = "mobileno"                 // Mobile Number
	ItemName                     = "name"                     // Principal Name
	ItemNationality              = "nationality"              // Nationality / Citizenship
	ItemNOA                      = "noa"                      // Notice of Assessment (Detailed, Latest Year)
	ItemNOABasic                 = "noa-basic"                // Notice of Assessment (Basic, Latest Year)
	ItemNOAHistory               = "noahistory"               // Notice of Assessment (Detailed, Last 2 Years)
	ItemNOAHistoryBasic          = "noahistory-basic"         // Notice of Assessment (Basic, Last 2 Years)
	ItemOccupation               = "occupation"               // Occupation
	ItemOwnerPrivate             = "ownerprivate"             // Ownership of Private Residential Property
	ItemPartialUINFIN            = "partialuinfin"            // Partial NRIC / FIN
	ItemPassExpiryDate           = "passexpirydate"           // Pass Expiry Date
	ItemPassportExpiryDate       = "passportexpirydate"       // Passport Expiry Date
	ItemPassportNumber           = "passportnumber"           // Passport Number
	ItemPassStatus               = "passstatus"               // Pass Status
	ItemPassType                 = "passtype"                 // Pass Type
	ItemPioneerGen               = "pioneergen"               // Pioneer Generation Eligibility
	ItemRace                     = "race"                     // Race
	ItemRegAdd                   = "regadd"                   // Registered Address
	ItemResidentialStatus        = "residentialstatus"        // Residential Status
	ItemSecondaryRace            = "secondaryrace"            // Secondary Race
	ItemSex                      = "sex"                      // Sex
	ItemSponsoredChildrenRecords = "sponsoredchildrenrecords" // Sponsored Children Records
	ItemUINFIN                   = "uinfin"                   // NRIC / FIN
	ItemVehicles                 = "vehicles"                 // Vehicles
)

// catalogue lists each item's scopes, in the data catalogue's order. Most
// items are a single scope named like the item; a dataset such as vehicles
// or drivinglicence has one scope per field.
var catalogue = map[string][]string{
	ItemAcademicQualifications:   {"academicqualifications.transcripts", "academicqualifications.certificates"},
	ItemAliasName:                {"aliasname"},
	ItemBirthCountry:             {"birthcountry"},
	ItemCHAS:                     {"chas"},
	ItemChildrenBirthRecords:     {"childrenbirthrecords.birthcertno", "childrenbirthrecords.name", "childrenbirthrecords.aliasname", "childrenbirthrecords.hanyupinyinname", "childrenbirthrecords.hanyupinyinaliasname", "childrenbirthrecords.marriedname", "childrenbirthrecords.sex", "childrenbirthrecords.race", "childrenbirthrecords.secondaryrace", "childrenbirthrecords.dob", "childrenbirthrecords.tob", "childrenbirthrecords.dialect", "childrenbirthrecords.lifestatus", "childrenbirthrecords.vaccinationrequirements", "childrenbirthrecords.sgcitizenatbirthind"},
	ItemCountryOfMarriage:        {"countryofmarriage"},
	ItemCPFBalances:              {"cpfbalances.oa", "cpfbalances.ma", "cpfbalances.ra", "cpfbalances.sa"},
	ItemCPFContributions:         {"cpfcontributions"},
	ItemCPFEmployers:             {"cpfemployers"},
	ItemCPFHousingWithdrawal:     {"cpfhousingwithdrawal"},
	ItemCPFInvestmentScheme:      {"cpfinvestmentscheme.account", "cpfinvestmentscheme.sdsnetshareholdingqty", "cpfinvestmentscheme.saqparticipationstatus"},
	ItemDialect:                  {"dialect"},
	ItemDivorceDate:              {"divorcedate"},
	ItemDOB:                      {"dob"},
	ItemDrivingLicence:           {"drivinglicence.comstatus", "drivinglicence.totaldemeritpoints", "drivinglicence.suspension.startdate", "drivinglicence.suspension.enddate", "drivinglicence.disqualification.startdate", "drivinglicence.disqualification.enddate", "drivinglicence.revocation.startdate", "drivinglicence.revocation.enddate", "drivinglicence.pdl.validity", "drivinglicence.pdl.expirydate", "drivinglicence.pdl.classes", "drivinglicence.qdl.validity", "drivinglicence.qdl.expirydate", "drivinglicence.qdl.classes", "drivinglicence.photocardserialno"},
	ItemEmail:                    {"email"},
	ItemEmployment:               {"employment"},
	ItemEmploymentSector:         {"employmentsector"},
	ItemHanyuPinyinAliasName:     {"hanyupinyinaliasname"},
	ItemHanyuPinyinName:          {"hanyupinyinname"},
	ItemHDBOwnership:             {"hdbownership.noofowners", "hdbownership.address", "hdbownership.hdbtype", "hdbownership.leasecommencementdate", "hdbownership.termoflease", "hdbownership.dateofpurchase", "hdbownership.dateofownershiptransfer", "hdbownership.loangranted", "hdbownership.originalloanrepayment", "hdbownership.balanceloanrepayment", "hdbownership.outstandingloanbalance", "hdbownership.monthlyloaninstalment", "hdbownership.purchaseprice", "hdbownership.outstandinginstalment"},
	ItemHDBType:                  {"hdbtype"},
	ItemHousingType:              {"housingtype"},
	ItemLTAVocationalLicences:    {"ltavocationallicences.tdvl.licencename", "ltavocationallicences.tdvl.vocationallicencenumber", "ltavocationallicences.tdvl.expirydate", "ltavocationallicences.tdvl.status", "ltavocationallicences.pdvl.licencename", "ltavocationallicences.pdvl.vocationallicencenumber", "ltavocationallicences.pdvl.expirydate", "ltavocationallicences.pdvl.status", "ltavocationallicences.bavl.licencename", "ltavocationallicences.bavl.vocationallicencenumber", "ltavocationallicences.bavl.expirydate", "ltavocationallicences.bavl.status", "ltavocationallicences.bdvl.licencename", "ltavocationallicences.bdvl.vocationallicencenumber", "ltavocationallicences.bdvl.expirydate", "ltavocationallicences.bdvl.status", "ltavocationallicences.odvl.licencename", "ltavocationallicences.odvl.vocationallicencenumber", "ltavocationallicences.odvl.expirydate", "ltavocationallicences.odvl.status"},
	ItemMarital:                  {"marital"},
	ItemMarriageCertNo:           {"marriagecertno"},
	ItemMarriageDate:             {"marriagedate"},
	ItemMarriedName:              {"marriedname"},
	ItemMerdekaGen:               {"merdekagen.eligibility"},
	ItemMobileNo:                 {"mobileno"},
	ItemName:                     {"name"},
	ItemNationality:              {"nationality"},
	ItemNOA:                      {"noa"},
	ItemNOABasic:                 {"noa-basic"},
	ItemNOAHistory:               {"noahistory"},
	ItemNOAHistoryBasic:          {"noahistory-basic"},
	ItemOccupation:               {"occupation"},
	ItemOwnerPrivate:             {"ownerprivate"},
	ItemPartialUINFIN:            {"partialuinfin"},
	ItemPassExpiryDate:           {"passexpirydate"},
	ItemPassportExpiryDate:       {"passportexpirydate"},
	ItemPassportNumber:           {"passportnumber"},
	ItemPassStatus:               {"passstatus"},
	ItemPassType:                 {"passtype"},
	ItemPioneerGen:               {"pioneergen.eligibility"},
	ItemRace:                     {"race"},
	ItemRegAdd:                   {"regadd"},
	ItemResidentialStatus:        {"residentialstatus"},
	ItemSecondaryRace:            {"secondaryrace"},
	ItemSex:                      {"sex"},
	ItemSponsoredChildrenRecords: {"sponsoredchildrenrecords.nric", "sponsoredchildrenrecords.name", "sponsoredchildrenrecords.aliasname", "sponsoredchildrenrecords.hanyupinyinname", "sponsoredchildrenrecords.hanyupinyinaliasname", "sponsoredchildrenrecords.marriedname", "sponsoredchildrenrecords.sex", "sponsoredchildrenrecords.race", "sponsoredchildrenrecords.secondaryrace", "sponsoredchildrenrecords.dialect", "sponsoredchildrenrecords.dob", "sponsoredchildrenrecords.birthcountry", "sponsoredchildrenrecords.lifestatus", "sponsoredchildrenrecords.residentialstatus", "sponsoredchildrenrecords.nationality", "sponsoredchildrenrecords.scprgrantdate", "sponsoredchildrenrecords.vaccinationrequirements"},
	ItemUINFIN:                   {"uinfin"},
	ItemVehicles:                 {"vehicles.vehicleno", "vehicles.type", "vehicles.iulabelno", "vehicles.make", "vehicles.model", "vehicles.chassisno", "vehicles.engineno", "vehicles.motorno", "vehicles.yearofmanufacture", "vehicles.firstregistrationdate", "vehicles.originalregistrationdate", "vehicles.coecategory", "vehicles.coeexpirydate", "vehicles.roadtaxexpirydate", "vehicles.quotapremium", "vehicles.openmarketvalue", "vehicles.co2emission", "vehicles.status", "vehicles.primarycolour", "vehicles.secondarycolour", "vehicles.attachment1", "vehicles.attachment2", "vehicles.attachment3", "vehicles.scheme", "vehicles.thcemission", "vehicles.coemission", "vehicles.noxemission", "vehicles.pmemission", "vehicles.enginecapacity", "vehicles.powerrate", "vehicles.effectiveownership", "vehicles.propellant", "vehicles.maximumunladenweight", "vehicles.maximumladenweight", "vehicles.minimumparfbenefit", "vehicles.nooftransfers", "vehicles.vpc"},
}
