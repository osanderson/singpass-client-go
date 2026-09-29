// Code generated from the Corppass Myinfo Business scope pages and
// entity_info OpenAPI specification (docs.corppass.gov.sg, retrieved
// 2026-09-29). Update both sources together, keeping the corrections marked
// "Not on Corppass's scope pages" or "The scope pages list", which come from
// what Corppass staging accepts (checked 2026-09-29).

package myinfo

// Myinfo Business item keys: the data items a Myinfo Business client can
// request, as block-prefixed scope stems — entity.* for entity_info (the
// organisation), user.* for person_info (the acting person) and corppass.*
// for corppass_info. Scopes expands each into its scopes.
const (
	EntityAddress            = "entity.address"            // Registered address
	EntityAppointments       = "entity.appointments"       // Appointments (directors, secretaries, …)
	EntityBasicProfile       = "entity.basic_profile"      // Basic profile: name, UEN, type, status, activities
	EntityBuilders           = "entity.builders"           // Builders licences
	EntityCapitals           = "entity.capitals"           // Share capital
	EntityContractors        = "entity.contractors"        // Contractor registrations
	EntityFinancials         = "entity.financials"         // Financial statements
	EntityGrants             = "entity.grants"             // Government grants
	EntityHistory            = "entity.history"            // Previous names and registration numbers
	EntityIdentity           = "entity.identity"           // Entity identity: not on Corppass's scope pages, but Corppass accepts it
	EntityLicences           = "entity.licences"           // Licences
	EntityShareholders       = "entity.shareholders"       // Shareholders
	UserAliasName            = "user.aliasname"            // Alias Name
	UserCPFContributions     = "user.cpfcontributions"     // CPF Contribution History (up to 15 months)
	UserCPFEmployers         = "user.cpfemployers"         // CPF Employers
	UserCPFHousingWithdrawal = "user.cpfhousingwithdrawal" // CPF Housing Withdrawal
	UserDOB                  = "user.dob"                  // Date of Birth
	UserDrivingLicence       = "user.drivinglicence"       // Driving Licence
	UserEmployment           = "user.employment"           // Name of Employer
	UserEmploymentSector     = "user.employmentsector"     // Employment Sector
	UserHanyuPinyinAliasName = "user.hanyupinyinaliasname" // Hanyu Pinyin Alias Name
	UserHanyuPinyinName      = "user.hanyupinyinname"      // Hanyu Pinyin Name
	UserHDBOwnership         = "user.hdbownership"         // HDB Ownership
	UserHDBType              = "user.hdbtype"              // HDB Type
	UserHousingType          = "user.housingtype"          // Type of Housing
	UserMarital              = "user.marital"              // Marital Status
	UserMarriedName          = "user.marriedname"          // Married Name
	UserName                 = "user.name"                 // Principal Name
	UserNationality          = "user.nationality"          // Nationality/Citizenship
	UserNOA                  = "user.noa"                  // Notice of Assessment (Detailed, Latest Year)
	UserNOABasic             = "user.noa-basic"            // Notice of Assessment (Basic, Latest Year)
	UserNOAHistory           = "user.noahistory"           // Notice of Assessment (Detailed, Last 2 Years)
	UserNOAHistoryBasic      = "user.noahistory-basic"     // Notice of Assessment (Basic, Last 2 Years)
	UserOwnerPrivate         = "user.ownerprivate"         // Ownership of Private Residential Property
	UserPassportExpiryDate   = "user.passportexpirydate"   // Passport Expiry Date
	UserPassportNumber       = "user.passportnumber"       // Passport Number
	UserPassStatus           = "user.passstatus"           // Pass Status
	UserPassType             = "user.passtype"             // Pass Type
	UserRace                 = "user.race"                 // Race
	UserRegAdd               = "user.regadd"               // Registered Address
	UserResidentialStatus    = "user.residentialstatus"    // Residential Status
	UserSecondaryRace        = "user.secondaryrace"        // Secondary Race
	UserSex                  = "user.sex"                  // Sex
	UserUINFIN               = "user.uinfin"               // NRIC / FIN
	UserVehicles             = "user.vehicles"             // Vehicles
	CorppassEmail            = "corppass.email"            // Corppass Registered Email
)

// businessCatalogue lists each Myinfo Business item's scopes, in the
// Corppass documentation's order.
var businessCatalogue = map[string][]string{
	EntityAddress:      {"entity.address"},
	EntityAppointments: {"entity.appointments.appointment_date", "entity.appointments.position", "entity.appointments.category", "entity.appointments.designation", "entity.appointments.entity_appointment.name", "entity.appointments.entity_appointment.registration_number", "entity.appointments.entity_appointment.type", "entity.appointments.individual_appointment.id_number", "entity.appointments.individual_appointment.id_type", "entity.appointments.individual_appointment.name", "entity.appointments.individual_appointment.nationality"},
	EntityBasicProfile: {"entity.basic_profile.company_type", "entity.basic_profile.constitution", "entity.basic_profile.country_of_incorporation", "entity.basic_profile.expiry_date", "entity.basic_profile.name", "entity.basic_profile.primary_activity", "entity.basic_profile.registration_date", "entity.basic_profile.registration_number", "entity.basic_profile.secondary_activity", "entity.basic_profile.type", "entity.basic_profile.uen_status"},
	EntityBuilders:     {"entity.builders.licence", "entity.builders.licence_expiry_date"},
	EntityCapitals:     {"entity.capitals.currency", "entity.capitals.issued_amount", "entity.capitals.paid_up_amount", "entity.capitals.share_allotted_number", "entity.capitals.share_type"},
	EntityContractors:  {"entity.contractors.crs_expiry_date", "entity.contractors.workhead", "entity.contractors.workhead_financial_grade"},
	EntityFinancials:   {"entity.financials.is_audited", "entity.financials.company_financial.profit_loss_after_tax", "entity.financials.company_financial.profit_loss_before_tax", "entity.financials.company_financial.revenue", "entity.financials.currency", "entity.financials.current_period_end_date", "entity.financials.current_period_start_date", "entity.financials.group_financial.profit_loss_after_tax", "entity.financials.group_financial.profit_loss_before_tax", "entity.financials.group_financial.revenue", "entity.financials.group_financial.share_capital"},
	// The scope pages list entity.grants.last_update_date, but the field (in
	// the entity_info specification) and the scope Corppass accepts are
	// last_updated_date.
	EntityGrants:             {"entity.grants.development_category", "entity.grants.functional_area", "entity.grants.submitted_on_date", "entity.grants.approved_amount", "entity.grants.last_updated_date", "entity.grants.status", "entity.grants.type"},
	EntityHistory:            {"entity.history.previous_names.previous_name", "entity.history.previous_names.previous_name_effective_date", "entity.history.previous_registration_numbers.previous_registration_number"},
	EntityIdentity:           {"entity.identity"}, // Not on Corppass's scope pages
	EntityLicences:           {"entity.licences.issuance_agency", "entity.licences.expiry_date", "entity.licences.issue_date", "entity.licences.licence_name", "entity.licences.licence_number"},
	EntityShareholders:       {"entity.shareholders.entity_shareholder.name", "entity.shareholders.entity_shareholder.registration_number", "entity.shareholders.entity_shareholder.type", "entity.shareholders.individual_shareholder.id_number", "entity.shareholders.individual_shareholder.id_type", "entity.shareholders.individual_shareholder.name", "entity.shareholders.individual_shareholder.nationality", "entity.shareholders.allocation", "entity.shareholders.category", "entity.shareholders.currency", "entity.shareholders.share_type"},
	UserAliasName:            {"user.aliasname"},
	UserCPFContributions:     {"user.cpfcontributions"},
	UserCPFEmployers:         {"user.cpfemployers"},
	UserCPFHousingWithdrawal: {"user.cpfhousingwithdrawal"},
	UserDOB:                  {"user.dob"},
	UserDrivingLicence:       {"user.drivinglicence.pdl.validity", "user.drivinglicence.qdl.classes", "user.drivinglicence.qdl.validity"},
	UserEmployment:           {"user.employment"},
	UserEmploymentSector:     {"user.employmentsector"},
	UserHanyuPinyinAliasName: {"user.hanyupinyinaliasname"},
	UserHanyuPinyinName:      {"user.hanyupinyinname"},
	UserHDBOwnership:         {"user.hdbownership.address", "user.hdbownership.dateofpurchase", "user.hdbownership.hdbtype", "user.hdbownership.monthlyloaninstalment", "user.hdbownership.noofowners", "user.hdbownership.outstandingloanbalance"},
	UserHDBType:              {"user.hdbtype"},
	UserHousingType:          {"user.housingtype"},
	UserMarital:              {"user.marital"},
	UserMarriedName:          {"user.marriedname"},
	UserName:                 {"user.name"},
	UserNationality:          {"user.nationality"},
	UserNOA:                  {"user.noa"},
	UserNOABasic:             {"user.noa-basic"},
	UserNOAHistory:           {"user.noahistory"},
	UserNOAHistoryBasic:      {"user.noahistory-basic"},
	UserOwnerPrivate:         {"user.ownerprivate"},
	UserPassportExpiryDate:   {"user.passportexpirydate"},
	UserPassportNumber:       {"user.passportnumber"},
	UserPassStatus:           {"user.passstatus"},
	UserPassType:             {"user.passtype"},
	UserRace:                 {"user.race"},
	UserRegAdd:               {"user.regadd"},
	UserResidentialStatus:    {"user.residentialstatus"},
	UserSecondaryRace:        {"user.secondaryrace"},
	UserSex:                  {"user.sex"},
	UserUINFIN:               {"user.uinfin"},
	UserVehicles:             {"user.vehicles.make", "user.vehicles.model", "user.vehicles.vehicleno"},
	CorppassEmail:            {"corppass.email"},
}
