package myinfo

import "strings"

// Label returns a human-readable label for a Myinfo or Myinfo Business data
// key: a curated label for the keys whose meaning isn't obvious from the key
// itself ("hdbownership" → "HDB ownership", "noa-basic" → "NOA basic (Notice
// of Assessment)", "oa" → "OA (Ordinary)"), otherwise the key with
// underscores and hyphens as spaces and a capital first letter
// ("entity_reg_number" → "Entity reg number"). It is for display; match on
// keys, not labels.
func Label(key string) string {
	if l, ok := labels[key]; ok {
		return l
	}
	s := strings.NewReplacer("_", " ", "-", " ").Replace(key)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// labels are the curated Label overrides: single-token keys Label can't split
// into words, acronyms, and codes that need expanding.
var labels = map[string]string{
	// Common person keys and acronyms.
	"uinfin":               "UINFIN",
	"dob":                  "Date of birth",
	"regadd":               "Registered address",
	"mobileno":             "Mobile number",
	"uen_status":           "UEN status",
	"id_number":            "ID number",
	"id_type":              "ID type",
	"birthcountry":         "Birth country",
	"residentialstatus":    "Residential status",
	"housingtype":          "Housing type",
	"aliasname":            "Alias name",
	"marriedname":          "Married name",
	"hanyupinyinname":      "Hanyu Pinyin name",
	"hanyupinyinaliasname": "Hanyu Pinyin alias name",
	"ownerprivate":         "Owns private property",
	"secondaryrace":        "Secondary race",
	"marital":              "Marital status",
	"countryofmarriage":    "Country of marriage",
	"marriagecertno":       "Marriage cert no.",
	"marriagedate":         "Marriage date",
	"divorcedate":          "Divorce date",
	"employmentsector":     "Employment sector",
	"passtype":             "Pass type",
	"passstatus":           "Pass status",
	"passexpirydate":       "Pass expiry date",
	"passportnumber":       "Passport number",
	"passportexpirydate":   "Passport expiry date",
	// Nested / grouped blocks (containers the recursive flatten descends into).
	"cpfbalances":              "CPF balances",
	"cpfcontributions":         "CPF contributions",
	"cpfemployers":             "CPF employers",
	"cpfinvestmentscheme":      "CPF Investment Scheme",
	"cpfhousingwithdrawal":     "CPF housing withdrawal",
	"drivinglicence":           "Driving licence",
	"ltavocationallicences":    "LTA vocational licences",
	"hdbownership":             "HDB ownership",
	"hdbtype":                  "HDB type",
	"academicqualifications":   "Academic qualifications",
	"childrenbirthrecords":     "Children birth records",
	"sponsoredchildrenrecords": "Sponsored children records",
	"noa":                      "NOA (Notice of Assessment)",
	"noa-basic":                "NOA basic (Notice of Assessment)",
	"noahistory":               "NOA history",
	"noahistory-basic":         "NOA history basic",
	"noas":                     "NOAs",
	"yearofassessment":         "Year of assessment",
	"taxclearance":             "Tax clearance",
	"merdekagen":               "Merdeka Generation",
	"pioneergen":               "Pioneer Generation",
	// Driving licence / demerit points.
	"totaldemeritpoints": "Total demerit points",
	"suspension":         "Suspension",
	"disqualification":   "Disqualification",
	"startdate":          "Start date",
	"enddate":            "End date",
	// CPF Investment Scheme.
	"agentbankcode":          "Agent bank code",
	"invbankacctno":          "Investment bank account no.",
	"saqparticipationstatus": "SAQ participation status",
	"sdsnetshareholdingqty":  "SDS net shareholding qty",
	// Short CPF account keys.
	"oa": "OA (Ordinary)",
	"sa": "SA (Special)",
	"ma": "MA (MediSave)",
	"ra": "RA (Retirement)",
}
