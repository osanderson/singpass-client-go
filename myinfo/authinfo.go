package myinfo

// Authorisation is one Corppass e-service authorisation row from an auth_info /
// tp_auth_info block, flattened from the bespoke
// Result_Set.ESrvc_Result[].Auth_Result_Set.Row[] nesting. Unlike Myinfo person /
// entity data it carries no envelope metadata (no source / classification /
// lastupdated) — it is a plain record of what the entity/user is authorised to do.
type Authorisation struct {
	ESrvcID   string // CPESrvcID — the e-service this authorisation is for
	Subject   string // CPEntID_SUB — the authorised entity/user sub (often empty)
	Role      string // CPRole — the granted role (often empty)
	StartDate string // StartDate — validity start (YYYY-MM-DD)
	EndDate   string // EndDate — validity end (YYYY-MM-DD; 9999-12-31 = open-ended)
	// Parameters holds the row's Parameter[] entries, left as raw Data: the element
	// shape is undocumented and empty in practice, so it is exposed for navigation
	// rather than modelled.
	Parameters []Data
}

// Authorisations flattens a Corppass auth_info / tp_auth_info block into a flat
// list — one Authorisation per Auth_Result_Set.Row, each tagged with its parent
// e-service's CPESrvcID. It returns nil for a block that is absent or not in this
// shape, so callers can fall back to Raw.
//
// This is the Corppass counterpart to the Myinfo envelope accessors: auth_info is
// not the Myinfo envelope but a bespoke nested structure of bare PascalCase
// scalars, so Field / Object / List navigate it fine — but the key names
// (Result_Set, ESrvc_Result, Auth_Result_Set, Row, CPESrvcID, CPRole, …) are
// tribal knowledge this method hides. Field synthesises a {value} envelope for the
// bare scalars, so Field(k).String() reads them directly.
func (d Data) Authorisations() []Authorisation {
	if !d.Present() {
		return nil
	}
	var out []Authorisation
	for _, esrvc := range d.Object("Result_Set").List("ESrvc_Result") {
		id := esrvc.Field("CPESrvcID").String()
		for _, row := range esrvc.Object("Auth_Result_Set").List("Row") {
			out = append(out, Authorisation{
				ESrvcID:    id,
				Subject:    row.Field("CPEntID_SUB").String(),
				Role:       row.Field("CPRole").String(),
				StartDate:  row.Field("StartDate").String(),
				EndDate:    row.Field("EndDate").String(),
				Parameters: row.List("Parameter"),
			})
		}
	}
	return out
}
