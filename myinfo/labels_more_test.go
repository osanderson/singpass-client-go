package myinfo

import "testing"

func TestCodeLabelsAndRaw(t *testing.T) {
	var nilResp *Response
	nilJSON, err := nilResp.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	r := Parse(map[string]any{"person_info": map[string]any{"name": map[string]any{"value": "TAN"}}})
	checkAll(t,
		check{"government-verified", SourceGovernmentVerified.String(), "government-verified"},
		check{"user-provided", SourceUserProvided.String(), "user-provided"},
		check{"not-applicable", SourceNotApplicable.String(), "not-applicable"},
		check{"user-provided (verified)", SourceUserProvidedVerified.String(), "user-provided (verified)"},
		check{"unknown source", SourceUnknown.String(), "unknown"},
		check{"confidential", ClassificationConfidential.String(), "confidential"},
		check{"unknown classification", ClassificationUnknown.String(), "unknown"},
		check{"nil Response JSON", string(nilJSON), "null"},
		check{"Data.Raw", r.Person.Raw()["name"] != nil, true},
		check{"Field.Raw", r.Person.Field("name").Raw()["value"], "TAN"},
	)
}
