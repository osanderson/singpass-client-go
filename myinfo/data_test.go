package myinfo

import "testing"

// TestDataEnvelopeMetadata covers the object-level envelope accessors — the
// container / record source, classification and lastupdated that a grouped dataset
// declares on its container object (not on the value leaves inside), and that a
// repeated record carries as a sibling of its leaves. It also checks that the zero
// Data (an absent block) returns empty metadata rather than panicking.
func TestDataEnvelopeMetadata(t *testing.T) {
	m := Parse(map[string]any{
		"person_info": map[string]any{
			// noa-basic style: metadata on the container, {value}-only leaves inside.
			"noa-basic": map[string]any{
				"source":           "1",
				"classification":   "C",
				"lastupdated":      "2026-09-23",
				"amount":           map[string]any{"value": float64(100000)},
				"yearofassessment": map[string]any{"value": "2024"},
			},
		},
	})
	noa := m.Person.Object("noa-basic")
	if got := noa.Source(); got != "1" {
		t.Errorf("Source() = %q, want %q", got, "1")
	}
	if got := noa.SourceCode(); got != SourceGovernmentVerified {
		t.Errorf("SourceCode() = %v, want SourceGovernmentVerified", got)
	}
	if got := noa.Classification(); got != "C" {
		t.Errorf("Classification() = %q, want %q", got, "C")
	}
	if !noa.ClassificationCode().Confidential() {
		t.Errorf("ClassificationCode().Confidential() = false, want true")
	}
	if got := noa.LastUpdated(); got != "2026-09-23" {
		t.Errorf("LastUpdated() = %q, want %q", got, "2026-09-23")
	}

	// The zero Data (absent block) yields empty metadata, never a panic.
	absent := m.Entity
	if absent.Present() {
		t.Fatalf("entity_info should be absent in this fixture")
	}
	if absent.Source() != "" || absent.SourceCode() != SourceUnknown || absent.LastUpdated() != "" {
		t.Errorf("absent Data should have empty metadata, got source=%q code=%v lastupdated=%q",
			absent.Source(), absent.SourceCode(), absent.LastUpdated())
	}
	if absent.ClassificationCode().Confidential() {
		t.Errorf("absent Data should not be confidential")
	}
}

// TestDataKind covers the envelope-shape discriminator used to dispatch a generic
// walk: object containers, repeated-record arrays, value/coded/unavailable leaves,
// bare-scalar envelope metadata, and absent keys.
func TestDataKind(t *testing.T) {
	m := Parse(map[string]any{
		"entity_info": map[string]any{
			"basic_profile": map[string]any{ // container object
				"entity-name":   map[string]any{"value": "ACME PTE LTD"},      // leaf (value)
				"entity-status": map[string]any{"code": "LC", "desc": "Live"}, // leaf (code)
				"former-name":   map[string]any{"unavailable": true},          // leaf (unavailable)
				"source":        "3",                                          // bare scalar (meta)
			},
			"appointments": []any{ // repeated-record array
				map[string]any{"position": map[string]any{"value": "DIRECTOR"}},
			},
		},
	})
	e := m.Entity
	if got := e.Kind("basic_profile"); got != KindObject {
		t.Errorf("basic_profile Kind = %v, want KindObject", got)
	}
	if got := e.Kind("appointments"); got != KindList {
		t.Errorf("appointments Kind = %v, want KindList", got)
	}
	if got := e.Kind("nonexistent"); got != KindAbsent {
		t.Errorf("nonexistent Kind = %v, want KindAbsent", got)
	}

	bp := e.Object("basic_profile")
	for _, tc := range []struct {
		key  string
		want Kind
	}{
		{"entity-name", KindLeaf},
		{"entity-status", KindLeaf},
		{"former-name", KindLeaf},
		{"source", KindScalar},
	} {
		if got := bp.Kind(tc.key); got != tc.want {
			t.Errorf("%s Kind = %v, want %v", tc.key, got, tc.want)
		}
	}
}
