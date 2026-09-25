// Package myinfo is the envelope-aware data model for a Myinfo / Myinfo Business
// /userinfo response: Response groups the data blocks, Data and Field read each
// item's Myinfo envelope (value or code+desc, source, classification,
// lastupdated, unavailable), and Authorisation flattens Corppass auth_info.
//
// It depends only on the standard library. The singpass package fills
// Identity.Myinfo from FAPIgo's validated /userinfo result; Parse builds the
// same view from any already-decoded claim map (tests, stored responses).
package myinfo

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// userInfoBlocks are the top-level claims the Myinfo family returns person and
// organisation data under, each a nested JSON object. Singpass's personal Myinfo
// returns only "person_info"; Corppass's Myinfo Business can return several —
// entity, person, Corppass account, and the two auth-info blocks — selected by
// the requested scopes.
var userInfoBlocks = []string{
	"entity_info",   // Myinfo Business entity (organisation) data
	"person_info",   // Myinfo / Myinfo Business person data
	"corppass_info", // Myinfo Business Corppass account data
	"auth_info",     // Corppass authorisation the user holds
	"tp_auth_info",  // third-party authorisation info
}

// Response is the parsed, envelope-aware view of a Myinfo / Myinfo Business
// /userinfo response. Every value it exposes has already been decrypted,
// inner-JWS-verified and sub-matched by FAPIgo before it reaches here.
//
// Myinfo returns data grouped into the blocks the response actually carried
// (see userInfoBlocks); a block absent from the response is the zero Data, for
// which Present reports false and every accessor is safe to call. Personal
// Myinfo populates only Person; Myinfo Business can populate Entity / Corppass /
// Auth / TPAuth as well, selected by the client's whitelisted scopes.
//
// Each data item inside a block is a Field carrying the Myinfo "envelope"
// (value or code+desc, plus source / classification / lastupdated, or an
// unavailable flag); addresses and phone numbers are nested objects reached via
// Data.Object, and repeated records via Data.List. Anything the typed accessors
// don't model is still reachable through Raw.
type Response struct {
	Person   Data // person_info      — the logged-in person's data
	Entity   Data // entity_info      — Myinfo Business organisation data
	Corppass Data // corppass_info    — Myinfo Business Corppass account data
	Auth     Data // auth_info        — authorisations the user holds
	TPAuth   Data // tp_auth_info     — third-party authorisation info
	raw      map[string]any
}

// Raw returns the full decoded /userinfo response as a map — every claim the
// response carried (the data blocks plus iss / aud / sub / iat), with any
// double-encoded (stringified) JSON already unwrapped one level so nested data
// reads as real JSON. It is the escape hatch for anything the typed accessors
// don't cover.
func (m *Response) Raw() map[string]any {
	if m == nil {
		return nil
	}
	return m.raw
}

// Blocks lists the recognised data blocks present in this response, in a stable
// order (a subset of userInfoBlocks).
func (m *Response) Blocks() []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, name := range userInfoBlocks {
		if v, ok := m.raw[name]; ok {
			if _, isMap := v.(map[string]any); isMap {
				out = append(out, name)
			}
		}
	}
	return out
}

// Data is one Myinfo object — a top-level block (person_info, entity_info, …) or
// a nested object within one (regadd, mobileno, a Corppass basic-profile). The
// zero Data is a valid, empty object: Present reports false and every accessor
// returns a zero value rather than panicking.
type Data struct {
	m map[string]any
}

// Present reports whether this Data refers to an object that was in the response
// (as opposed to an absent block or nested object).
func (d Data) Present() bool { return d.m != nil }

// Has reports whether key is present in this object.
func (d Data) Has(key string) bool {
	_, ok := d.m[key]
	return ok
}

// Keys returns this object's keys, sorted.
func (d Data) Keys() []string {
	if d.m == nil {
		return nil
	}
	out := make([]string, 0, len(d.m))
	for k := range d.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Field returns the leaf data item at key with its Myinfo envelope. A missing
// key yields the zero Field (Present false). A non-object leaf is wrapped as a
// synthetic {value: …} envelope so String / Value still work.
func (d Data) Field(key string) Field {
	v, ok := d.m[key]
	if !ok {
		return Field{}
	}
	if mm, ok := v.(map[string]any); ok {
		return Field{m: mm, present: true}
	}
	return Field{m: map[string]any{"value": v}, present: true}
}

// Object returns the nested object at key (e.g. regadd, mobileno). A missing key
// or a non-object value yields the zero Data (Present false).
func (d Data) Object(key string) Data {
	if mm, ok := d.m[key].(map[string]any); ok {
		return Data{m: mm}
	}
	return Data{}
}

// List returns the array of objects at key (e.g. a Corppass appointments or
// vehicles list). A missing key or a non-array value yields nil. Array elements
// that are not objects yield a zero Data in that position.
func (d Data) List(key string) []Data {
	arr, ok := d.m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]Data, len(arr))
	for i, e := range arr {
		if mm, ok := e.(map[string]any); ok {
			out[i] = Data{m: mm}
		}
	}
	return out
}

// Raw returns this object's underlying map (nil for the zero Data).
func (d Data) Raw() map[string]any { return d.m }

// Source returns this object's own "source" member — the Myinfo provenance code
// ("1".."4") that a container object (a grouped dataset such as noa-basic or
// drivinglicence, where the value leaves inside carry only {value}) or a repeated
// record (a licence, an appointment) declares as a sibling of its value leaves,
// rather than on any single leaf. Empty when the object declares none. Use
// SourceCode for the parsed, switch-able value. This is the object-level counterpart
// to Field.Source, so a caller need not reach into Raw and re-parse the code table.
func (d Data) Source() string { return asString(d.m["source"]) }

// SourceCode returns this object's own provenance as a typed Source (see Source).
func (d Data) SourceCode() Source { return parseSource(d.Source()) }

// Classification returns this object's own "classification" member (e.g. "C" for
// confidential); grouped datasets declare it on the container, not the leaves. Use
// ClassificationCode for the parsed value.
func (d Data) Classification() string { return asString(d.m["classification"]) }

// ClassificationCode returns this object's own classification as a typed
// Classification (see Classification).
func (d Data) ClassificationCode() Classification {
	return parseClassification(d.Classification())
}

// LastUpdated returns this object's own "lastupdated" member (YYYY-MM-DD); like
// Source / Classification it is carried on the container of a grouped dataset.
func (d Data) LastUpdated() string { return asString(d.m["lastupdated"]) }

// Kind classifies the value at key by its Myinfo envelope shape, so a caller
// walking a block generically can dispatch without inspecting the raw map itself:
// a leaf field to read (Field), a nested object to descend (Object), a repeated-
// record array to iterate (List), a bare scalar to skip (envelope metadata such as
// source / classification / lastupdated, or a non-envelope Corppass PascalCase
// scalar), or an absent key.
type Kind int

const (
	// KindAbsent means key is not present in this object (the zero value).
	KindAbsent Kind = iota
	// KindScalar is a bare scalar value — envelope metadata (source, classification,
	// lastupdated) or a non-envelope Corppass scalar — not a data leaf to render.
	KindScalar
	// KindLeaf is a leaf envelope (carries value / code / unavailable); read it with Field.
	KindLeaf
	// KindObject is a nested container object; descend into it with Object.
	KindObject
	// KindList is a repeated-record array; iterate it with List.
	KindList
)

// Kind reports the envelope shape of the value at key (see Kind).
func (d Data) Kind(key string) Kind {
	v, ok := d.m[key]
	if !ok {
		return KindAbsent
	}
	switch t := v.(type) {
	case []any:
		return KindList
	case map[string]any:
		if isLeafEnvelope(t) {
			return KindLeaf
		}
		return KindObject
	default:
		return KindScalar
	}
}

// isLeafEnvelope reports whether a map is a Myinfo leaf item (carries value, code,
// or the unavailable flag) rather than a nested container. Containers such as
// regadd / cpfbalances / noa carry only envelope metadata and child objects at
// their own level, so they have none of these keys.
func isLeafEnvelope(m map[string]any) bool {
	if _, ok := m["value"]; ok {
		return true
	}
	if _, ok := m["code"]; ok {
		return true
	}
	if _, ok := m["unavailable"]; ok {
		return true
	}
	return false
}

// Field is one leaf Myinfo data item together with its envelope metadata. Myinfo
// wraps every data item as an object carrying either a "value" (most fields) or a
// "code"+"desc" pair (coded fields such as sex / nationality / residentialstatus),
// plus "source", "classification" and "lastupdated"; an unavailable item instead
// carries "unavailable": true and no value. The zero Field is valid and empty
// (Present / Available false, string accessors "").
type Field struct {
	m       map[string]any
	present bool
}

// Present reports whether the field's key existed in the response at all.
func (f Field) Present() bool { return f.present }

// Unavailable reports whether Myinfo flagged this item as unavailable (present
// in the response but carrying no value, e.g. the source holds no such record).
func (f Field) Unavailable() bool {
	b, _ := f.m["unavailable"].(bool)
	return b
}

// Available reports whether the field is present, not flagged unavailable, and
// actually carries a value or code — i.e. there is real data to read.
func (f Field) Available() bool {
	return f.present && !f.Unavailable() && (f.Value() != "" || f.Code() != "")
}

// Value returns the "value" member (empty for coded or absent fields).
func (f Field) Value() string { return asString(f.m["value"]) }

// Code returns the "code" member of a coded field (empty otherwise).
func (f Field) Code() string { return asString(f.m["code"]) }

// Desc returns the "desc" member of a coded field (empty otherwise).
func (f Field) Desc() string { return asString(f.m["desc"]) }

// String returns the most human-readable text for the field: its value if it has
// one, else its coded description, else "". It is the "just show me the text"
// accessor.
func (f Field) String() string {
	if v := f.Value(); v != "" {
		return v
	}
	return f.Desc()
}

// Source returns the raw "source" member — Myinfo's provenance code ("1"
// government-verified, "2" user-provided, "3" not applicable, "4" verified).
// Use SourceCode for the parsed, switch-able value.
func (f Field) Source() string { return asString(f.m["source"]) }

// SourceCode returns the field's provenance as a typed Source, so callers can
// switch on it or ask Source.Authoritative rather than comparing the raw "1".."4"
// string against Myinfo's documented meanings by hand.
func (f Field) SourceCode() Source { return parseSource(f.Source()) }

// Classification returns the raw "classification" member (e.g. "C" for
// confidential). Use ClassificationCode for the parsed value.
func (f Field) Classification() string { return asString(f.m["classification"]) }

// ClassificationCode returns the field's data classification as a typed
// Classification.
func (f Field) ClassificationCode() Classification {
	return parseClassification(f.Classification())
}

// LastUpdated returns the "lastupdated" member (YYYY-MM-DD).
func (f Field) LastUpdated() string { return asString(f.m["lastupdated"]) }

// Raw returns the field's underlying envelope map (nil for the zero Field).
func (f Field) Raw() map[string]any { return f.m }

// Source is the parsed Myinfo provenance of a data item — where the value came
// from and how much it can be trusted. It is the typed form of Field.Source.
type Source int

const (
	// SourceUnknown is an absent or unrecognised "source" (the zero value).
	SourceUnknown Source = iota
	// SourceGovernmentVerified ("1") — provided and verified by the government.
	SourceGovernmentVerified
	// SourceUserProvided ("2") — provided by the user, not verified.
	SourceUserProvided
	// SourceNotApplicable ("3") — field not applicable / carries no value.
	SourceNotApplicable
	// SourceUserProvidedVerified ("4") — provided by the user and verified
	// against supporting documents.
	SourceUserProvidedVerified
)

// parseSource maps a raw Myinfo "source" code to a Source.
func parseSource(code string) Source {
	switch code {
	case "1":
		return SourceGovernmentVerified
	case "2":
		return SourceUserProvided
	case "3":
		return SourceNotApplicable
	case "4":
		return SourceUserProvidedVerified
	default:
		return SourceUnknown
	}
}

// Authoritative reports whether the value has been verified by an authority —
// either government-verified (1) or user-provided-and-verified (4) — as opposed
// to unverified user input or an inapplicable field.
func (s Source) Authoritative() bool {
	return s == SourceGovernmentVerified || s == SourceUserProvidedVerified
}

// String returns a human-readable label for the provenance.
func (s Source) String() string {
	switch s {
	case SourceGovernmentVerified:
		return "government-verified"
	case SourceUserProvided:
		return "user-provided"
	case SourceNotApplicable:
		return "not-applicable"
	case SourceUserProvidedVerified:
		return "user-provided (verified)"
	default:
		return "unknown"
	}
}

// Classification is the parsed Myinfo data-sensitivity classification of a data
// item. It is the typed form of Field.Classification.
type Classification int

const (
	// ClassificationUnknown is an absent or unrecognised "classification"
	// (the zero value).
	ClassificationUnknown Classification = iota
	// ClassificationConfidential ("C") — the sensitivity Myinfo tags person data
	// with today; handle accordingly.
	ClassificationConfidential
)

// parseClassification maps a raw Myinfo "classification" code to a Classification.
func parseClassification(code string) Classification {
	switch code {
	case "C":
		return ClassificationConfidential
	default:
		return ClassificationUnknown
	}
}

// Confidential reports whether the field is classified confidential.
func (c Classification) Confidential() bool { return c == ClassificationConfidential }

// String returns a human-readable label for the classification.
func (c Classification) String() string {
	switch c {
	case ClassificationConfidential:
		return "confidential"
	default:
		return "unknown"
	}
}

// Parse builds the envelope-aware view of an already-decoded /userinfo claim map.
// It takes a plain map (not a FAPIgo client.UserInfo), so it has no FAPIgo
// dependency and is usable on its own — e.g. in tests or over stored responses.
// The singpass package calls it with FAPIgo's validated result (userinfo.go).
func Parse(all map[string]any) *Response {
	unwrapped, _ := unwrapDeep(all).(map[string]any)
	if unwrapped == nil {
		unwrapped = map[string]any{}
	}
	return &Response{
		raw:      unwrapped,
		Person:   blockData(unwrapped, "person_info"),
		Entity:   blockData(unwrapped, "entity_info"),
		Corppass: blockData(unwrapped, "corppass_info"),
		Auth:     blockData(unwrapped, "auth_info"),
		TPAuth:   blockData(unwrapped, "tp_auth_info"),
	}
}

// blockData extracts a recognised object block, or the zero Data if absent /
// not an object.
func blockData(all map[string]any, key string) Data {
	if mm, ok := all[key].(map[string]any); ok {
		return Data{m: mm}
	}
	return Data{}
}

// unwrapDeep walks a decoded JSON value and unwraps any *stringified* JSON
// object/array one level, recursively — the Corppass Myinfo Business quirk where
// /userinfo data blocks (and some nested objects) arrive double-encoded: the
// value is a JSON string whose contents are themselves a JSON object or array. A
// string that parses as an object/array is replaced by the parsed value (and its
// contents unwrapped in turn); every other value — a decoded object/array is
// recursed into, a plain scalar (including a leaf "value" string, which never
// begins with '{' or '[') is returned unchanged.
func unwrapDeep(v any) any {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
			var inner any
			if json.Unmarshal([]byte(s), &inner) == nil {
				return unwrapDeep(inner)
			}
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = unwrapDeep(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = unwrapDeep(e)
		}
		return out
	default:
		return v
	}
}

// asString coerces a decoded JSON scalar to a string for display: strings pass
// through; JSON numbers (float64) are formatted without a trailing ".0"; bools
// render as "true"/"false"; anything else (or nil) yields "".
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}
