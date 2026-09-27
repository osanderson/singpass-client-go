package myinfo

import "strconv"

// Leaf is one data item found by Data.Leaves: the item and the keys that lead
// to it from the Data it was found in.
type Leaf struct {
	// Path is the keys from the starting object down to the item, e.g.
	// ["regadd", "postal"]. An element of a repeated-record list appears as its
	// zero-based index, e.g. ["vehicles", "0", "make"] — Myinfo keys are never
	// numeric, so an index can't be mistaken for a key.
	Path []string
	// Field is the item with its envelope.
	Field Field
}

// Key returns the item's own key: the last element of Path.
func (l Leaf) Key() string {
	if len(l.Path) == 0 {
		return ""
	}
	return l.Path[len(l.Path)-1]
}

// Leaves returns every data item under d, depth-first in key order: it
// descends nested objects and repeated-record lists, so a caller can flatten a
// block (to a table, a form, a database row) without knowing its shape. Bare
// envelope metadata (source, classification, lastupdated, …) is not returned;
// items flagged unavailable are, so check Field.Available.
func (d Data) Leaves() []Leaf {
	var out []Leaf
	d.walk(nil, &out)
	return out
}

func (d Data) walk(prefix []string, out *[]Leaf) {
	for _, k := range d.Keys() {
		path := append(append([]string(nil), prefix...), k)
		switch d.Kind(k) {
		case KindLeaf:
			*out = append(*out, Leaf{Path: path, Field: d.Field(k)})
		case KindObject:
			d.Object(k).walk(path, out)
		case KindList:
			for i, el := range d.List(k) {
				if el.Present() {
					el.walk(append(path, strconv.Itoa(i)), out)
				}
			}
		}
	}
}

// EffectiveSource returns the provenance that applies to everything in d: the
// source d declares itself (Myinfo puts it on the container of a grouped
// dataset such as regadd or drivinglicence, not on the value leaves inside),
// or else the single source shared by all of d's items and nested objects.
// It is SourceUnknown when they are mixed — including when a nested object is
// itself mixed — or when none is declared.
func (d Data) EffectiveSource() Source {
	s, _ := d.effectiveSource()
	return s
}

// effectiveSource is EffectiveSource plus whether d's sources are mixed, so a
// parent can tell a mixed child (which makes it mixed) from one that simply
// declares nothing (which doesn't count).
func (d Data) effectiveSource() (Source, bool) {
	if s := d.SourceCode(); s != SourceUnknown {
		return s, false
	}
	seen := map[Source]bool{}
	mixed := false
	add := func(s Source, m bool) {
		mixed = mixed || m
		if s != SourceUnknown {
			seen[s] = true
		}
	}
	for _, k := range d.Keys() {
		switch d.Kind(k) {
		case KindLeaf:
			if f := d.Field(k); f.Available() {
				add(f.SourceCode(), false)
			}
		case KindObject:
			add(d.Object(k).effectiveSource())
		case KindList:
			add(commonSource(d.List(k)))
		}
	}
	if mixed || len(seen) > 1 {
		return SourceUnknown, true
	}
	return single(seen), false
}

// CommonSource returns the effective source shared by all the given items —
// e.g. the records of a repeated-record list, for one provenance badge on a
// table — or SourceUnknown when they differ, any is mixed, or none declares one.
func CommonSource(items ...Data) Source {
	s, _ := commonSource(items)
	return s
}

func commonSource(items []Data) (Source, bool) {
	seen := map[Source]bool{}
	for _, it := range items {
		if !it.Present() {
			continue
		}
		s, mixed := it.effectiveSource()
		if mixed {
			return SourceUnknown, true
		}
		if s != SourceUnknown {
			seen[s] = true
		}
	}
	if len(seen) > 1 {
		return SourceUnknown, true
	}
	return single(seen), false
}

func single(seen map[Source]bool) Source {
	if len(seen) != 1 {
		return SourceUnknown
	}
	for s := range seen {
		return s
	}
	return SourceUnknown
}
