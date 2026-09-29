package myinfo

import (
	"slices"
	"sort"
	"strings"
)

// Scopes returns the Myinfo scopes that request the given data items, for
// MyinfoOptions.Scopes or MyinfoBusinessOptions.Scopes. Each item (an Item constant, e.g. ItemName) expands to
// every scope in the Myinfo data catalogue that it covers: ItemName gives
// "name", ItemVehicles all 37 "vehicles.*" field scopes, ItemCPFBalances
// "cpfbalances.oa", ".ma", ".ra" and ".sa". Anything that isn't an item key —
// "openid", or a single field scope such as "vehicles.make" — is passed
// through unchanged, so the result can be the whole scope list:
//
//	Scopes: myinfo.Scopes("openid", myinfo.ItemUINFIN, myinfo.ItemName, myinfo.ItemVehicles),
//
// For Myinfo Business, pass the block-prefixed items instead:
// EntityBasicProfile gives every "entity.basic_profile.*" scope, UserName
// "user.name", CorppassEmail "corppass.email".
//
// Duplicates are dropped and the input order kept. Request only what your app
// is approved for: Singpass rejects scopes the app isn't allowed.
func Scopes(items ...string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, it := range items {
		scopes, ok := catalogue[it]
		if !ok {
			scopes, ok = businessCatalogue[it]
		}
		if ok {
			for _, s := range scopes {
				add(s)
			}
			continue
		}
		add(it)
	}
	return out
}

// IsScope reports whether s is a Myinfo scope: a person-data scope in the
// Singpass data catalogue, e.g. "name" or "vehicles.make", or a Myinfo
// Business scope, e.g. "entity.basic_profile.name" or "user.name". It is
// useful for checking scopes read from configuration. It is false for
// "openid" and for item keys that aren't scopes themselves, such as
// "vehicles".
func IsScope(s string) bool {
	item, rest, _ := strings.Cut(s, ".")
	if slices.Contains(catalogue[item], s) {
		return true
	}
	// Myinfo Business scopes are block-prefixed: entity.<item>…, user.<item>…
	next, _, _ := strings.Cut(rest, ".")
	return slices.Contains(businessCatalogue[item+"."+next], s)
}

// AllScopes returns every Myinfo person-data scope in the data catalogue,
// sorted.
func AllScopes() []string {
	var out []string
	for _, scopes := range catalogue {
		out = append(out, scopes...)
	}
	sort.Strings(out)
	return out
}

// AllBusinessScopes returns every Myinfo Business scope Corppass documents
// (entity.*, user.* and corppass.*), sorted.
func AllBusinessScopes() []string {
	var out []string
	for _, scopes := range businessCatalogue {
		out = append(out, scopes...)
	}
	sort.Strings(out)
	return out
}
