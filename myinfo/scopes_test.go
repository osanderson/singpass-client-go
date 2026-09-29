package myinfo

import (
	"reflect"
	"strings"
	"testing"
)

func TestScopes(t *testing.T) {
	got := Scopes("openid", ItemName, ItemCPFBalances, "vehicles.make", ItemName)
	want := []string{"openid", "name", "cpfbalances.oa", "cpfbalances.ma", "cpfbalances.ra", "cpfbalances.sa", "vehicles.make"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Scopes = %q, want %q", got, want)
	}
	if n := len(Scopes(ItemVehicles)); n != 37 {
		t.Errorf("vehicles expands to %d scopes, want 37", n)
	}
	if Scopes() != nil {
		t.Error("Scopes() should be nil")
	}
}

func TestIsScope(t *testing.T) {
	for s, want := range map[string]bool{
		"name": true, "vehicles.make": true, "noa-basic": true, "drivinglicence.qdl.classes": true,
		"vehicles": false, "cpfbalances": false, "openid": false, "vehicles.colour": false, "": false,
	} {
		if IsScope(s) != want {
			t.Errorf("IsScope(%q) = %v", s, !want)
		}
	}
}

// The catalogue is generated from Singpass's data catalogue: 53 items and
// 171 scopes, each under its item.
func TestCatalogue(t *testing.T) {
	if len(catalogue) != 53 || len(AllScopes()) != 171 {
		t.Errorf("catalogue has %d items and %d scopes, want 53 and 171", len(catalogue), len(AllScopes()))
	}
	for item, scopes := range catalogue {
		for _, s := range scopes {
			if s != item && !strings.HasPrefix(s, item+".") {
				t.Errorf("scope %q is filed under %q", s, item)
			}
		}
	}
	// Every item PersonProfile reads is a catalogue item.
	for _, item := range []string{ItemUINFIN, ItemName, ItemDOB, ItemRegAdd, ItemMobileNo, ItemCPFBalances,
		ItemNOABasic, ItemNOA, ItemNOAHistoryBasic, ItemNOAHistory, ItemVehicles, ItemHDBOwnership, ItemDrivingLicence} {
		if _, ok := catalogue[item]; !ok {
			t.Errorf("%q is not a catalogue item", item)
		}
	}
}
