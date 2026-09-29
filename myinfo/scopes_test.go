package myinfo

import (
	"reflect"
	"slices"
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

func TestBusinessScopes(t *testing.T) {
	got := Scopes("openid", EntityBasicProfile, UserName, CorppassEmail, UserName)
	if got[0] != "openid" || !slices.Contains(got, "entity.basic_profile.name") || !slices.Contains(got, "entity.basic_profile.uen_status") ||
		!slices.Contains(got, "user.name") || !slices.Contains(got, "corppass.email") {
		t.Errorf("Scopes = %q", got)
	}
	if n := len(got); n != 1+len(businessCatalogue[EntityBasicProfile])+2 {
		t.Errorf("got %d scopes: duplicates not dropped?", n)
	}
	for s, want := range map[string]bool{
		"entity.basic_profile.name": true, "entity.appointments.individual_appointment.id_number": true,
		"user.name": true, "user.hdbownership.address": true, "corppass.email": true,
		"entity.identity": true, "entity.grants.last_updated_date": true,
		"entity.basic_profile": false, "user.chas": false, "entity.nope": false, "entity.grants.last_update_date": false,
	} {
		if IsScope(s) != want {
			t.Errorf("IsScope(%q) = %v", s, !want)
		}
	}
}

// The Myinfo Business catalogue comes from Corppass's scope pages (45 items
// and 113 scopes) plus entity.identity, which they don't list but Corppass
// accepts. Every user.* scope is a person-data scope with the user.
// prefix.
func TestBusinessCatalogue(t *testing.T) {
	if len(businessCatalogue) != 46 || len(AllBusinessScopes()) != 114 {
		t.Errorf("business catalogue has %d items and %d scopes, want 46 and 114", len(businessCatalogue), len(AllBusinessScopes()))
	}
	for item, scopes := range businessCatalogue {
		for _, s := range scopes {
			if s != item && !strings.HasPrefix(s, item+".") {
				t.Errorf("scope %q is filed under %q", s, item)
			}
			if rest, ok := strings.CutPrefix(s, "user."); ok && !IsScope(rest) {
				t.Errorf("%q is not user. + a person-data scope", s)
			}
		}
	}
	// The entity items EntityProfile reads are catalogue items.
	for _, item := range []string{EntityBasicProfile, EntityAddress, EntityAppointments, EntityShareholders} {
		if _, ok := businessCatalogue[item]; !ok {
			t.Errorf("%q missing", item)
		}
	}
}
