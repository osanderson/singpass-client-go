package main

import (
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/myinfo"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

func summaryMap(id *singpass.Identity) map[string]string {
	out := map[string]string{}
	for _, h := range summary(id) {
		out[h.Label] = h.Value
		if h.Hint == "" {
			out["missing hint: "+h.Label] = ""
		}
	}
	return out
}

func TestSummaryPerson(t *testing.T) {
	persona := singpasstest.DefaultPersonas(singpasstest.Singpass)[0]
	got := summaryMap(&singpass.Identity{Myinfo: myinfo.Parse(persona.UserInfo)})
	for label, want := range map[string]string{
		"Name":               "TAN XIAO HUI",
		"UINFIN":             "S9812381D",
		"Sex":                "FEMALE (F)",
		"Date of birth":      "6 June 1998",
		"Mobile":             "+65 97399245 (+6597399245)",
		"Registered address": "102 BEDOK NORTH AVENUE 4 / #09-128 / SINGAPORE 460102",
	} {
		if got[label] != want {
			t.Errorf("%s = %q, want %q", label, got[label], want)
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "missing hint") {
			t.Error(k)
		}
	}
}

func TestSummaryEntity(t *testing.T) {
	persona := singpasstest.DefaultPersonas(singpasstest.Corppass)[0]
	id := &singpass.Identity{
		Myinfo: myinfo.Parse(persona.UserInfo),
		Claims: map[string]any{"sub_attributes": persona.SubAttributes},
	}
	got := summaryMap(id)
	for label, want := range map[string]string{
		"Entity":       "HARBOURFRONT TRADING PTE. LTD.",
		"UEN":          "201912345K",
		"UEN status":   "REGISTERED",
		"Address":      "10 HARBOURFRONT AVENUE, #08-01, SINGAPORE 098632",
		"Appointments": "1: DIRECTOR LIM WEI MING",
	} {
		if got[label] != want {
			t.Errorf("%s = %q, want %q", label, got[label], want)
		}
	}
	if summary(&singpass.Identity{}) != nil {
		t.Error("Login identity (no Myinfo) should have no summary")
	}
}

func TestSGD(t *testing.T) {
	for x, want := range map[float64]string{0: "S$0.00", 1581.48: "S$1,581.48", 1234567.5: "S$1,234,567.50", 999.999: "S$1,000.00", -42: "-S$42.00"} {
		if got := sgd(x); got != want {
			t.Errorf("sgd(%v) = %q, want %q", x, got, want)
		}
	}
}
