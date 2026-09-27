package demoapp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPagesCreditTheLibrary checks both pages name the library and link to its
// repository.
func TestPagesCreditTheLibrary(t *testing.T) {
	home := httptest.NewRecorder()
	RenderHome(home, Home{Apps: []HomeApp{{Name: "login", Title: "Singpass Login"}}})
	profile := httptest.NewRecorder()
	RenderProfile(profile, ProfileData{App: "login", Title: "Singpass Login", Subject: "S"})

	for name, body := range map[string]string{"home": home.Body.String(), "profile": profile.Body.String()} {
		if !strings.Contains(body, `href="`+RepoURL+`"`) {
			t.Errorf("%s page has no link to %s", name, RepoURL)
		}
		if !strings.Contains(body, "singpass-client-go") || !strings.Contains(body, "View on GitHub") {
			t.Errorf("%s page doesn't credit singpass-client-go", name)
		}
	}
}

// TestHomeDescribesTheMode checks the landing page names staging normally and
// flags mock mode (without the staging claim) when running against the fakes.
func TestHomeDescribesTheMode(t *testing.T) {
	apps := []HomeApp{{Name: "login", Title: "Singpass Login"}}
	for _, tc := range []struct {
		mock           bool
		want, dontWant string
	}{
		{false, "(Singpass / Corppass staging)", "Mock mode"},
		{true, "Mock mode", "(Singpass / Corppass staging)"},
	} {
		rec := httptest.NewRecorder()
		RenderHome(rec, Home{Apps: apps, Mock: tc.mock})
		body := rec.Body.String()
		if !strings.Contains(body, tc.want) || strings.Contains(body, tc.dontWant) {
			t.Errorf("mock=%v: want %q and not %q", tc.mock, tc.want, tc.dontWant)
		}
	}

	rec := httptest.NewRecorder()
	RenderProfile(rec, ProfileData{App: "login", Title: "Singpass Login", Mock: true})
	if !strings.Contains(rec.Body.String(), "mock mode") {
		t.Error("profile page doesn't flag mock mode")
	}
}

// TestProfileAccessibilityMarkup checks the screen-reader affordances: a
// labelled lock, empty values read as "no value", and column headers scoped.
func TestProfileAccessibilityMarkup(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderProfile(rec, ProfileData{App: "mi", Title: "Myinfo", Sections: []Section{{
		Title: "Person",
		Rows:  []Highlight{{Label: "Name", Value: "TAN", Confidential: true}, {Label: "Email"}},
		Tables: []Table{{Title: "Vehicles", Columns: []string{"Make", "Model"},
			Rows: []TableRow{{Cells: []string{"TOYOTA", ""}}}}},
	}}})
	body := rec.Body.String()
	for _, want := range []string{
		`role="img" aria-label="Confidential"`,
		`<span class="sr-only">no value</span>`,
		`<th scope="col">Make</th>`,
		`<div class="tablewrap"><table>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("profile page lacks %q", want)
		}
	}
}
