package singpasstest

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// UserPersona returns a Singpass test user made up from an NRIC or FIN and a
// name — for a login as someone the built-in personas don't cover, from the
// sign-in page's custom login or in a test. Its subject is a stable UUID
// derived from the NRIC or FIN, so logging in again as the same one gives the
// same "sub". Its Myinfo data is the NRIC or FIN, its masked form and the
// name; add more with Persona.UserInfo.
func UserPersona(nric, name string) Persona {
	nric = strings.ToUpper(strings.TrimSpace(nric))
	name = strings.ToUpper(strings.TrimSpace(name))
	if name == "" {
		name = "TEST USER " + nric
	}
	return Persona{
		Name:    name + " (custom)",
		Subject: stableUUID("user:" + nric),
		SubAttributes: map[string]any{
			"account_type": "standard", "identity_number": nric, "identity_coi": "SG", "name": name,
		},
		UserInfo: map[string]any{"person_info": map[string]any{
			"uinfin":        field(nric),
			"partialuinfin": field(maskID(nric)),
			"name":          field(name),
		}},
	}
}

// EntityPersona returns a Corppass test user made up from an entity's UEN and
// name, acting through a person's NRIC or FIN and name. The entity is the
// subject, as on Corppass, and the person is the "act" claim. Its Myinfo
// Business data is the entity's basic profile; add more with
// Persona.UserInfo.
func EntityPersona(uen, entityName, nric, name string) Persona {
	uen = strings.ToUpper(strings.TrimSpace(uen))
	entityName = strings.ToUpper(strings.TrimSpace(entityName))
	if entityName == "" {
		entityName = "TEST ENTITY " + uen
	}
	person := UserPersona(nric, name)
	return Persona{
		Name:    entityName + " (custom)",
		Subject: uen,
		SubAttributes: map[string]any{
			"entity_type": "UEN", "entity_reg_number": uen, "entity_coi": "SG",
			"entity_name": entityName, "entity_uen_status": "Registered",
		},
		Act: &Actor{Subject: person.Subject, SubAttributes: person.SubAttributes},
		UserInfo: map[string]any{"entity_info": map[string]any{"basic_profile": map[string]any{
			"name":                field(entityName),
			"registration_number": field(uen),
			"uen_status":          coded("R", "REGISTERED"),
		}}},
	}
}

var (
	nricPattern = regexp.MustCompile(`^[STFGM][0-9]{7}[A-Z]$`)
	uenPattern  = regexp.MustCompile(`^[0-9A-Z]{9,10}$`)
)

// checkCustom validates the sign-in page's custom login fields.
func checkCustom(nric, uen string, corppass bool) error {
	if !nricPattern.MatchString(strings.ToUpper(strings.TrimSpace(nric))) {
		return fmt.Errorf("NRIC / FIN %q must be a letter, 7 digits and a letter, e.g. S1234567D", nric)
	}
	if corppass && !uenPattern.MatchString(strings.ToUpper(strings.TrimSpace(uen))) {
		return fmt.Errorf("UEN %q must be 9 or 10 letters and digits, e.g. 201912345K", uen)
	}
	return nil
}

// stableUUID derives a UUID-shaped subject from seed, so the same custom user
// always gets the same "sub".
func stableUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	h[6] = h[6]&0x0f | 0x50 // version 5-style
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// maskID masks all but the last four characters, as Myinfo's partialuinfin.
func maskID(id string) string {
	if len(id) <= 4 {
		return id
	}
	return strings.Repeat("*", len(id)-4) + id[len(id)-4:]
}
