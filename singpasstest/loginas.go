package singpasstest

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Headers that choose who one login signs in as, sent on the authorization
// request — the GET of the URL singpass.Client.BeginLogin returns. They are
// MockPass's, so tests written for it carry over. A request with any of them
// is approved (or denied) straight away, even on an Interactive server, so
// one server serves both a browser and headless tests; each login picks its
// own user, so parallel tests don't interfere. See LoginAs.
const (
	// HeaderNRIC is the user's NRIC or FIN. Required with any other header
	// except HeaderError.
	HeaderNRIC = "X-Custom-NRIC"
	// HeaderUUID overrides the user's Singpass UUID: the id_token "sub" on
	// Singpass, "act.sub" on Corppass.
	HeaderUUID = "X-Custom-UUID"
	// HeaderUEN is the entity's UEN. Required on Corppass, refused on
	// Singpass.
	HeaderUEN = "X-Custom-UEN"
	// HeaderName is the user's name, for a user no persona has.
	HeaderName = "X-Custom-Name"
	// HeaderError makes the login fail: "access_denied" is the user
	// cancelling.
	HeaderError = "X-Custom-Error"
)

// LoginAs chooses the user for one login, as the X-Custom-* headers do
// (see HeaderNRIC). An NRIC or FIN that a persona has — or, on Corppass, a
// UEN — logs in as that persona, with its Myinfo data; any other logs in as a
// new user, made as UserPersona or EntityPersona make one. On Corppass, an
// NRIC other than the persona's acting person acts for the persona's entity
// instead. The zero LoginAs means the current persona (see
// Server.SetPersona).
type LoginAs struct {
	NRIC string
	// UUID, if set, replaces the user's Singpass UUID.
	UUID string
	// UEN is the entity, on Corppass only.
	UEN string
	// Name is a new user's name; a persona keeps its own.
	Name string
	// Cancel denies the login with access_denied, as if the user cancelled.
	Cancel bool
}

// Header returns l as the X-Custom-* headers, for a test that sends the
// authorization request itself.
func (l LoginAs) Header() http.Header {
	h := http.Header{}
	for name, v := range map[string]string{HeaderNRIC: l.NRIC, HeaderUUID: l.UUID, HeaderUEN: l.UEN, HeaderName: l.Name} {
		if v != "" {
			h.Set(name, v)
		}
	}
	if l.Cancel {
		h.Set(HeaderError, "access_denied")
	}
	return h
}

// loginAsFromHeader reads the X-Custom-* headers. A zero result means none
// were sent.
func loginAsFromHeader(h http.Header) (LoginAs, error) {
	l := LoginAs{
		NRIC: strings.TrimSpace(h.Get(HeaderNRIC)),
		UUID: strings.TrimSpace(h.Get(HeaderUUID)),
		UEN:  strings.TrimSpace(h.Get(HeaderUEN)),
		Name: strings.TrimSpace(h.Get(HeaderName)),
	}
	switch e := strings.TrimSpace(h.Get(HeaderError)); e {
	case "":
	case "access_denied":
		l.Cancel = true
	default:
		return LoginAs{}, fmt.Errorf("%s %q is not supported; use access_denied", HeaderError, e)
	}
	return l, nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// check reports what is wrong with l for a Singpass or Corppass login.
func (l LoginAs) check(corppass bool) error {
	if l.Cancel {
		if l.NRIC != "" || l.UUID != "" || l.UEN != "" || l.Name != "" {
			return fmt.Errorf("%s cannot be combined with the other X-Custom-* headers", HeaderError)
		}
		return nil
	}
	if l.NRIC == "" {
		return fmt.Errorf("%s is required with %s, %s and %s", HeaderNRIC, HeaderUUID, HeaderUEN, HeaderName)
	}
	if !corppass && l.UEN != "" {
		return fmt.Errorf("%s is for Corppass; this is a Singpass server", HeaderUEN)
	}
	if corppass && l.UEN == "" {
		return fmt.Errorf("%s is required on Corppass", HeaderUEN)
	}
	if l.UUID != "" && !uuidPattern.MatchString(l.UUID) {
		return fmt.Errorf("%s %q must be a UUID, e.g. a9865837-7bd7-46ac-bef4-42a76a946424", HeaderUUID, l.UUID)
	}
	return checkCustom(l.NRIC, l.UEN, corppass)
}

// headerLogin reads the X-Custom-* headers in h and the persona they choose:
// none for a zero or cancelled LoginAs.
func (s *Server) headerLogin(h http.Header) (LoginAs, Persona, error) {
	l, err := loginAsFromHeader(h)
	if err != nil || l == (LoginAs{}) {
		return l, Persona{}, err
	}
	corppass := s.cfg.Issuer == Corppass
	if err := l.check(corppass); err != nil {
		return LoginAs{}, Persona{}, err
	}
	if l.Cancel {
		return l, Persona{}, nil
	}
	return l, s.loginAsPersona(l, corppass), nil
}

// loginAsPersona returns the persona a checked, non-cancelling l logs in as.
func (s *Server) loginAsPersona(l LoginAs, corppass bool) Persona {
	nric := strings.ToUpper(l.NRIC)
	uuid := strings.ToLower(l.UUID)
	if !corppass {
		p, ok := s.personaWith(func(p Persona) bool { return identityNumber(p.SubAttributes) == nric })
		if !ok {
			p = UserPersona(nric, l.Name)
		}
		if uuid != "" {
			p.Subject = uuid
		}
		return p
	}
	uen := strings.ToUpper(l.UEN)
	p, ok := s.personaWith(func(p Persona) bool { return p.Subject == uen })
	if !ok {
		p = EntityPersona(uen, "", nric, l.Name)
	}
	if p.Act == nil || identityNumber(p.Act.SubAttributes) != nric {
		u := UserPersona(nric, l.Name)
		p.Act = &Actor{Subject: u.Subject, SubAttributes: u.SubAttributes}
	}
	if uuid != "" {
		act := *p.Act
		act.Subject = uuid
		p.Act = &act
	}
	return p
}

// personaWith returns a copy of the first persona match accepts.
func (s *Server) personaWith(match func(Persona) bool) (Persona, bool) {
	for _, p := range s.personas {
		if match(p) {
			return p, true
		}
	}
	return Persona{}, false
}

// identityNumber is the NRIC or FIN in a person's sub_attributes.
func identityNumber(attrs map[string]any) string {
	s, _ := attrs["identity_number"].(string)
	return strings.ToUpper(s)
}
