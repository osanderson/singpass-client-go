package singpasstest

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// The dashboard's paths, under the server's base URL.
const (
	dashboardPath = "/_fake/"
	requestsPath  = "/_fake/requests"
)

// healthcheckUserAgent marks singpass-fake-server's health checks, which the
// request log leaves out.
const healthcheckUserAgent = "singpass-fake-server-healthcheck"

// requestLogSize is how many requests the dashboard keeps.
const requestLogSize = 200

// RequestRecord is one request the server handled, as the dashboard lists it.
type RequestRecord struct {
	Time     time.Time `json:"time"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	ClientID string    `json:"client_id,omitempty"`
	Status   int       `json:"status"`
	// Error and ErrorDescription are the OAuth error the server answered
	// with, or sent back to the client in a redirect.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	// Detail says what a successful request did, e.g. who logged in.
	Detail string `json:"detail,omitempty"`
}

// requestLog keeps the most recent requests.
type requestLog struct {
	mu      sync.Mutex
	records []RequestRecord // oldest first
}

func (l *requestLog) add(r RequestRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r)
	if len(l.records) > requestLogSize {
		l.records = l.records[len(l.records)-requestLogSize:]
	}
}

// newest returns the records, newest first.
func (l *requestLog) newest() []RequestRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]RequestRecord, len(l.records))
	for i, r := range l.records {
		out[len(out)-1-i] = r
	}
	return out
}

// Requests returns the requests the server handled most recently, newest
// first: up to 200, leaving out the dashboard's own, a browser's favicon
// request and health checks. The
// dashboard at /_fake/ lists them, and /_fake/requests serves them as JSON.
func (s *Server) Requests() []RequestRecord { return s.requests.newest() }

// DashboardURL is where the server serves its dashboard: its issuer,
// clients, test users and recent requests.
func (s *Server) DashboardURL() string { return s.base + dashboardPath }

// recordingWriter records the response to a request.
type recordingWriter struct {
	http.ResponseWriter
	rec *RequestRecord
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.rec.Status == 0 {
		w.rec.Status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if w.rec.Status == 0 {
		w.rec.Status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// record wraps next to log each request for the dashboard.
func (s *Server) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_fake/") || r.URL.Path == "/favicon.ico" || r.UserAgent() == healthcheckUserAgent {
			next.ServeHTTP(w, r)
			return
		}
		rec := &RequestRecord{Time: time.Now(), Method: r.Method, Path: r.URL.Path}
		next.ServeHTTP(&recordingWriter{ResponseWriter: w, rec: rec}, r)
		if loc, err := url.Parse(w.Header().Get("Location")); err == nil && rec.Error == "" {
			// A redirect back to the client carries the outcome.
			q := loc.Query()
			rec.Error, rec.ErrorDescription = q.Get("error"), q.Get("error_description")
		}
		s.requests.add(*rec)
	})
}

// note adds to the record of the request w answers, if it is recorded.
func note(w http.ResponseWriter, clientID, detail string) {
	rw, ok := w.(*recordingWriter)
	if !ok {
		return
	}
	if clientID != "" {
		rw.rec.ClientID = clientID
	}
	if detail != "" {
		rw.rec.Detail = detail
	}
}

// noteError records the OAuth error the server answers w's request with.
func noteError(w http.ResponseWriter, clientID, code, desc string) {
	if rw, ok := w.(*recordingWriter); ok {
		if clientID != "" {
			rw.rec.ClientID = clientID
		}
		rw.rec.Error, rw.rec.ErrorDescription = code, desc
	}
}

// label is how the X-Custom-* headers name p: its NRIC or FIN, or on
// Corppass its UEN and the acting person's NRIC or FIN.
func (p Persona) label() string {
	nric, _ := p.SubAttributes["identity_number"].(string)
	if p.Act != nil {
		actor, _ := p.Act.SubAttributes["identity_number"].(string)
		return p.Subject + " / " + actor
	}
	return nric
}

func (s *Server) handleRequests(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.Requests())
}

//go:embed dashboard.html
var dashboardHTML string

var dashboardTemplate = template.Must(template.New("dashboard").Parse(dashboardHTML))

// dashboardClient is a registered client, as the dashboard shows it.
type dashboardClient struct {
	ID, App, RedirectURIs, Scopes, Keys string
	Test                                bool
}

// dashboardUser is a test user, as the dashboard shows it.
type dashboardUser struct{ Label, Name, Subject string }

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	name := "Singpass"
	if s.cfg.Issuer == Corppass {
		name = "Corppass"
	}
	tests := map[string]bool{}
	for _, id := range s.TestClients() {
		tests[id] = true
	}
	var clients []dashboardClient
	for _, id := range s.clients.ids() {
		c, _ := s.clients.get(fapi.ClientID(id))
		app := "Login"
		if c.cfg.App == Myinfo {
			app = "Myinfo"
			if s.cfg.Issuer == Corppass {
				app = "Myinfo Business"
			}
		}
		redirects := strings.Join(c.cfg.RedirectURIs, " ")
		if c.cfg.AnyLoopbackRedirectURI {
			redirects = "any http://localhost URI"
		}
		clients = append(clients, dashboardClient{
			ID: id, App: app, RedirectURIs: redirects, Scopes: scopesSummary(c.cfg.Scopes),
			Keys: "sig " + c.cfg.SigningKID + ", enc " + c.cfg.EncryptionKID, Test: tests[id],
		})
	}
	var users []dashboardUser
	for _, p := range s.personas {
		users = append(users, dashboardUser{Label: p.label(), Name: p.Name, Subject: p.Subject})
	}
	requests, _ := json.Marshal(s.Requests())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = dashboardTemplate.Execute(w, map[string]any{
		"Name": name, "Issuer": s.issuer, "Discovery": s.issuer + "/.well-known/openid-configuration",
		"Clients": clients, "Users": users, "Corppass": s.cfg.Issuer == Corppass,
		"TestKeysURL": s.TestClientKeysURL(), "HasTestClients": len(tests) > 0,
		"Requests": template.JS(requests), "RequestsURL": requestsPath,
	})
}
