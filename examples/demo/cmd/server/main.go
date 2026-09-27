// Command server runs the Singpass RP demo: a small web app that authenticates
// users against Singpass Login, Singpass Myinfo, and Corppass Myinfo Business
// (whichever have a client_id configured) using the reusable singpass and web
// packages. It is an example of wiring the library, not production code — it
// defaults to the in-memory session store and staging assurance.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/examples/demo/internal/config"
	"github.com/osanderson/singpass-client-go/examples/demo/internal/demoapp"
	"github.com/osanderson/singpass-client-go/keyfile"
	"github.com/osanderson/singpass-client-go/myinfo"
	"github.com/osanderson/singpass-client-go/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	logger := newLogger(cfg.LogJSON)
	slog.SetDefault(logger)

	// Cancelled on SIGTERM (Cloud Run's shutdown signal) or Ctrl-C, which
	// triggers a graceful shutdown below.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	// Shared dependencies for every relying party: the demo defaults (in-memory
	// sessions, staging assurance) plus the HTTP timeout and debug flag from the
	// environment. A production deployment would set Assurance and a durable
	// Sessions store here.
	deps := singpass.Dependencies{
		HTTPTimeout: cfg.HTTPTimeout,
		Debug:       cfg.Debug,
		Logger:      logger,
	}

	if cfg.Mock {
		closeMock, err := startMock(&cfg, logger)
		if err != nil {
			logger.Error("start mock servers", "err", err)
			os.Exit(1)
		}
		defer closeMock()
		deps.AllowLoopbackHTTP = true
	}

	var apps []*web.App
	for _, ac := range cfg.Apps {
		client, jwks, err := buildApp(ctx, ac, deps)
		if err != nil {
			logger.Error("build relying party", "app", ac.Name, "err", err)
			os.Exit(1)
		}
		apps = append(apps, &web.App{
			Name:  ac.Name,
			Title: ac.Title,
			Auth:  client,
			JWKS:  jwks,
		})
		logger.Info("relying party ready",
			"app", ac.Name, "issuer", ac.Issuer, "client_id", ac.ClientID,
			"redirect_uri", ac.RedirectURI, "fetch_userinfo", ac.FetchUserInfo,
			"acr_values", ac.AcrValues)
	}

	renderHome := func(w http.ResponseWriter, message string) {
		demoapp.RenderHome(w, demoapp.Home{Apps: homeApps(apps), Message: message, Mock: cfg.Mock})
	}

	handlers := web.New(web.Config{
		Apps:   apps,
		Logger: logger,
		// Mark cookies Secure whenever the app is served over HTTPS, so the
		// session cookie is never sent in the clear.
		Cookies: web.CookieConfig{Secure: strings.HasPrefix(cfg.BaseURL, "https://")},
		OnAuthenticated: func(w http.ResponseWriter, r *http.Request, _ *web.App, _ *singpass.Identity) {
			// The "/" handler renders the profile from the session cookie the web
			// helper just set.
			http.Redirect(w, r, "/", http.StatusFound)
		},
		OnDenied: func(w http.ResponseWriter, _ *http.Request, app *web.App, denied *singpass.DeniedError) {
			renderHome(w, "Login with "+app.Title+" was declined: "+denied.Code)
		},
		OnError: func(w http.ResponseWriter, _ *http.Request, app *web.App, err error) {
			// A stale login (expired, reloaded callback, other browser) isn't a
			// failure worth alarming the user about: ask them to try again.
			if errors.Is(err, singpass.ErrLoginExpired) {
				logger.Warn("login expired", "app", app.Name, "err", err)
				w.WriteHeader(http.StatusBadRequest)
				renderHome(w, "Your "+app.Title+" login expired. Please try again.")
				return
			}
			logger.Error("login error", "app", app.Name, "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			renderHome(w, "Login with "+app.Title+" failed. See server logs.")
		},
	})

	mux := handlers.Mux()
	// "/" shows the signed-in identity and Myinfo data, so it must never be
	// cached (NoStore): after logout, Back must not bring it back.
	mux.Handle("/", web.NoStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if id, ok := handlers.CurrentIdentity(r); ok {
			app := handlers.App(id.App)
			title := id.App
			if app != nil {
				title = app.Title
			}
			pd := demoapp.ProfileData{
				Mock:            cfg.Mock,
				App:             id.App,
				Title:           title,
				Subject:         id.Subject,
				Scope:           id.Scope,
				ScopeList:       strings.Fields(id.Scope),
				TokenHighlights: idTokenHighlights(id),
				ClaimsPre:       demoapp.PrettyJSON(id.Claims),
			}
			if id.Myinfo != nil {
				pd.Blocks = strings.Join(id.Myinfo.Blocks(), ", ")
				pd.Summary = summary(id)
				pd.Sections = myinfoSections(id.Myinfo)
				pd.PersonInfoPre = demoapp.PrettyJSON(id.Myinfo.Raw())
			}
			demoapp.RenderProfile(w, pd)
			return
		}
		renderHome(w, "")
	})))

	logger.Info("listening", "addr", cfg.Addr, "base_url", cfg.BaseURL, "apps", len(apps))
	// Bound how long a client may take to send headers/body or sit idle, so
	// slow or stalled connections (Slowloris) cannot pin the server open. No
	// WriteTimeout: Myinfo callbacks wait on several outbound calls, each
	// already bounded by cfg.HTTPTimeout.
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           web.SecureHeaders(mux), // CSP, anti-framing, nosniff, HSTS, …
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		logger.Error("server", "err", err)
		os.Exit(1)
	case <-ctx.Done():
	}
	// Cloud Run allows 10s between SIGTERM and SIGKILL; let in-flight
	// callbacks finish within that.
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
	}
}

// newLogger returns the demo's logger: human-readable text by default, or JSON
// lines whose "severity" and "message" keys Cloud Logging maps to a log entry's
// level and summary (so errors show as errors in the Cloud Run console).
func newLogger(jsonFormat bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if !jsonFormat {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) > 0 {
			return a
		}
		switch a.Key {
		case slog.LevelKey:
			a.Key = "severity"
			if a.Value.Any().(slog.Level) == slog.LevelWarn {
				a.Value = slog.StringValue("WARNING")
			}
		case slog.MessageKey:
			a.Key = "message"
		}
		return a
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

// buildApp constructs the singpass.Client and public JWKS for one configured relying
// party, dispatching on its slug to the matching product constructor so the demo
// exercises all three. Key material is loaded from the PEM files the config
// points at.
func buildApp(ctx context.Context, ac config.AppConfig, deps singpass.Dependencies) (*singpass.Client, []byte, error) {
	sigKey, encKey := ac.SigKey, ac.EncKey
	var err error
	if sigKey == nil {
		if sigKey, err = keyfile.LoadECPrivateKey(ac.SigKeyPath); err != nil {
			return nil, nil, err
		}
	}
	if encKey == nil {
		if encKey, err = keyfile.LoadECPrivateKey(ac.EncKeyPath); err != nil {
			return nil, nil, err
		}
	}

	var client *singpass.Client
	switch ac.Name {
	case "login":
		client, err = singpass.NewLogin(ctx, singpass.LoginOptions{
			Name:            ac.Name,
			Issuer:          ac.Issuer,
			ClientID:        ac.ClientID,
			RedirectURI:     ac.RedirectURI,
			Scopes:          ac.Scopes,
			AuthContextType: ac.AuthContextType,
			AcrValues:       ac.AcrValues,
			SigningKey:      sigKey,
			SigningKID:      ac.SigKID,
			EncryptionKey:   encKey,
			EncryptionKID:   ac.EncKID,
		}, deps)
	case "mi":
		client, err = singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
			Name:          ac.Name,
			Issuer:        ac.Issuer,
			ClientID:      ac.ClientID,
			RedirectURI:   ac.RedirectURI,
			Scopes:        ac.Scopes,
			AcrValues:     ac.AcrValues,
			SigningKey:    sigKey,
			SigningKID:    ac.SigKID,
			EncryptionKey: encKey,
			EncryptionKID: ac.EncKID,
		}, deps)
	case "mib":
		client, err = singpass.NewMyinfoBusiness(ctx, singpass.MyinfoBusinessOptions{
			Name:          ac.Name,
			Issuer:        ac.Issuer,
			ClientID:      ac.ClientID,
			RedirectURI:   ac.RedirectURI,
			Scopes:        ac.Scopes,
			SigningKey:    sigKey,
			SigningKID:    ac.SigKID,
			EncryptionKey: encKey,
			EncryptionKID: ac.EncKID,
		}, deps)
	default:
		return nil, nil, fmt.Errorf("unknown app slug %q", ac.Name)
	}
	if err != nil {
		return nil, nil, err
	}

	jwks, err := client.PublicJWKS(ctx)
	if err != nil {
		return nil, nil, err
	}
	return client, jwks, nil
}

// idTokenHighlights interprets the validated id_token claims into a short table,
// the id_token counterpart of myinfoSections. The id_token is present for every
// flow (unlike /userinfo), so this renders for Login, Myinfo and Myinfo Business
// alike; claims a given flow doesn't carry are simply skipped. FAPIgo has already
// signature-, issuer-, audience-, nonce- and expiry-validated these before we read
// them, and IDTokenIssuedAt / IDTokenExpiry are the exact validated iat / exp.
func idTokenHighlights(id *singpass.Identity) []demoapp.Highlight {
	var hs []demoapp.Highlight
	add := func(label, value, note string) {
		if value == "" {
			return
		}
		hs = append(hs, demoapp.Highlight{Label: label, Value: value, Note: note})
	}

	add("Issuer", id.Issuer(), "")
	add("Audience", strings.Join(id.Audience(), ", "), "the client_id this token was issued to")
	// SubjectType distinguishes a person ("user") from an organisation login
	// ("entity", Corppass Myinfo Business).
	add("Subject type", id.SubjectType(), "")
	assuranceNote := ""
	if loa := id.AssuranceLevel(); loa != "" {
		assuranceNote = "Level of Assurance " + loa
	}
	add("Assurance (acr)", id.AssuranceContext(), assuranceNote)
	add("Auth methods (amr)", strings.Join(id.AuthMethods(), ", "), "")
	// For Corppass the person who authenticated on behalf of the entity is the
	// acting party, distinct from the entity subject.
	if act := id.ActingParty(); act != nil {
		add("Acting user", act.Subject, strings.TrimSpace(act.SubjectType))
		attributeRows(add, "Acting user › ", "act.sub_attributes", act.Attributes)
	}
	if !id.IDTokenIssuedAt.IsZero() {
		add("Issued at", id.IDTokenIssuedAt.Format(time.RFC3339), "")
	}
	if !id.IDTokenExpiry.IsZero() {
		note := ""
		if !id.IDTokenIssuedAt.IsZero() {
			note = "lifetime " + id.IDTokenExpiry.Sub(id.IDTokenIssuedAt).String()
		}
		add("Expires", id.IDTokenExpiry.Format(time.RFC3339), note)
	}
	// sub_attributes describes the subject: a Singpass person's identity details
	// (released per scope) or a Corppass entity's.
	attributeRows(add, "", "sub_attributes", id.SubjectAttributes())
	return hs
}

// modelledAttributes are the sub_attributes members singpass.SubjectAttributes
// has typed fields for; attributeRows shows any other member from Raw.
var modelledAttributes = map[string]bool{
	"account_type": true, "identity_number": true, "identity_coi": true, "name": true, "email": true, "mobileno": true,
	"entity_type": true, "entity_reg_number": true, "entity_coi": true, "entity_name": true, "entity_uen_status": true,
}

// attributeRows adds one row per set field of a, labelled with prefix, then
// any member the library doesn't model yet (so a new Singpass field still shows).
func attributeRows(add func(label, value, note string), prefix, note string, a singpass.SubjectAttributes) {
	for _, f := range []struct{ label, value string }{
		{"Name", a.Name}, {"Identity number", a.IdentityNumber}, {"Identity country", a.IdentityCOI},
		{"Account type", a.AccountType}, {"Email", a.Email}, {"Mobile no.", a.MobileNo},
		{"Entity name", a.EntityName}, {"Entity reg. number", a.EntityRegNumber}, {"Entity type", a.EntityType},
		{"Entity country", a.EntityCOI}, {"Entity UEN status", a.EntityUENStatus},
	} {
		add(prefix+f.label, f.value, note)
	}
	for _, k := range sortedKeys(a.Raw) {
		if !modelledAttributes[k] {
			add(prefix+myinfo.Label(k), claimString(a.Raw, k), note)
		}
	}
}

// claimString reads a scalar claim as text (string / number / bool), or "".
func claimString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

// sortedKeys returns a map's keys in sorted order, for stable rendering.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// myinfoSections turns the /userinfo person data into grouped sections — one per
// recognised Myinfo block — using the envelope-aware myinfo.Response accessor. Within a
// block, singleton leaf fields and nested singleton objects (CPF balances, NOA,
// entity address) become the section's definition-list Rows, while every repeated-
// record collection (CPF contribution history, appointments, shareholders,
// capitals, financials, licences, …) becomes its own Table — one column per leaf
// field, one row per record. Nothing is dropped from the structured view; the raw
// /userinfo JSON is rendered alongside (collapsed) for the full envelope. Works for
// personal Myinfo (person_info) and Myinfo Business (entity_info / …) alike.
func myinfoSections(m *myinfo.Response) []demoapp.Section {
	var secs []demoapp.Section
	if p := m.Person; p.Present() {
		secs = append(secs, personSection(p))
	}
	if e := m.Entity; e.Present() {
		secs = append(secs, genericSection("Entity", e))
	}
	if c := m.Corppass; c.Present() {
		secs = append(secs, genericSection("Corppass account", c))
	}
	// auth_info / tp_auth_info use the bespoke Corppass authorisation shape (not the
	// Myinfo envelope), so they get a dedicated builder driven by the library's
	// Data.Authorisations() accessor rather than the generic envelope renderer.
	if a := m.Auth; a.Present() {
		secs = append(secs, authSection("Authorisations", a))
	}
	if tp := m.TPAuth; tp.Present() {
		secs = append(secs, authSection("Third-party authorisations", tp))
	}
	// Drop blocks that produced no structured content. auth_info / tp_auth_info are
	// a bespoke non-envelope shape (Result_Set.ESrvc_Result[].Auth_Result_Set.Row[]
	// of bare scalars) the generic envelope renderer can't extract, so they'd render
	// as a bare heading with nothing under it — confusingly abutting the raw JSON
	// dump. Their data is still fully present in the collapsed raw /userinfo panel.
	kept := make([]demoapp.Section, 0, len(secs))
	for _, s := range secs {
		if len(s.Rows) == 0 && len(s.Groups) == 0 && len(s.Tables) == 0 {
			continue
		}
		s.Anchor = anchorize(s.Title)
		kept = append(kept, s)
	}
	return kept
}

// anchorize turns a section title into a lowercase URL-fragment slug (letters and
// digits kept, spaces/dashes collapsed to '-') for the block table-of-contents.
func anchorize(title string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(title) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// personSection builds the person_info block, leading with the headline identity
// leaves in a readable order, then folding in every remaining field verbatim. No
// values are synthesised: nested objects such as mobileno / regadd surface as their
// own sub-headed groups with each raw component ("Nbr", "Postal", …) shown as-is, so
// the structured view faithfully mirrors the raw /userinfo envelope.
func personSection(p myinfo.Data) demoapp.Section {
	sec := demoapp.Section{Title: "Person"}
	shown := map[string]bool{}
	for _, h := range []struct{ label, key string }{
		{"Name", "name"}, {"UINFIN", "uinfin"}, {"Sex", "sex"},
		{"Nationality", "nationality"}, {"Date of birth", "dob"}, {"Email", "email"},
	} {
		shown[h.key] = true
		if f := p.Field(h.key); f.Available() {
			sec.Rows = append(sec.Rows, demoapp.Highlight{Label: h.label, Value: f.String(), Note: sourceNote(f), NoteKind: sourceKind(f.SourceCode()), Updated: f.LastUpdated(), Confidential: f.ClassificationCode().Confidential()})
		}
	}
	fillBlock(&sec, p, shown)
	if s := p.EffectiveSource(); s != myinfo.SourceUnknown {
		sec.Badge = s.String()
		sec.BadgeKind = sourceKind(s)
	}
	dropRedundantNotes(sec.Rows, sec.Badge)
	return sec
}

// genericSection builds one block (entity_info, corppass_info, auth_info, …) with
// no special field ordering — every field is surfaced verbatim through fillBlock,
// so a nested object like entity_info.address renders as its own sub-headed group
// of raw component leaves (block / street / building / …), nothing synthesised.
func genericSection(title string, d myinfo.Data) demoapp.Section {
	sec := demoapp.Section{Title: title}
	fillBlock(&sec, d, nil)
	if s := d.EffectiveSource(); s != myinfo.SourceUnknown {
		sec.Badge = s.String()
		sec.BadgeKind = sourceKind(s)
	}
	dropRedundantNotes(sec.Rows, sec.Badge)
	return sec
}

// authSection renders a Corppass auth_info / tp_auth_info block as a single table
// of authorisations, via the library's myinfo.Data.Authorisations() accessor (which
// flattens the bespoke Result_Set.ESrvc_Result[].Auth_Result_Set.Row[] nesting).
// Columns are E-service · Role · Subject · Valid from · Valid to, with the
// often-empty Role / Subject columns dropped when no row populates them. These
// records carry no Myinfo envelope metadata, so there is no provenance badge. An
// empty result yields an empty Section, which myinfoSections then drops (the data
// stays in the raw /userinfo panel).
func authSection(title string, d myinfo.Data) demoapp.Section {
	sec := demoapp.Section{Title: title}
	auths := d.Authorisations()
	if len(auths) == 0 {
		return sec
	}
	hasRole, hasSubject := false, false
	for _, a := range auths {
		hasRole = hasRole || a.Role != ""
		hasSubject = hasSubject || a.Subject != ""
	}
	cols := []string{"E-service"}
	if hasRole {
		cols = append(cols, "Role")
	}
	if hasSubject {
		cols = append(cols, "Subject")
	}
	cols = append(cols, "Valid from", "Valid to")
	t := demoapp.Table{Title: "Authorisations", Columns: cols}
	for _, a := range auths {
		cells := []string{a.ESrvcID}
		if hasRole {
			cells = append(cells, a.Role)
		}
		if hasSubject {
			cells = append(cells, a.Subject)
		}
		cells = append(cells, a.StartDate, a.EndDate)
		t.Rows = append(t.Rows, demoapp.TableRow{Cells: cells})
	}
	sec.Tables = append(sec.Tables, t)
	return sec
}

// fillBlock partitions a block's top-level keys into the section: a leaf envelope
// becomes a Row (money-ish values separated); a repeated-record array becomes a
// Table; and a nested singleton object becomes its own sub-headed Group (so the
// block name is not repeated on every descendant leaf — "CPF balances › MA" turns
// into a "CPF balances" heading over an "MA" row). Keys in skip (already emitted as
// headline / convenience rows) are omitted.
func fillBlock(sec *demoapp.Section, d myinfo.Data, skip map[string]bool) {
	for _, k := range d.Keys() {
		if skip[k] {
			continue
		}
		switch d.Kind(k) {
		case myinfo.KindList:
			switch k {
			case "appointments":
				if t, ok := appointmentsTable(d); ok {
					sec.Tables = append(sec.Tables, t)
				}
			case "shareholders":
				if t, ok := shareholdersTable(d); ok {
					sec.Tables = append(sec.Tables, t)
				}
			default:
				if t, ok := buildTable(k, myinfo.Label(k), d.List(k)); ok {
					sec.Tables = append(sec.Tables, t)
				}
			}
		case myinfo.KindLeaf:
			if f := d.Field(k); f.Available() {
				label := myinfo.Label(k)
				sec.Rows = append(sec.Rows, demoapp.Highlight{Label: label, Value: formatAmount(label, f.String()), Note: sourceNote(f), NoteKind: sourceKind(f.SourceCode()), Updated: f.LastUpdated(), Confidential: f.ClassificationCode().Confidential()})
			}
		case myinfo.KindObject:
			obj := d.Object(k)
			g := demoapp.Group{Title: myinfo.Label(k)}
			fillGroup(&g, obj)
			if len(g.Rows) > 0 || len(g.Tables) > 0 {
				if s := obj.EffectiveSource(); s != myinfo.SourceUnknown {
					g.Badge = s.String()
					g.BadgeKind = sourceKind(s)
				}
				// Grouped datasets declare classification / lastupdated on the
				// container object (noa-basic, drivinglicence, …), not the value
				// leaves — read straight off the container Data.
				g.Updated = obj.LastUpdated()
				g.Confidential = obj.ClassificationCode().Confidential()
				dropRedundantNotes(g.Rows, g.Badge)
				sec.Groups = append(sec.Groups, g)
			}
		}
	}
}

// fillGroup fills one Group from a nested singleton object. Leaf envelopes become
// Rows; a repeated-record array becomes a Table (e.g. NOA history's noas); and a
// deeper nested object is flattened into the group's Rows with a short "parent ›
// child" path label (via collectLeaves), so a two-level nest like CPF Investment
// Scheme's "account" shows "Account › Agent bank code" without a further heading.
func fillGroup(g *demoapp.Group, obj myinfo.Data) {
	for _, k := range obj.Keys() {
		label := myinfo.Label(k)
		switch obj.Kind(k) {
		case myinfo.KindList:
			if t, ok := buildTable(k, label, obj.List(k)); ok {
				g.Tables = append(g.Tables, t)
			}
		case myinfo.KindLeaf:
			if f := obj.Field(k); f.Available() {
				g.Rows = append(g.Rows, demoapp.Highlight{Label: label, Value: formatAmount(label, f.String()), Note: sourceNote(f), NoteKind: sourceKind(f.SourceCode()), Updated: f.LastUpdated(), Confidential: f.ClassificationCode().Confidential()})
			}
		case myinfo.KindObject:
			prefix := label
			if transparentContainers[k] {
				prefix = "" // a wrapper that adds no information — don't extend the path
			}
			for _, lf := range collectLeaves(obj.Object(k), prefix) {
				g.Rows = append(g.Rows, demoapp.Highlight{Label: lf.label, Value: lf.value, Note: lf.note, NoteKind: lf.noteKind, Updated: lf.updated, Confidential: lf.confidential})
			}
		}
	}
}

// leaf is one data-bearing Myinfo leaf: its path label, resolved text value, an
// optional provenance note (and CSS kind), the envelope's lastupdated date, and
// whether the envelope classifies it as confidential.
type leaf struct {
	label, value, note, noteKind, updated string
	confidential                          bool
}

// transparentContainers are Corppass nested objects whose name adds nothing to a
// table column ("Company financial › Revenue" reads better as "Revenue"), so
// collectLeaves passes through them without extending the label. Appointments and
// shareholders, whose person/entity variants need the same treatment, are read
// through the library's typed Appointments / Shareholders instead.
var transparentContainers = map[string]bool{
	"company_financial": true,
}

// collectLeaves flattens a Myinfo object via the library's Data.Leaves into
// display rows with a "parent › child" path label (relative to prefix): list
// elements add a "#n" record suffix and transparent containers add nothing.
// Unavailable items are skipped; money-ish values get thousands separators.
func collectLeaves(d myinfo.Data, prefix string) []leaf {
	var out []leaf
	for _, lf := range d.Leaves() {
		f := lf.Field
		if !f.Available() {
			continue
		}
		var parts []string
		for _, k := range lf.Path {
			if n, err := strconv.Atoi(k); err == nil && len(parts) > 0 {
				parts[len(parts)-1] += fmt.Sprintf(" #%d", n+1) // Myinfo keys are never numeric
				continue
			}
			if transparentContainers[k] {
				continue
			}
			parts = append(parts, myinfo.Label(k))
		}
		label := joinLabel(prefix, strings.Join(parts, " › "))
		out = append(out, leaf{label, formatAmount(label, f.String()), sourceNote(f), sourceKind(f.SourceCode()), f.LastUpdated(), f.ClassificationCode().Confidential()})
	}
	return out
}

// moneyLabelKeywords are the label substrings (lowercased) that mark a leaf as a
// currency amount worth thousands-separating. Kept to Myinfo's actual money fields
// (CPF balances/contributions, capitals, financials, NOA income lines) so that
// identifiers, postal codes, years, quantities and dates are never touched.
var moneyLabelKeywords = []string{
	"amount", "revenue", "profit", "allocation", "allotted", "balance",
	"employment", "trade", "rent", "interest",
}

// formatAmount inserts thousands separators into a money-ish leaf value. It is
// gated on the label (moneyLabelKeywords) and on the value being a plain number —
// an integer part of at least four digits, optionally followed by a decimal
// fraction (CPF balances carry cents). Anything else is returned unchanged, so
// identifiers ("F1234567D"), postal codes, years ("2024") and dates pass through.
func formatAmount(label, value string) string {
	l := strings.ToLower(label)
	moneyish := false
	for _, kw := range moneyLabelKeywords {
		if strings.Contains(l, kw) {
			moneyish = true
			break
		}
	}
	if !moneyish {
		return value
	}
	intPart, frac := value, ""
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		intPart, frac = value[:dot], value[dot:] // frac keeps its leading '.'
	}
	if len(intPart) < 4 {
		return value
	}
	for _, r := range intPart {
		if r < '0' || r > '9' {
			return value
		}
	}
	// frac, if present, must be a single '.' followed only by digits — reject a
	// second dot (e.g. "1234.5.6") so a malformed value is left untouched.
	for i, r := range frac {
		if i == 0 {
			continue // the leading '.'
		}
		if r < '0' || r > '9' {
			return value
		}
	}
	// A present fraction is a currency amount → normalise to two decimals so cents
	// line up ("89365.6" → "89,365.60"). A whole number is left alone (never turned
	// into "1,360.00"), since not every money-labelled field is a cents amount.
	if len(frac) == 2 { // "." + one digit
		frac += "0"
	}
	n := len(intPart)
	var b strings.Builder
	for i, r := range intPart {
		if i > 0 && (n-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String() + frac
}

// tableColumnOrder gives a preferred column order per repeated-record collection
// (keyed by the raw block key). Columns named here float to the front in this
// order; any column not listed (e.g. a field Singpass later adds) keeps its
// first-seen position after them, so the tables stay readable without dropping
// anything. Labels are the post-transparent-container short forms.
var tableColumnOrder = map[string][]string{
	"capitals":   {"Share type", "Issued amount", "Paid up amount", "Share allotted number", "Currency"},
	"financials": {"Current period start date", "Current period end date", "Revenue", "Profit loss before tax", "Profit loss after tax", "Is audited", "Currency"},
	"licences":   {"Licence name", "Issuance agency", "Issue date", "Expiry date"},
	// Personal-Myinfo nested collections. "history" is shared by cpfcontributions
	// (month/date/employer/amount) and cpfemployers; the union of both floats these
	// front, with any employer-history-only column trailing in first-seen order.
	"history": {"Month", "Date", "Employer", "Amount"},
	// noahistory.noas[] — one record per year of assessment.
	"noas": {"Year of assessment", "Type", "Category", "Amount", "Employment", "Trade", "Rent", "Interest", "Tax clearance"},
}

// buildTable turns an array of record objects into a Table: the columns are the
// union of leaf paths across all records (so heterogeneous records — e.g.
// individual vs entity appointments — still line up), ordered by tableColumnOrder
// for the given block key (falling back to first-seen order), and each row fills
// its cells by column. It reports ok=false when the array carries no object
// records with data (e.g. an empty array or scalar elements), so the caller can
// skip it.
func buildTable(key, title string, list []myinfo.Data) (demoapp.Table, bool) {
	var cols []string
	seen := map[string]bool{}
	var recs []map[string]string
	for _, el := range list {
		if !el.Present() {
			continue
		}
		leaves := collectLeaves(el, "")
		if len(leaves) == 0 {
			continue
		}
		cells := make(map[string]string, len(leaves))
		for _, lf := range leaves {
			if !seen[lf.label] {
				seen[lf.label] = true
				cols = append(cols, lf.label)
			}
			cells[lf.label] = lf.value
		}
		recs = append(recs, cells)
	}
	if len(recs) == 0 {
		return demoapp.Table{}, false
	}
	cols = orderColumns(key, cols)
	t := demoapp.Table{Title: title, Columns: cols}
	if s := myinfo.CommonSource(list...); s != myinfo.SourceUnknown {
		t.Badge = s.String()
		t.BadgeKind = sourceKind(s)
	}
	for _, cells := range recs {
		row := make([]string, len(cols))
		for i, c := range cols {
			row[i] = cells[c]
		}
		t.Rows = append(t.Rows, demoapp.TableRow{Cells: row})
	}
	return t, true
}

// appointmentsTable renders entity_info appointments from the library's typed
// records, which flatten the person / entity appointee variants.
func appointmentsTable(entity myinfo.Data) (demoapp.Table, bool) {
	recs := entity.Appointments()
	if len(recs) == 0 {
		return demoapp.Table{}, false
	}
	t := demoapp.Table{Title: "Appointments", Columns: []string{"Position", "Name", "Appointee", "ID / registration no.", "Nationality", "Category", "Appointment date"}}
	datas := make([]myinfo.Data, 0, len(recs))
	for _, a := range recs {
		t.Rows = append(t.Rows, demoapp.TableRow{Cells: []string{a.Position, a.Appointee.Name, partyKind(a.Appointee), partyID(a.Appointee), a.Appointee.Nationality, a.Category, a.AppointmentDate}})
		datas = append(datas, a.Data)
	}
	badge(&t, datas)
	dropEmptyColumns(&t)
	return t, true
}

// shareholdersTable renders entity_info shareholders from the library's typed
// records.
func shareholdersTable(entity myinfo.Data) (demoapp.Table, bool) {
	recs := entity.Shareholders()
	if len(recs) == 0 {
		return demoapp.Table{}, false
	}
	t := demoapp.Table{Title: "Shareholders", Columns: []string{"Name", "Holder", "ID / registration no.", "Allocation", "Share type", "Currency", "Category"}}
	datas := make([]myinfo.Data, 0, len(recs))
	for _, sh := range recs {
		t.Rows = append(t.Rows, demoapp.TableRow{Cells: []string{sh.Holder.Name, partyKind(sh.Holder), partyID(sh.Holder), formatAmount("allocation", sh.Allocation), sh.ShareType, sh.Currency, sh.Category}})
		datas = append(datas, sh.Data)
	}
	badge(&t, datas)
	dropEmptyColumns(&t)
	return t, true
}

func partyKind(p myinfo.Party) string {
	if p.Individual {
		return "Individual"
	}
	return "Entity"
}

func partyID(p myinfo.Party) string {
	if p.Individual {
		return strings.TrimSpace(p.IDNumber + " " + p.IDType)
	}
	return p.RegistrationNumber
}

// dropEmptyColumns removes columns no row fills, so sparse records don't show
// a column of dashes.
func dropEmptyColumns(t *demoapp.Table) {
	keep := make([]bool, len(t.Columns))
	for _, r := range t.Rows {
		for i, c := range r.Cells {
			keep[i] = keep[i] || c != ""
		}
	}
	var cols []string
	for i, c := range t.Columns {
		if keep[i] {
			cols = append(cols, c)
		}
	}
	for ri, r := range t.Rows {
		var cells []string
		for i, c := range r.Cells {
			if keep[i] {
				cells = append(cells, c)
			}
		}
		t.Rows[ri].Cells = cells
	}
	t.Columns = cols
}

// badge sets a table's provenance badge from its records' common source.
func badge(t *demoapp.Table, records []myinfo.Data) {
	if s := myinfo.CommonSource(records...); s != myinfo.SourceUnknown {
		t.Badge = s.String()
		t.BadgeKind = sourceKind(s)
	}
}

// orderColumns reorders cols by the preference list for key: listed columns first
// (in preference order), then the remaining columns in their original first-seen
// order. Unknown keys return cols unchanged.
func orderColumns(key string, cols []string) []string {
	pref, ok := tableColumnOrder[key]
	if !ok {
		return cols
	}
	rank := make(map[string]int, len(pref))
	for i, c := range pref {
		rank[c] = i
	}
	ordered := make([]string, len(cols))
	copy(ordered, cols)
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, iok := rank[ordered[i]]
		rj, jok := rank[ordered[j]]
		if iok && jok {
			return ri < rj
		}
		if iok != jok {
			return iok // a ranked column sorts before an unranked one
		}
		return false // both unranked: preserve first-seen order
	})
	return ordered
}

// dropRedundantNotes blanks any row Note that just restates label (the group- or
// section-level badge), so a uniform provenance is stated once at the heading
// rather than repeated on every row. A row whose source genuinely differs from the
// badge keeps its note, making the exception visible.
func dropRedundantNotes(rows []demoapp.Highlight, label string) {
	if label == "" {
		return
	}
	for i := range rows {
		if rows[i].Note == label {
			rows[i].Note = ""
			rows[i].NoteKind = ""
		}
	}
}

// joinLabel builds a "parent › child" path label (or just child at the top).
func joinLabel(prefix, child string) string {
	if prefix == "" {
		return child
	}
	return prefix + " › " + child
}

// sourceNote annotates a leaf with its Myinfo provenance (government-verified /
// user-provided / …) when present; nested leaves often inherit source from their
// parent container and carry none of their own, in which case the note is blank.
func sourceNote(f myinfo.Field) string {
	if s := f.SourceCode(); s != myinfo.SourceUnknown {
		return s.String()
	}
	return ""
}

// sourceKind maps a Myinfo source to the provenance CSS class the template uses to
// colour badges and notes: "gov" (government-verified, authoritative), "userv"
// (user-provided verified, authoritative), "user" (user-provided, self-declared —
// amber), "na" (not-applicable, grey), or "" (unknown — no colour).
func sourceKind(s myinfo.Source) string {
	switch s {
	case myinfo.SourceGovernmentVerified:
		return "gov"
	case myinfo.SourceUserProvidedVerified:
		return "userv"
	case myinfo.SourceUserProvided:
		return "user"
	case myinfo.SourceNotApplicable:
		return "na"
	default:
		return ""
	}
}

// homeApps maps the web helper's apps to the demo's landing-page view model.
func homeApps(apps []*web.App) []demoapp.HomeApp {
	out := make([]demoapp.HomeApp, 0, len(apps))
	for _, a := range apps {
		out = append(out, demoapp.HomeApp{Name: a.Name, Title: a.Title})
	}
	return out
}
