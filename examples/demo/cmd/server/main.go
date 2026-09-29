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
				pd.Sections = typedSections(id)
				pd.Untyped, pd.ItemCount = untypedItems(id.Myinfo)
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
