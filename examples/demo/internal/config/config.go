// Package config loads the demo relying parties' configuration from the
// environment. The demo can run three relying parties at once — "login"
// (Singpass Login) and "mi" (Myinfo person data) on the Singpass FAPI
// issuer, and "mib" (Myinfo Business corporate data) on the Corppass
// FAPI issuer — each with its own client_id and key pair. Every value a real
// integration must supply (client IDs, key material, redirect URIs) is read
// here so the rest of the app never reaches for os.Getenv itself.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the fully-resolved configuration for one running instance. It
// holds the values shared by every relying party plus the list of apps
// that are actually enabled (an app is enabled when its client_id is set).
type Config struct {
	// BaseURL is this app's own externally-reachable base URL. Each app's
	// RedirectURI is derived from it (<base>/<app>/callback) and must
	// exactly match the redirect URI registered for that client.
	BaseURL string

	// Addr is the TCP address the HTTP server listens on: APP_ADDR if set,
	// else ":$PORT" (the port Cloud Run and similar platforms inject), else
	// ":8088".
	Addr string

	// LogJSON switches logging to JSON lines in the shape Cloud Logging parses
	// ("severity" / "message"), from LOG_FORMAT=json.
	LogJSON bool

	// HTTPTimeout bounds each outbound call to Singpass (PAR, token,
	// discovery, JWKS, userinfo).
	HTTPTimeout time.Duration

	// Debug enables outbound PAR/token/userinfo request logging in the singpass
	// client (set from SP_DEBUG_HTTP). The request dump includes the client
	// assertion — staging only.
	Debug bool

	// Apps are the enabled relying parties, in display order.
	Apps []AppConfig
}

// AppConfig is one relying party's configuration.
type AppConfig struct {
	// Name is the URL/route slug and cookie namespace: "login", "mi" (Myinfo),
	// or "mib" (Myinfo Business). It appears in the redirect URI
	// (<base>/<name>/callback), and Singpass/Corppass reject redirect URIs
	// containing "singpass", "corppass" or "myinfo" — hence the terse slugs.
	Name string

	// Title is the human-facing label shown in the UI.
	Title string

	// Issuer is the FAPI 2.0 issuer identifier (Singpass for login/myinfo,
	// Corppass for myinfobiz). Its ".well-known/openid-configuration" is
	// fetched at startup — every endpoint (auth, token, PAR, jwks, userinfo)
	// comes from that document.
	Issuer string

	// ClientID is the client_id Singpass issued for THIS client.
	ClientID string

	// RedirectURI is derived as <BaseURL>/<Name>/callback.
	RedirectURI string

	// AuthContextType is the authentication_context_type — the flow the user
	// is authenticating for (e.g. "APP_AUTHENTICATION_DEFAULT"). It is a
	// *Login-app-only* parameter on both Singpass and Corppass: the servers
	// reject it on Myinfo / Myinfo Business requests, so it is set only for
	// "login" and left empty for "mi" and "mib".
	AuthContextType string

	// AcrValues is the optional requested level of assurance
	// (urn:singpass:authentication:loa:2 / :3), from SINGPASS_ACR_VALUES. It
	// may ONLY be sent by clients Singpass has whitelisted for it; empty means
	// "do not send". Set for the Singpass apps ("login", "mi") only — the
	// values are Singpass URNs, so "mib" (Corppass) never sends them.
	AcrValues string

	// Scopes requested at authorization; must include "openid".
	Scopes []string

	// SigKeyPath / SigKID: EC P-256 key (PKCS#8 PEM) registered under
	// "use":"sig"; signs private_key_jwt client assertions.
	SigKeyPath string
	SigKID     string

	// EncKeyPath / EncKID: EC P-256 key (PKCS#8 PEM) registered under
	// "use":"enc"; Singpass encrypts the id_token (and, for Myinfo, the
	// userinfo response) to it, and we decrypt with it.
	EncKeyPath string
	EncKID     string

	// FetchUserInfo makes the app call the FAPI /userinfo endpoint after
	// token exchange to retrieve Myinfo person data. True for "mi" and
	// "mib" (shown in startup logging; the singpass product constructor sets
	// the client behaviour).
	FetchUserInfo bool
}

const (
	// defaultSingpassIssuer is the Singpass FAPI 2.0 issuer (Login + Myinfo).
	defaultSingpassIssuer = "https://stg-id.singpass.gov.sg/fapi"
	// defaultCorppassIssuer is the Corppass FAPI 2.0 issuer (Myinfo
	// Business). Note it has no "/fapi" path suffix, unlike Singpass, and it
	// is a separate authorization server with its own discovery document.
	defaultCorppassIssuer = "https://stg-id.corppass.gov.sg"
)

// Load reads configuration from the environment, applying the documented
// defaults for a Singpass staging integration. It enables each relying
// party whose *_CLIENT_ID is set; at least one must be.
func Load() (Config, error) {
	cfg := Config{
		BaseURL:     env("APP_BASE_URL", "http://localhost:8088"),
		Addr:        env("APP_ADDR", ":"+env("PORT", "8088")),
		HTTPTimeout: 15 * time.Second,
		Debug:       os.Getenv("SP_DEBUG_HTTP") != "",
		LogJSON:     os.Getenv("LOG_FORMAT") == "json",
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	sharedIssuer := env("SINGPASS_ISSUER", defaultSingpassIssuer)
	singpassAcr := os.Getenv("SINGPASS_ACR_VALUES")

	// Login relying party: authentication only. authentication_context_type
	// is a Login-app parameter (Singpass rejects it on Myinfo requests).
	login := AppConfig{
		Name:            "login",
		Title:           "Singpass Login",
		Issuer:          env("SINGPASS_LOGIN_ISSUER", sharedIssuer),
		ClientID:        os.Getenv("SINGPASS_LOGIN_CLIENT_ID"),
		Scopes:          splitScopes(env("SINGPASS_LOGIN_SCOPES", "email mobileno name openid user.identity")),
		AuthContextType: env("SINGPASS_AUTH_CONTEXT_TYPE", "APP_AUTHENTICATION_DEFAULT"),
		AcrValues:       singpassAcr,
		SigKeyPath:      env("SINGPASS_LOGIN_SIG_KEY_PATH", "keys/login/sig.pem"),
		SigKID:          env("SINGPASS_LOGIN_SIG_KID", "login-sig-1"),
		EncKeyPath:      env("SINGPASS_LOGIN_ENC_KEY_PATH", "keys/login/enc.pem"),
		EncKID:          env("SINGPASS_LOGIN_ENC_KID", "login-enc-1"),
	}

	// Myinfo relying party: authentication + person data via /userinfo.
	myinfo := AppConfig{
		Name:          "mi",
		Title:         "Myinfo",
		Issuer:        env("MYINFO_ISSUER", sharedIssuer),
		ClientID:      os.Getenv("MYINFO_CLIENT_ID"),
		AcrValues:     singpassAcr,
		Scopes:        splitScopes(env("MYINFO_SCOPES", "academicqualifications.certificates academicqualifications.transcripts aliasname birthcountry chas childrenbirthrecords.aliasname childrenbirthrecords.birthcertno childrenbirthrecords.dialect childrenbirthrecords.dob childrenbirthrecords.hanyupinyinaliasname childrenbirthrecords.hanyupinyinname childrenbirthrecords.lifestatus childrenbirthrecords.marriedname childrenbirthrecords.name childrenbirthrecords.race childrenbirthrecords.secondaryrace childrenbirthrecords.sex childrenbirthrecords.sgcitizenatbirthind childrenbirthrecords.tob childrenbirthrecords.vaccinationrequirements countryofmarriage cpfbalances.ma cpfbalances.oa cpfbalances.ra cpfbalances.sa cpfcontributions cpfemployers cpfhousingwithdrawal cpfinvestmentscheme.account cpfinvestmentscheme.saqparticipationstatus cpfinvestmentscheme.sdsnetshareholdingqty dialect divorcedate dob drivinglicence.comstatus drivinglicence.disqualification.enddate drivinglicence.disqualification.startdate drivinglicence.pdl.classes drivinglicence.pdl.expirydate drivinglicence.pdl.validity drivinglicence.photocardserialno drivinglicence.qdl.classes drivinglicence.qdl.expirydate drivinglicence.qdl.validity drivinglicence.revocation.enddate drivinglicence.revocation.startdate drivinglicence.suspension.enddate drivinglicence.suspension.startdate drivinglicence.totaldemeritpoints email employment employmentsector hanyupinyinaliasname hanyupinyinname hdbownership.address hdbownership.balanceloanrepayment hdbownership.dateofownershiptransfer hdbownership.dateofpurchase hdbownership.hdbtype hdbownership.leasecommencementdate hdbownership.loangranted hdbownership.monthlyloaninstalment hdbownership.noofowners hdbownership.originalloanrepayment hdbownership.outstandinginstalment hdbownership.outstandingloanbalance hdbownership.purchaseprice hdbownership.termoflease hdbtype housingtype ltavocationallicences.bavl.expirydate ltavocationallicences.bavl.licencename ltavocationallicences.bavl.status ltavocationallicences.bavl.vocationallicencenumber ltavocationallicences.bdvl.expirydate ltavocationallicences.bdvl.licencename ltavocationallicences.bdvl.status ltavocationallicences.bdvl.vocationallicencenumber ltavocationallicences.odvl.expirydate ltavocationallicences.odvl.licencename ltavocationallicences.odvl.status ltavocationallicences.odvl.vocationallicencenumber ltavocationallicences.pdvl.expirydate ltavocationallicences.pdvl.licencename ltavocationallicences.pdvl.status ltavocationallicences.pdvl.vocationallicencenumber ltavocationallicences.tdvl.expirydate ltavocationallicences.tdvl.licencename ltavocationallicences.tdvl.status ltavocationallicences.tdvl.vocationallicencenumber marital marriagecertno marriagedate marriedname merdekagen.eligibility mobileno name nationality noa noa-basic noahistory noahistory-basic occupation openid ownerprivate passexpirydate passportexpirydate passportnumber passstatus passtype pioneergen.eligibility race regadd residentialstatus secondaryrace sex sponsoredchildrenrecords.aliasname sponsoredchildrenrecords.birthcountry sponsoredchildrenrecords.dialect sponsoredchildrenrecords.dob sponsoredchildrenrecords.hanyupinyinaliasname sponsoredchildrenrecords.hanyupinyinname sponsoredchildrenrecords.lifestatus sponsoredchildrenrecords.marriedname sponsoredchildrenrecords.name sponsoredchildrenrecords.nationality sponsoredchildrenrecords.nric sponsoredchildrenrecords.race sponsoredchildrenrecords.residentialstatus sponsoredchildrenrecords.scprgrantdate sponsoredchildrenrecords.secondaryrace sponsoredchildrenrecords.sex sponsoredchildrenrecords.vaccinationrequirements uinfin vehicles.attachment1 vehicles.attachment2 vehicles.attachment3 vehicles.chassisno vehicles.co2emission vehicles.coecategory vehicles.coeexpirydate vehicles.coemission vehicles.effectiveownership vehicles.enginecapacity vehicles.engineno vehicles.firstregistrationdate vehicles.iulabelno vehicles.make vehicles.maximumladenweight vehicles.maximumunladenweight vehicles.minimumparfbenefit vehicles.model vehicles.motorno vehicles.nooftransfers vehicles.noxemission vehicles.openmarketvalue vehicles.originalregistrationdate vehicles.pmemission vehicles.powerrate vehicles.primarycolour vehicles.propellant vehicles.quotapremium vehicles.roadtaxexpirydate vehicles.scheme vehicles.secondarycolour vehicles.status vehicles.thcemission vehicles.type vehicles.vehicleno vehicles.vpc vehicles.yearofmanufacture")),
		SigKeyPath:    env("MYINFO_SIG_KEY_PATH", "keys/myinfo/sig.pem"),
		SigKID:        env("MYINFO_SIG_KID", "myinfo-sig-1"),
		EncKeyPath:    env("MYINFO_ENC_KEY_PATH", "keys/myinfo/enc.pem"),
		EncKID:        env("MYINFO_ENC_KID", "myinfo-enc-1"),
		FetchUserInfo: true,
	}

	// Myinfo Business relying party: the corporate Myinfo product, on the
	// Corppass FAPI 2.0 authorization server. Same protocol as Singpass
	// (PAR, DPoP, private_key_jwt, PKCE, JWE id_token + userinfo), different
	// issuer and scope namespaces. authentication_context_type is likewise a
	// Corppass-Login-only parameter and is omitted here. Its /userinfo returns
	// several blocks (entity_info / person_info / corppass_info / auth_info /
	// tp_auth_info); the scopes below request one of each as a starting point.
	myinfobiz := AppConfig{
		Name:          "mib",
		Title:         "Myinfo Business",
		Issuer:        env("MYINFO_BIZ_ISSUER", defaultCorppassIssuer),
		ClientID:      os.Getenv("MYINFO_BIZ_CLIENT_ID"),
		Scopes:        splitScopes(env("MYINFO_BIZ_SCOPES", "openid entity.basic_profile.name user.name corppass.email")),
		SigKeyPath:    env("MYINFO_BIZ_SIG_KEY_PATH", "keys/myinfobiz/sig.pem"),
		SigKID:        env("MYINFO_BIZ_SIG_KID", "myinfobiz-sig-1"),
		EncKeyPath:    env("MYINFO_BIZ_ENC_KEY_PATH", "keys/myinfobiz/enc.pem"),
		EncKID:        env("MYINFO_BIZ_ENC_KID", "myinfobiz-enc-1"),
		FetchUserInfo: true,
	}

	for _, app := range []AppConfig{login, myinfo, myinfobiz} {
		if app.ClientID == "" {
			continue // not onboarded / not enabled
		}
		if !containsScope(app.Scopes, "openid") {
			return Config{}, fmt.Errorf("config: %s scopes must include \"openid\"", app.Name)
		}
		app.RedirectURI = cfg.BaseURL + "/" + app.Name + "/callback"
		cfg.Apps = append(cfg.Apps, app)
	}

	if len(cfg.Apps) == 0 {
		return Config{}, fmt.Errorf("config: set SINGPASS_LOGIN_CLIENT_ID, MYINFO_CLIENT_ID and/or MYINFO_BIZ_CLIENT_ID to enable at least one relying party")
	}
	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func splitScopes(s string) []string {
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
