// Package singpass wires the FAPIgo relying-party engine
// (github.com/idfoundry/fapigo/client) to talk to the Singpass / Corppass FAPI
// 2.0 profile. FAPIgo does all of the protocol work; this package supplies the
// pieces FAPIgo leaves to the embedder — a key manager, a keys.Decrypter for the
// encrypted id_token, and a session store — and encodes the Singpass-specific
// choices (PAR parameters, algorithm suite, /userinfo handling) so a relying
// party can integrate Singpass Login, Myinfo, and Myinfo Business without
// rediscovering them.
//
// Unofficial: this is a community library, not affiliated with or endorsed by
// GovTech, Singpass or Corppass.
//
// Most callers should use the per-product constructors NewLogin, NewMyinfo, and
// NewMyinfoBusiness (see products.go), which take just key material and a
// client_id. New is the lower-level constructor for full control or a
// non-standard product.
//
// A login is BeginLogin, which returns the redirect URL and the login's state
// to keep with the browser, then Complete at the callback, given that state.
//
// The defaults target staging. Set Environment: Production in the product
// options for the production issuers and AssuranceProduction, which requires a
// durable Dependencies.Sessions store (see the sqlstore package) and durable
// keys (Dependencies.KeyCustody). A stale or replayed login is reported as
// ErrLoginExpired and a cancelled or denied one as *DeniedError; ErrorCode and
// IsTemporary read the error Singpass or Corppass sent.
package singpass

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"

	"github.com/osanderson/singpass-client-go/myinfo"
)

// defaultHTTPTimeout bounds each outbound call to the authorization server when
// Dependencies.HTTPTimeout is left zero and no HTTPClient is supplied.
const defaultHTTPTimeout = 15 * time.Second

// Options is the protocol configuration for a Client: the behaviour knobs that
// describe how this relying party talks to its authorization server. The
// injectable collaborators (keys, session store, HTTP client, …) live in
// Dependencies. The per-product constructors in products.go fill most of this
// in for you.
type Options struct {
	Name            string   // app slug ("login" / "myinfo"), for logging and Identity
	Issuer          string   // FAPI issuer, e.g. https://stg-id.singpass.gov.sg/fapi
	ClientID        string   // client_id issued by the authorization server
	RedirectURI     string   // must match what is registered with the server
	Scopes          []string // includes "openid"
	AuthContextType string   // authentication_context_type (Login apps only; rejected on Myinfo)
	// AuthContextMessage is the optional authentication_context_message
	// (Login apps only): up to 100 printable ASCII characters, excluding
	// < > \ and `, shown to the user while they authenticate.
	AuthContextMessage string
	// AppClaimedHTTPS sends redirect_uri_https_type=app_claimed_https, for a
	// RedirectURI that is a mobile app's App Link / Universal Link.
	AppClaimedHTTPS bool
	// AppLaunchURL is the optional app_launch_url: the iOS App Link that
	// returns the user to your app after authenticating in the Singpass app,
	// for a journey that starts and ends in an iOS app. Must be https.
	AppLaunchURL  string
	AcrValues     string // optional requested level of assurance; "" to omit
	FetchUserInfo bool   // call the FAPI /userinfo endpoint after token exchange (Myinfo)
	// TolerateUserInfoSubjectClientID accepts a /userinfo "sub" equal to the
	// client_id (as well as the id_token sub) — a deviation from OIDC Core
	// §5.3.2 that Corppass Myinfo Business used to have and has since fixed.
	// Off by default; see MyinfoBusinessOptions.TolerateUserInfoSubjectClientID.
	TolerateUserInfoSubjectClientID bool
}

// Dependencies are a Client's injected collaborators. Only Keys and Decryption
// are required; every other field's zero value selects a sensible staging
// default, so the simple path is Dependencies{Keys: km, Decryption: dec}. A
// production deployment sets the fields it needs to harden — most importantly a
// durable Sessions store together with Assurance: AssuranceProduction.
type Dependencies struct {
	// Keys performs this client's signing operations (client assertion + DPoP
	// proof). Required. See NewKeyManager.
	Keys KeyManager

	// Decryption recovers the content-encryption key of the encrypted id_token
	// (and /userinfo response). Required. See NewECDHDecrypter.
	Decryption Decrypter

	// KeyCustody declares how the private keys behind Keys and Decryption are
	// held. AssuranceProduction requires Durable: the keys survive a restart
	// (loaded from a file or secret store, or held in an HSM or KMS), as they
	// must anyway once Singpass has your JWKS. It applies to the Keys and
	// Decryption this package builds (the product constructors, NewKeyManager,
	// NewECDHDecrypter, …); one built with FAPIgo directly declares its own
	// custody with keys.DeclareCustody.
	KeyCustody KeyCustody

	// Sessions persists in-progress authorization-flow state. Nil installs
	// NewMemorySessionStore(0): per-process and non-durable, but expired
	// sessions are dropped and pending logins are capped, so abandoned logins
	// cannot grow memory without bound. Fine for a single instance /
	// development; refused under AssuranceProduction.
	Sessions SessionStore

	// Assurance gates how strict FAPIgo's dependency validation is. Zero means
	// AssuranceDevelopment (permits the in-memory Sessions default).
	// AssuranceProduction requires a Sessions store declaring StoreAssurance
	// (Durable + AtomicConsume), so the in-memory default is refused.
	Assurance AssuranceLevel

	// HTTPClient is the base client for discovery, JWKS, PAR, token and
	// /userinfo calls. Nil builds &http.Client{Timeout: HTTPTimeout}.
	HTTPClient *http.Client

	// HTTPTimeout bounds each outbound call. Zero means defaultHTTPTimeout. It
	// is also folded into the default Limits (below) and the default HTTPClient.
	HTTPTimeout time.Duration

	// Clock supplies the current time. Nil means client.SystemClock{}.
	Clock Clock

	// Random is the randomness source for state/nonce/PKCE. Nil means
	// crypto/rand.Reader, which AssuranceProduction requires.
	Random io.Reader

	// BeginLoginRetries is how many times BeginLogin retries a pushed
	// authorization request that failed temporarily (see IsTemporary), with
	// exponential backoff from 250ms, within the request's context. Zero
	// means no retries; Singpass allows up to 3.
	BeginLoginRetries int

	// Limits bounds token lifetimes and JOSE/HTTP sizes. Nil means
	// RecommendedLimits(HTTPTimeout).
	Limits *Limits

	// Algorithms overrides the FAPI algorithm suite. Nil selects the
	// Singpass/Corppass suite (ES256; id_token ECDH-ES+A256KW / A256CBC-HS512;
	// and, when Options.FetchUserInfo is set, /userinfo A256GCM). When you set
	// this, it is used verbatim and the FetchUserInfo augmentation is skipped —
	// declare the /userinfo algorithms yourself.
	Algorithms *Algorithms

	// AllowLoopbackHTTP permits http:// issuer and endpoint URLs on a loopback
	// host — localhost, a name under .localhost, 127.0.0.0/8 or ::1 — for a
	// local fake authorization server such as singpasstest's. Any other name
	// stays refused even if it resolves to a loopback address, so a URL
	// taken from a response can't reach services on this machine.
	// Development only: New refuses it together with AssuranceProduction.
	AllowLoopbackHTTP bool

	// Debug, when true, logs outbound PAR/token/userinfo requests and responses
	// (method, URL, form body, sizes) via Logger. The request dump includes the
	// client_assertion, the authorization code and the PKCE verifier, so New
	// refuses it under AssuranceProduction: enable it only against staging.
	Debug bool

	// Logger receives Debug output and internal warnings. Nil means
	// slog.Default().
	Logger *slog.Logger
}

// Client is a relying party (Login, Myinfo, or Myinfo Business). It is safe for
// concurrent use.
type Client struct {
	engine    *client.Client
	name      string
	scopes    []string
	acrValues []string // requested acr_values, if any (sent only when non-empty)
	// authContext, appClaimed and appLaunchURL are the Singpass-specific PAR
	// parameters (see loginExtensions).
	authContext  LoginContext
	appClaimed   bool
	appLaunchURL string

	// fetchUserInfo makes Complete call the engine's native FetchUserInfo
	// after token exchange to retrieve Myinfo person data.
	fetchUserInfo bool

	// httpClient is the base HTTP client, for CheckPublishedJWKS.
	httpClient *http.Client

	// retries is Dependencies.BeginLoginRetries.
	retries int

	// decryption and encAlg let PublicJWKS publish a NewRotatingDecrypter's
	// additional encryption keys, which FAPIgo's own JWKS doesn't include.
	decryption keys.Decrypter
	encAlg     fapi.KeyManagementAlgorithm
}

// Identity is the authenticated result of a completed login.
type Identity struct {
	// App is the relying party that produced this identity ("login" / "myinfo").
	App string

	// Subject is the "sub" — the identifier for this person, as validated from
	// the id_token (never an unverified claim).
	Subject string

	// Claims is the full decoded id_token payload, for display. It has already
	// been signature-, issuer-, audience- and nonce-validated by FAPIgo before
	// we ever decode it here.
	Claims map[string]any

	// Scope granted by the authorization server. When the token response omits
	// the optional "scope" (RFC 6749 §5.1 permits this when the granted scope
	// equals the requested scope — as Singpass Myinfo does), this falls back to
	// the requested scope, which under that rule is the granted scope.
	Scope string

	// IDTokenIssuedAt and IDTokenExpiry are the validated id_token's "iat" and
	// "exp" (FAPIgo has already enforced both against the clock). Captured so
	// the caller can report the token's exact lifetime (exp − iat).
	IDTokenIssuedAt time.Time
	IDTokenExpiry   time.Time

	// Myinfo is the envelope-aware view of the /userinfo person / organisation
	// data (decrypted and inner-JWS-verified). Nil for the Login app, which
	// makes no userinfo call; non-nil for Myinfo / Myinfo Business, with the
	// blocks the response carried populated (see myinfo.Response).
	Myinfo *myinfo.Response
}

// New discovers the FAPI metadata and constructs a ready-to-use relying-party
// client. deps.Keys and deps.Decryption are required; every other Dependencies
// field defaults to a staging-appropriate value when left zero (see
// Dependencies). Most callers should prefer NewLogin / NewMyinfo /
// NewMyinfoBusiness.
func New(ctx context.Context, opts Options, deps Dependencies) (*Client, error) {
	if err := checkDependencies(opts, deps); err != nil {
		return nil, err
	}
	deps = withKeyCustody(deps, deps.KeyCustody)
	if deps.HTTPTimeout == 0 {
		deps.HTTPTimeout = defaultHTTPTimeout
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if err := checkAssurance(opts, deps); err != nil {
		return nil, err
	}

	var urlOpts []fapi.URLOption
	if deps.AllowLoopbackHTTP {
		urlOpts = append(urlOpts, fapi.AllowLoopbackHTTP())
	}
	issuer, err := fapi.ParseIssuerURL(opts.Issuer, urlOpts...)
	if err != nil {
		return nil, fmt.Errorf("singpass: parse issuer: %w", err)
	}

	// The base HTTP client, shared by the discovery/JWKS fetcher and the
	// engine's PAR/token/userinfo calls.
	base := deps.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: deps.HTTPTimeout}
	}
	discovered, issuerKeys, err := discover(ctx, base, issuer, deps, urlOpts)
	if err != nil {
		return nil, err
	}

	// Myinfo needs the UserInfo endpoint. FAPIgo calls it natively
	// (Client.FetchUserInfo) once we declare the response algorithms (below);
	// the endpoint itself rides along in discovered.Endpoints like every other
	// endpoint. Fail fast here if the issuer advertises none — an endpoint-
	// presence check NewFromDiscovery (below) does not make.
	if opts.FetchUserInfo && discovered.Endpoints.UserInfo.IsZero() {
		return nil, fmt.Errorf("singpass: issuer advertises no userinfo_endpoint but FetchUserInfo is set")
	}

	cfg := engineConfig(opts, deps, issuer, discovered)

	// The engine's PAR/token/userinfo HTTP client. A transparent wrapper over
	// base that logs only when deps.Debug is set (otherwise it just delegates),
	// so the default behaviour is a plain pass-through.
	httpClient := newLoggingHTTPClient(base, deps.Debug, deps.Logger)

	// NewFromDiscovery is New plus discovery-only checks: cfg.Issuer must
	// equal the discovered issuer; it runs discovered.SupportsAlgorithms(
	// cfg.Algorithms) — so a declared-but-unadvertised algorithm fails
	// cleanly at startup instead of as an opaque signature/JWE-decrypt
	// failure on the first live response; and it upgrades
	// cfg.AuthorizationResponseIssPolicy to RequireAuthorizationResponseIss from
	// discovered.AuthorizationResponseIssSupported (RFC 9207 §2.4), on top of the
	// TolerateAbsent baseline set in engineConfig. cfg.Endpoints is already
	// set, so it is used as given.
	engine, err := client.NewFromDiscovery(discovered, cfg, engineDependencies(deps, issuerKeys, httpClient))
	if err != nil {
		return nil, fmt.Errorf("singpass: construct client: %w", err)
	}

	// acr_values is opt-in: Singpass rejects it unless the client is
	// whitelisted, so it is sent only when configured. The other
	// Singpass-specific PAR parameters are built per login (loginExtensions).
	var acrValues []string
	if v := strings.TrimSpace(opts.AcrValues); v != "" {
		acrValues = strings.Fields(v)
	}

	return &Client{
		engine:        engine,
		name:          opts.Name,
		scopes:        opts.Scopes,
		acrValues:     acrValues,
		authContext:   LoginContext{Type: opts.AuthContextType, Message: opts.AuthContextMessage},
		appClaimed:    opts.AppClaimedHTTPS,
		appLaunchURL:  opts.AppLaunchURL,
		fetchUserInfo: opts.FetchUserInfo,
		httpClient:    base,
		decryption:    deps.Decryption,
		retries:       deps.BeginLoginRetries,
		encAlg:        cfg.Algorithms.IDTokenKeyManagement,
	}, nil
}

// checkDependencies checks what New needs before anything else: the two
// required dependencies, the options, and the retry count.
func checkDependencies(opts Options, deps Dependencies) error {
	if deps.Keys == nil {
		return fmt.Errorf("singpass: Dependencies.Keys is required")
	}
	if deps.Decryption == nil {
		return fmt.Errorf("singpass: Dependencies.Decryption is required")
	}
	if err := validateOptions(opts, deps.Assurance == AssuranceProduction); err != nil {
		return err
	}
	if deps.BeginLoginRetries < 0 || deps.BeginLoginRetries > maxBeginLoginRetries {
		return fmt.Errorf("singpass: Dependencies.BeginLoginRetries must be between 0 and %d", maxBeginLoginRetries)
	}
	return nil
}

// checkAssurance refuses the development-only settings under
// AssuranceProduction and requires durable keys there. Outside it, it warns
// when the issuer is a production one.
func checkAssurance(opts Options, deps Dependencies) error {
	if deps.Assurance != AssuranceProduction {
		if isProductionIssuer(opts.Issuer) {
			deps.Logger.Warn("singpass: production issuer without AssuranceProduction: the durable-session, key-custody and randomness checks are off",
				"issuer", opts.Issuer)
		}
		return nil
	}
	if deps.AllowLoopbackHTTP {
		return fmt.Errorf("singpass: Dependencies.AllowLoopbackHTTP is refused under AssuranceProduction")
	}
	if deps.Debug {
		return fmt.Errorf("singpass: Dependencies.Debug is refused under AssuranceProduction: it logs the client assertion and authorization code")
	}
	if km, ok := deps.Keys.(*rotatingKeyManager); ok && km.ephemeralDPoP {
		return errors.New("singpass: AssuranceProduction needs a DPoP key shared by every instance (DPoPKey, or NewKeyManagerWithDPoP): " +
			"Singpass binds each login to the DPoP key it started with, so with a key generated per process a callback that reaches " +
			"another instance, or this one after a restart, fails with invalid_dpop_proof")
	}
	return checkKeyCustody(deps)
}

// discover fetches the issuer's discovery document, through a hardened
// fetcher for the GET-only discovery and JWKS documents, and returns it with
// the issuer's verification keys: resolved from the JWKS URI it advertises,
// cached and auto-refreshing.
func discover(ctx context.Context, base *http.Client, issuer fapi.URL, deps Dependencies, urlOpts []fapi.URLOption) (client.DiscoveredMetadata, keys.IssuerKeySource, error) {
	fetcher, err := fapihttp.New(base, fapihttp.Config{
		MaxResponseBytes:  1 << 20,
		RequestTimeout:    deps.HTTPTimeout,
		MaxRedirects:      5,
		AllowLoopbackHTTP: deps.AllowLoopbackHTTP,
	})
	if err != nil {
		return client.DiscoveredMetadata{}, nil, fmt.Errorf("singpass: build fetcher: %w", err)
	}
	discovered, err := client.Discover(ctx, fetcher, issuer, urlOpts...)
	if err != nil {
		return client.DiscoveredMetadata{}, nil, fmt.Errorf("singpass: discover metadata: %w", err)
	}
	issuerKeys, err := discovered.IssuerKeySource(fetcher, 10*time.Minute)
	if err != nil {
		return client.DiscoveredMetadata{}, nil, fmt.Errorf("singpass: build issuer key source: %w", err)
	}
	return discovered, issuerKeys, nil
}

// engineConfig is the FAPIgo client configuration for the Singpass/Corppass
// profile.
func engineConfig(opts Options, deps Dependencies, issuer fapi.URL, discovered client.DiscoveredMetadata) client.Config {
	assurance := deps.Assurance
	if assurance == 0 {
		assurance = client.AssuranceDevelopment
	}
	return client.Config{
		Issuer:      issuer,
		ClientID:    fapi.ClientID(opts.ClientID),
		RedirectURI: opts.RedirectURI,
		Endpoints:   discovered.Endpoints,
		// Singpass FAPI pushes plain parameters to PAR (it does not require a
		// signed request object), authenticated by private_key_jwt — the FAPI
		// 2.0 Security baseline, not the message-signing profile.
		Profile: client.ProfileFAPISecurity,
		// Assurance gates FAPIgo's client-side session-store check (mirroring
		// server.New): AssuranceProduction rejects a Sessions store that
		// declares no storage.StoreAssurance / Durable capability, which the
		// in-memory default does not — so a real deployment must both raise this
		// to AssuranceProduction and supply a durable SessionStore. The zero
		// value defaults to AssuranceDevelopment above.
		Assurance: assurance,
		// RFC 9207 iss enforcement. The policy has no default and is required, so
		// set an explicit baseline: tolerate a callback without "iss" for an
		// issuer that does not advertise the parameter. NewFromDiscovery
		// upgrades this to RequireAuthorizationResponseIss when discovery's
		// AuthorizationResponseIssSupported is set (RFC 9207 §2.4 MUST-rejects a
		// missing "iss" once the issuer is known to always send one) — it only
		// ever raises the bar, never lowers this baseline.
		AuthorizationResponseIssPolicy: client.TolerateAbsentAuthorizationResponseIss,
		// The following four are set to their zero-value defaults purely to
		// state the flow explicitly (each field's zero value already selects the
		// same behaviour): PAR commits the code to the DPoP key with an actual
		// proof (RFC 9449 §10.1), access tokens are DPoP-sender-constrained, the
		// client authenticates with private_key_jwt, and CIBA is unused (poll).
		PARDPoPBinding:               client.PARDPoPBindingProof,
		SenderConstrain:              storage.SenderConstrainDPoP,
		ClientAuthMethod:             storage.ClientAuthMethodPrivateKeyJWT,
		BackchannelTokenDeliveryMode: storage.BackchannelTokenDeliveryModePoll,
		// Opt-in: also accept a /userinfo "sub" equal to the client_id, as
		// Corppass Myinfo Business used to send (an OIDC Core §5.3.2 deviation).
		TolerateUserInfoSubjectEqualsClientID: opts.TolerateUserInfoSubjectClientID,
		Algorithms:                            resolveAlgorithms(deps.Algorithms, opts.FetchUserInfo),
		Limits:                                resolveLimits(deps.Limits, deps.HTTPTimeout),
	}
}

// engineDependencies is the FAPIgo client's dependencies, with the clock,
// session store and randomness defaults applied.
func engineDependencies(deps Dependencies, issuerKeys keys.IssuerKeySource, httpClient *loggingHTTPClient) client.Dependencies {
	clock := deps.Clock
	if clock == nil {
		clock = client.SystemClock{}
	}
	sessions := deps.Sessions
	if sessions == nil {
		// Expire against the same clock FAPIgo stamps ExpiresAt with.
		sessions = newMemorySessionStore(0, clock.Now)
	}
	random := deps.Random
	if random == nil {
		random = rand.Reader
	}
	return client.Dependencies{
		Sessions:   sessions,
		Keys:       deps.Keys,
		IssuerKeys: issuerKeys,
		Decryption: deps.Decryption,
		HTTP:       httpClient,
		Clock:      clock,
		Random:     random,
	}
}

// isProductionIssuer reports whether issuer is Singpass's or Corppass's
// production issuer.
func isProductionIssuer(issuer string) bool {
	issuer = strings.TrimSuffix(issuer, "/")
	return issuer == ProductionSingpassIssuer || issuer == ProductionCorppassIssuer
}

// resolveAlgorithms returns the caller's Algorithms verbatim when supplied,
// otherwise the Singpass/Corppass suite (augmented for /userinfo when fetching).
func resolveAlgorithms(override *client.Algorithms, fetchUserInfo bool) client.Algorithms {
	if override != nil {
		return *override
	}
	algs := client.Algorithms{
		ClientAuthentication: fapi.ES256,
		DPoP:                 fapi.ES256,
		IDToken:              fapi.ES256,
		// Singpass encrypts the id_token (signed-then-encrypted). Declaring
		// these makes FAPIgo require an encrypted id_token and decrypt it via
		// the Decryption dependency, then verify the inner JWS.
		IDTokenKeyManagement:     fapi.ECDHESA256KW,
		IDTokenContentEncryption: fapi.A256CBCHS512,
	}
	// Myinfo: the inner JWS is ES256 and the response is encrypted with
	// ECDH-ES+A256KW / A256GCM — note the content encryption (A256GCM) differs
	// from the id_token's A256CBC-HS512; FAPIgo decrypts it via the same
	// keys.Decrypter, which serves both IDTokenDecryption and
	// UserInfoDecryption.
	if fetchUserInfo {
		algs.UserInfo = fapi.ES256
		algs.UserInfoKeyManagement = fapi.ECDHESA256KW
		algs.UserInfoContentEncryption = fapi.A256GCM
	}
	return algs
}

// resolveLimits returns the caller's Limits verbatim when supplied, otherwise
// RecommendedLimits(httpTimeout).
func resolveLimits(override *client.Limits, httpTimeout time.Duration) client.Limits {
	if override != nil {
		return *override
	}
	return RecommendedLimits(httpTimeout)
}

// PublicJWKS returns this client's public JWK Set — the signing key the server
// uses to verify the private_key_jwt client assertion, and the encryption key it
// encrypts the id_token/userinfo to. FAPIgo assembles it (client.PublicJWKS)
// from the KeyManager and the keys.Decrypter this client already holds.
func (c *Client) PublicJWKS(ctx context.Context) ([]byte, error) {
	set, err := c.engine.PublicJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("singpass: publish client JWKS: %w", err)
	}
	extra, err := publishedEncryptionKeys(ctx, c.decryption, c.encAlg)
	if err != nil {
		return nil, fmt.Errorf("singpass: publish client JWKS: %w", err)
	}
	set.Keys = appendNewKIDs(set.Keys, extra)
	return json.MarshalIndent(set, "", "  ")
}

// BeginLogin starts an authorization attempt: it runs the pushed authorization
// request and returns the URL to redirect the browser to, plus the login's
// state. Keep the state with the browser — typically in an HttpOnly,
// SameSite=Lax cookie — and pass it to Complete at the callback: it binds the
// callback to the browser that started the login. With
// Dependencies.BeginLoginRetries set, a temporary failure is retried.
func (c *Client) BeginLogin(ctx context.Context) (redirectURL string, state string, err error) {
	return c.BeginLoginWith(ctx, LoginContext{})
}

// LoginContext describes, for Singpass Login, the transaction a user is
// authenticating for: Type is the authentication_context_type (one of the
// values Singpass defines, used against fraud) and Message the optional
// authentication_context_message shown to the user — up to 100 printable
// ASCII characters, excluding < > \ and `. Either left empty falls back to
// the client's LoginOptions.
type LoginContext struct {
	Type    string
	Message string
}

// BeginLoginWith is BeginLogin for a Singpass Login client that describes
// this particular login, e.g. LoginContext{Message: "Approve your transfer of
// $500"}; its fields override the client's for this login only. Myinfo
// clients take no login context.
func (c *Client) BeginLoginWith(ctx context.Context, lc LoginContext) (redirectURL string, state string, err error) {
	ext, err := c.loginExtensions(lc)
	if err != nil {
		return "", "", err
	}
	for attempt := 0; ; attempt++ {
		session, err := c.engine.BeginAuthorization(ctx, client.BeginAuthorizationRequest{
			Scope:      c.scopes,
			ACRValues:  c.acrValues,
			Extensions: ext,
		})
		if err == nil {
			return session.URL().String(), session.Handle().String(), nil
		}
		err = fmt.Errorf("singpass: begin authorization: %w", err)
		if attempt >= c.retries || !IsTemporary(err) {
			return "", "", err
		}
		select {
		case <-ctx.Done():
			return "", "", err
		case <-time.After(retryDelay(attempt)):
		}
	}
}

// loginExtensions builds the Singpass-specific PAR parameters for one login:
// the client's login context overridden by lc, and the mobile-app redirect
// parameters. FAPIgo sends each as a plain top-level PAR parameter.
func (c *Client) loginExtensions(lc LoginContext) (extension.Values, error) {
	ctx, err := c.loginContext(lc)
	if err != nil {
		return extension.Values{}, err
	}
	redirectType := ""
	if c.appClaimed {
		redirectType = "app_claimed_https"
	}
	var ext extension.Values
	for _, p := range []struct {
		def   extension.Definition[string]
		value string
	}{
		{authContextTypeExt, ctx.Type},
		{authContextMessageExt, ctx.Message},
		{redirectURIHTTPSTypeExt, redirectType},
		{appLaunchURLExt, c.appLaunchURL},
	} {
		if p.value == "" {
			continue
		}
		if err := extension.Set(&ext, p.def, p.value); err != nil {
			return ext, fmt.Errorf("singpass: set %s: %w", p.def.Name, err)
		}
	}
	return ext, nil
}

// loginContext is the client's login context with lc's fields, where set,
// in place of its own. Only a Login client, which has a context type, takes
// one.
func (c *Client) loginContext(lc LoginContext) (LoginContext, error) {
	ctx := c.authContext
	if lc.Type == "" && lc.Message == "" {
		return ctx, nil
	}
	if ctx.Type == "" {
		return LoginContext{}, errors.New("singpass: a login context is only for Singpass Login clients")
	}
	if lc.Type != "" {
		ctx.Type = lc.Type
	}
	if lc.Message != "" {
		if err := validateAuthContextMessage(lc.Message); err != nil {
			return LoginContext{}, err
		}
		ctx.Message = lc.Message
	}
	return ctx, nil
}

// Complete validates the authorization callback (identified by its raw query
// string), exchanges the code for tokens, and returns the authenticated
// identity. state is the value BeginLogin returned, recovered from the
// browser (e.g. its cookie) — never from the callback itself — so a callback
// URL delivered to another browser can't complete this login (RFC 9700 §4.7).
// A callback without a matching state, or a stale one (expired, reloaded or
// replayed), matches errors.Is(err, ErrLoginExpired); a user-declined or
// server-denied login is reported as a *DeniedError.
func (c *Client) Complete(ctx context.Context, rawQuery, state string) (*Identity, error) {
	handle, err := callbackSession(rawQuery, state)
	if err != nil {
		return nil, err
	}
	result, err := c.engine.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: handle})
	if err != nil {
		return nil, fmt.Errorf("singpass: complete authorization: %w", err)
	}

	switch r := result.(type) {
	case client.CompletionSuccess:
		if !r.Tokens.HasIDToken {
			return nil, fmt.Errorf("singpass: token response carried no id_token")
		}
		// FAPIgo has already decrypted, signature-, issuer-, audience-, nonce-
		// and expiry-validated these claims; AsMap just reshapes the validated
		// set (typed fields merged back under their JWT claim names, including
		// iat) into a map for display. It cannot fail.
		claims := r.Tokens.IDTokenClaims.AsMap()
		// The token endpoint's "scope" is optional: RFC 6749 §5.1 says it may be
		// omitted when the granted scope is identical to what was requested.
		// Singpass Myinfo omits it (Corppass echoes it), so fall back to the
		// requested scope — which, per that rule, is the granted scope.
		scope := r.Tokens.Scope
		if scope == "" {
			scope = strings.Join(c.scopes, " ")
		}
		id := &Identity{App: c.name, Subject: r.Tokens.Subject, Claims: claims, Scope: scope, IDTokenIssuedAt: r.Tokens.IDTokenClaims.IssuedAt, IDTokenExpiry: r.Tokens.IDTokenClaims.ExpiresAt}

		// Myinfo: the id_token only proves who logged in; the person data lives
		// behind the DPoP-protected /userinfo endpoint. FAPIgo makes that call
		// for us (Client.FetchUserInfo): it builds the DPoP proof with the
		// token's bound key, retries once on a DPoP-Nonce challenge, decrypts the
		// JWE, verifies the inner issuer JWS, and checks the response sub matches
		// the id_token — returning the validated claims.
		if c.fetchUserInfo {
			info, err := c.engine.FetchUserInfo(ctx, r.Tokens)
			if err != nil {
				return nil, fmt.Errorf("singpass: fetch userinfo: %w", err)
			}
			id.Myinfo = parseMyinfo(info)
		}
		return id, nil
	case client.CompletionDenied:
		return nil, &DeniedError{Code: r.Code, Description: r.Description}
	default:
		return nil, fmt.Errorf("singpass: unexpected completion result %T", result)
	}
}

// DeniedError is returned by Complete when the authorization server (or the
// user) declined the request, as opposed to a protocol or transport failure.
type DeniedError struct {
	Code        string
	Description string
}

func (e *DeniedError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("singpass: login denied: %s (%s)", e.Description, e.Code)
	}
	return fmt.Sprintf("singpass: login denied: %s", e.Code)
}

// authContextTypeExt is the Singpass/Corppass-proprietary
// "authentication_context_type" PAR parameter (mandatory for Login apps). It is
// a single bare string, so FAPIgo emits it as a plain top-level PAR parameter on
// the FAPI 2.0 baseline profile — no signed request object required. The value
// itself is the caller's responsibility (see Options.AuthContextType).
var authContextTypeExt = extension.Definition[string]{
	Name:           "authentication_context_type",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter,
	MaxBytes:       128,
}

// authContextMessageExt, redirectURIHTTPSTypeExt and appLaunchURLExt are the
// other Singpass PAR parameters, sent the same way: the message shown to the
// user during a Login (Login apps only), and the mobile-app redirect settings.
var (
	authContextMessageExt = extension.Definition[string]{
		Name:           "authentication_context_message",
		Cardinality:    extension.Single,
		AllowedSources: extension.SourcePlainParameter,
		MaxBytes:       maxAuthContextMessage,
	}
	redirectURIHTTPSTypeExt = extension.Definition[string]{
		Name:           "redirect_uri_https_type",
		Cardinality:    extension.Single,
		AllowedSources: extension.SourcePlainParameter,
		MaxBytes:       32,
	}
	appLaunchURLExt = extension.Definition[string]{
		Name:           "app_launch_url",
		Cardinality:    extension.Single,
		AllowedSources: extension.SourcePlainParameter,
		MaxBytes:       2048,
	}
)

// parseMyinfo adapts FAPIgo's validated UserInfo response into the envelope-aware
// myinfo.Response view. info.AsMap presents the already-decrypted,
// inner-JWS-verified and sub-matched claims as a decoded map (it cannot fail —
// every value round-tripped through json.Unmarshal when the response was first
// parsed); myinfo.Parse then unwraps any double-encoded blocks and groups the data.
func parseMyinfo(info client.UserInfo) *myinfo.Response {
	return myinfo.Parse(info.AsMap())
}
