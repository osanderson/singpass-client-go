// Package singpass wires the FAPIgo relying-party engine
// (github.com/idfoundry/fapigo/client) to talk to the Singpass / Corppass FAPI
// 2.0 profile. FAPIgo does all of the protocol work; this package supplies the
// pieces FAPIgo leaves to the embedder — a key manager, a keys.Decrypter for the
// encrypted id_token, and a session store — and encodes the Singpass-specific
// choices (PAR parameters, algorithm suite, /userinfo handling) so a relying
// party can integrate Singpass Login, Myinfo, and Myinfo Business without
// rediscovering them.
//
// Most callers should use the per-product constructors NewLogin, NewMyinfo, and
// NewMyinfoBusiness (see products.go), which take just key material and a
// client_id. New is the lower-level constructor for full control or a
// non-standard product.
package singpass

import (
	"context"
	"crypto/rand"
	"encoding/json"
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
	AcrValues       string   // optional requested level of assurance; "" to omit
	FetchUserInfo   bool     // call the FAPI /userinfo endpoint after token exchange (Myinfo)
	// TolerateUserInfoSubjectClientID accepts a /userinfo "sub" equal to the
	// client_id (as well as the id_token sub) — a Corppass Myinfo Business
	// deviation from OIDC Core §5.3.2. Set only for the Myinfo Business client.
	TolerateUserInfoSubjectClientID bool
}

// Dependencies are a Client's injected collaborators. Only Keys and Decryption
// are required; every other field's zero value selects a sensible staging
// default, so the simple path is Dependencies{Keys: km, Decryption: dec}. A
// production deployment sets the fields it needs to harden — most importantly a
// durable Sessions store together with Assurance: client.AssuranceProduction.
type Dependencies struct {
	// Keys performs this client's signing operations (client assertion + DPoP
	// proof). Required. See NewKeyManager.
	Keys keys.KeyManager

	// Decryption recovers the content-encryption key of the encrypted id_token
	// (and /userinfo response). Required. See NewECDHDecrypter.
	Decryption keys.Decrypter

	// Sessions persists in-progress authorization-flow state. Nil installs
	// NewMemorySessionStore(0): per-process and non-durable, but expired
	// sessions are dropped and pending logins are capped, so abandoned logins
	// cannot grow memory without bound. Fine for a single instance /
	// development; refused under AssuranceProduction.
	Sessions storage.SessionStore

	// Assurance gates how strict FAPIgo's dependency validation is. Zero means
	// client.AssuranceDevelopment (permits the in-memory Sessions default).
	// client.AssuranceProduction requires a Sessions store declaring
	// storage.StoreAssurance (Durable + AtomicConsume), so the in-memory
	// default is refused.
	Assurance client.AssuranceLevel

	// HTTPClient is the base client for discovery, JWKS, PAR, token and
	// /userinfo calls. Nil builds &http.Client{Timeout: HTTPTimeout}.
	HTTPClient *http.Client

	// HTTPTimeout bounds each outbound call. Zero means defaultHTTPTimeout. It
	// is also folded into the default Limits (below) and the default HTTPClient.
	HTTPTimeout time.Duration

	// Clock supplies the current time. Nil means client.SystemClock{}.
	Clock client.Clock

	// Random is the randomness source for state/nonce/PKCE. Nil means
	// crypto/rand.Reader.
	Random io.Reader

	// Limits bounds token lifetimes and JOSE/HTTP sizes. Nil means
	// RecommendedLimits(HTTPTimeout).
	Limits *client.Limits

	// Algorithms overrides the FAPI algorithm suite. Nil selects the
	// Singpass/Corppass suite (ES256; id_token ECDH-ES+A256KW / A256CBC-HS512;
	// and, when Options.FetchUserInfo is set, /userinfo A256GCM). When you set
	// this, it is used verbatim and the FetchUserInfo augmentation is skipped —
	// declare the /userinfo algorithms yourself.
	Algorithms *client.Algorithms

	// Debug, when true, logs outbound PAR/token/userinfo requests and responses
	// (method, URL, form body, sizes) via Logger. The request dump includes the
	// client_assertion — enable it only against staging.
	Debug bool

	// Logger receives Debug output and internal warnings. Nil means
	// slog.Default().
	Logger *slog.Logger
}

// Client is a relying party (Login, Myinfo, or Myinfo Business). It is safe for
// concurrent use.
type Client struct {
	engine     *client.Client
	name       string
	scopes     []string
	acrValues  []string         // requested acr_values, if any (sent only when non-empty)
	extensions extension.Values // Singpass-specific PAR parameters (authentication_context_type)

	// fetchUserInfo makes Complete call the engine's native FetchUserInfo
	// after token exchange to retrieve Myinfo person data.
	fetchUserInfo bool
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
	if deps.Keys == nil {
		return nil, fmt.Errorf("singpass: Dependencies.Keys is required")
	}
	if deps.Decryption == nil {
		return nil, fmt.Errorf("singpass: Dependencies.Decryption is required")
	}

	httpTimeout := deps.HTTPTimeout
	if httpTimeout == 0 {
		httpTimeout = defaultHTTPTimeout
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	issuer, err := fapi.ParseIssuerURL(opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("singpass: parse issuer: %w", err)
	}

	// The base HTTP client, shared by the discovery/JWKS fetcher and the
	// engine's PAR/token/userinfo calls.
	base := deps.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: httpTimeout}
	}

	// A hardened fetcher for the GET-only discovery and JWKS documents.
	fetcher, err := fapihttp.New(base, fapihttp.Config{
		MaxResponseBytes: 1 << 20,
		RequestTimeout:   httpTimeout,
		MaxRedirects:     5,
	})
	if err != nil {
		return nil, fmt.Errorf("singpass: build fetcher: %w", err)
	}

	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return nil, fmt.Errorf("singpass: discover metadata: %w", err)
	}

	// The issuer's verification keys, resolved straight from the JWKS URI the
	// discovery document just advertised (cached, auto-refreshing).
	issuerKeys, err := discovered.IssuerKeySource(fetcher, 10*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("singpass: build issuer key source: %w", err)
	}

	// Myinfo needs the UserInfo endpoint. FAPIgo calls it natively
	// (Client.FetchUserInfo) once we declare the response algorithms (below);
	// the endpoint itself rides along in discovered.Endpoints like every other
	// endpoint. Fail fast here if the issuer advertises none — an endpoint-
	// presence check NewFromDiscovery (below) does not make: it validates the
	// declared algorithms against discovery, but never touches cfg.Endpoints.
	if opts.FetchUserInfo && discovered.Endpoints.UserInfo.IsZero() {
		return nil, fmt.Errorf("singpass: issuer advertises no userinfo_endpoint but FetchUserInfo is set")
	}

	// The engine's PAR/token/userinfo HTTP client. A transparent wrapper over
	// base that logs only when deps.Debug is set (otherwise it just delegates),
	// so the default behaviour is a plain pass-through.
	httpClient := newLoggingHTTPClient(base, deps.Debug, logger)

	assurance := deps.Assurance
	if assurance == 0 {
		assurance = client.AssuranceDevelopment
	}

	cfg := client.Config{
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
		// issuer that does not advertise the parameter. NewFromDiscovery (below)
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
		// Corppass Myinfo Business sets its /userinfo "sub" to the client_id
		// rather than the authenticated person (an OIDC Core §5.3.2 deviation);
		// this opt-in accepts sub == client_id as well as the id_token's sub.
		TolerateUserInfoSubjectEqualsClientID: opts.TolerateUserInfoSubjectClientID,
		Algorithms:                            resolveAlgorithms(deps.Algorithms, opts.FetchUserInfo),
		Limits:                                resolveLimits(deps.Limits, httpTimeout),
	}

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

	// NewFromDiscovery is New plus two discovery-only checks: it runs
	// discovered.SupportsAlgorithms(cfg.Algorithms) — so a declared-but-
	// unadvertised algorithm fails cleanly at startup instead of as an opaque
	// signature/JWE-decrypt failure on the first live response — and it upgrades
	// cfg.AuthorizationResponseIssPolicy to RequireAuthorizationResponseIss from
	// discovered.AuthorizationResponseIssSupported (RFC 9207 §2.4), on top of the
	// TolerateAbsent baseline set above. It does not
	// read or modify cfg.Endpoints, so the UserInfo endpoint-presence fail-fast
	// above is still ours to make.
	engine, err := client.NewFromDiscovery(discovered, cfg, client.Dependencies{
		Sessions:   sessions,
		Keys:       deps.Keys,
		IssuerKeys: issuerKeys,
		Decryption: deps.Decryption,
		HTTP:       httpClient,
		Clock:      clock,
		Random:     random,
	})
	if err != nil {
		return nil, fmt.Errorf("singpass: construct client: %w", err)
	}

	// Attach the Singpass-specific authorization parameters FAPIgo will emit on
	// every PAR: authentication_context_type as a plain-string extension, and
	// acr_values (opt-in — Singpass rejects it unless the client is whitelisted,
	// so it is sent only when configured).
	var extensions extension.Values
	if opts.AuthContextType != "" {
		if err := extension.Set(&extensions, authContextTypeExt, opts.AuthContextType); err != nil {
			return nil, fmt.Errorf("singpass: set authentication_context_type: %w", err)
		}
	}
	var acrValues []string
	if v := strings.TrimSpace(opts.AcrValues); v != "" {
		acrValues = strings.Fields(v)
	}

	return &Client{
		engine:        engine,
		name:          opts.Name,
		scopes:        opts.Scopes,
		acrValues:     acrValues,
		extensions:    extensions,
		fetchUserInfo: opts.FetchUserInfo,
	}, nil
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
	return json.MarshalIndent(set, "", "  ")
}

// BeginLogin starts an authorization attempt: it runs the pushed authorization
// request and returns the URL to redirect the browser to, plus the opaque state
// handle (usable as a defense-in-depth cookie binding the request to its
// eventual callback).
func (c *Client) BeginLogin(ctx context.Context) (redirectURL string, state string, err error) {
	session, err := c.engine.BeginAuthorization(ctx, client.BeginAuthorizationRequest{
		Scope:      c.scopes,
		ACRValues:  c.acrValues,
		Extensions: c.extensions,
	})
	if err != nil {
		return "", "", fmt.Errorf("singpass: begin authorization: %w", err)
	}
	return session.URL().String(), session.Handle().String(), nil
}

// Complete validates the authorization callback (identified by its raw query
// string), exchanges the code for tokens, and returns the authenticated
// identity. A user-declined or server-denied login is reported as a
// *DeniedError.
func (c *Client) Complete(ctx context.Context, rawQuery string) (*Identity, error) {
	result, err := c.engine.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
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
