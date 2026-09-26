package singpasstest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// Issuer selects which authorization server the fake imitates.
type Issuer int

const (
	// Singpass imitates Singpass (Login and Myinfo): issuer path "/fapi",
	// person data under "person_info", and no "scope" in the token response.
	Singpass Issuer = iota
	// Corppass imitates Corppass (Myinfo Business): no "/fapi" path, several
	// /userinfo blocks sent as double-encoded JSON, and "scope" echoed in the
	// token response.
	Corppass
)

// App is the kind of client being registered.
type App int

const (
	// Login is a Singpass (or Corppass) Login client: authentication only. Its
	// PAR request must carry authentication_context_type.
	Login App = iota
	// Myinfo is a Myinfo (or, on Corppass, Myinfo Business) client: it also
	// calls /userinfo, and must not send authentication_context_type.
	Myinfo
)

// Config configures a Server. The zero value is a Singpass fake on a random
// localhost port that signs every login in as the first default persona.
type Config struct {
	// Issuer selects Singpass or Corppass behaviour.
	Issuer Issuer
	// Addr is the listen address. Empty means "127.0.0.1:0" (a free port).
	Addr string
	// Personas are the test users. Nil means DefaultPersonas(Issuer).
	Personas []Persona
	// CorppassUserInfoSubClientID reproduces Corppass's former /userinfo
	// deviation: "sub" set to the client_id instead of the id_token's subject.
	// Off by default, matching Corppass today. Use it to test a client that
	// must tolerate it (MyinfoBusinessOptions.TolerateUserInfoSubjectClientID).
	CorppassUserInfoSubClientID bool
	// Interactive serves a sign-in page listing the personas, with a cancel
	// button, for a browser to use. Otherwise every authorization is approved
	// straight away as the current persona (see SetPersona) — what automated
	// tests want.
	Interactive bool
}

// Client is a relying party registered with the fake, mirroring what real
// onboarding records: its client_id, redirect URIs, whitelisted scopes and the
// public halves of its two keys.
type Client struct {
	ID           string
	App          App
	RedirectURIs []string
	// Scopes the client may request. "openid" is always allowed.
	Scopes []string

	SigningKey    *ecdsa.PublicKey // verifies private_key_jwt client assertions
	SigningKID    string
	EncryptionKey *ecdsa.PublicKey // id_token and /userinfo JWEs are encrypted to it
	EncryptionKID string
}

// Server is a fake Singpass or Corppass FAPI 2.0 authorization server,
// listening on a loopback address over plain HTTP. Point a client at it with
// Issuer as the issuer and singpass.Dependencies.AllowLoopbackHTTP set.
type Server struct {
	cfg      Config
	base     string // scheme://host:port
	issuer   string
	srv      *server.Server
	rs       *resource.Verifier
	clients  *registry
	personas []Persona
	httpSrv  *http.Server
	ln       net.Listener

	mu      sync.Mutex
	current int // index into personas for non-interactive approval
}

const (
	signatureAlg      = fapi.ES256
	keyManagementAlg  = fapi.ECDHESA256KW
	idTokenContentEnc = fapi.A256CBCHS512
	userInfoContent   = fapi.A256GCM
)

// NewServer starts a fake authorization server. Close it when done.
func NewServer(cfg Config) (*Server, error) {
	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("singpasstest: listen: %w", err)
	}
	s := &Server{cfg: cfg, clients: newRegistry(), ln: ln}
	s.base = "http://" + ln.Addr().String()
	s.issuer = s.base
	if cfg.Issuer == Singpass {
		s.issuer += "/fapi"
	}
	s.personas = cfg.Personas
	if s.personas == nil {
		s.personas = DefaultPersonas(cfg.Issuer)
	}
	if len(s.personas) == 0 {
		ln.Close()
		return nil, errors.New("singpasstest: at least one persona is required")
	}
	if err := s.build(); err != nil {
		ln.Close()
		return nil, err
	}

	s.httpSrv = &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = s.httpSrv.Serve(ln) }()
	return s, nil
}

func (s *Server) endpoint(path string) string { return s.issuer + path }

func (s *Server) build() error {
	loopback := fapi.AllowLoopbackHTTP()
	issuer, err := fapi.ParseIssuerURL(s.issuer, loopback)
	if err != nil {
		return err
	}
	ep := func(path string) (fapi.URL, error) { return fapi.ParseEndpointURL(s.endpoint(path), loopback) }
	var endpoints server.Endpoints
	for _, e := range []struct {
		dst  *fapi.URL
		path string
	}{
		{&endpoints.Authorization, "/auth"},
		{&endpoints.Token, "/token"},
		{&endpoints.PushedAuthorizationRequest, "/par"},
		{&endpoints.JWKS, "/jwks"},
	} {
		if *e.dst, err = ep(e.path); err != nil {
			return err
		}
	}

	serverKeys, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: signatureAlg,
		keys.IDTokenSigning:     signatureAlg,
		keys.UserInfoSigning:    signatureAlg,
		keys.JARMSigning:        signatureAlg,
	})
	if err != nil {
		return fmt.Errorf("singpasstest: server keys: %w", err)
	}
	accessTokens, err := server.NewJWTAccessTokens(serverKeys, signatureAlg)
	if err != nil {
		return err
	}
	replay := memstore.NewReplayStore()
	revocation := memstore.NewRevocationStore()

	s.srv, err = server.New(server.Config{
		Issuer:    issuer,
		Endpoints: endpoints,
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion:                     server.AlgorithmSet{signatureAlg},
			RequestObject:                       server.AlgorithmSet{signatureAlg},
			JARM:                                signatureAlg,
			IDToken:                             signatureAlg,
			IDTokenEncryptionKeyManagement:      server.KeyManagementAlgorithmSet{keyManagementAlg},
			IDTokenEncryptionContentEncryption:  server.ContentEncryptionAlgorithmSet{idTokenContentEnc},
			UserInfo:                            signatureAlg,
			UserInfoEncryptionKeyManagement:     server.KeyManagementAlgorithmSet{keyManagementAlg},
			UserInfoEncryptionContentEncryption: server.ContentEncryptionAlgorithmSet{userInfoContent},
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: 2 * time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        10 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        30 * time.Minute,
			IDTokenLifetime:            10 * time.Minute,
			MaxIDTokenClaimsBytes:      4096,
			RefreshTokenLifetime:       time.Hour,
			MaxDPoPProofAge:            2 * time.Minute,
			MaxClockSkew:               30 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}, server.Dependencies{
		Clients:                s.clients,
		Transactions:           memstore.NewTransactionStore(),
		Grants:                 memstore.NewGrantStore(),
		Replay:                 replay,
		ClientKeys:             s.clients,
		ClientEncryptionKeys:   s.clients,
		Keys:                   serverKeys,
		AccessTokens:           accessTokens,
		Revocation:             revocation,
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  systemClock{},
		Random:                 rand.Reader,
	})
	if err != nil {
		return fmt.Errorf("singpasstest: server: %w", err)
	}

	resourceTokens, err := resource.NewJWTAccessTokens(issuerKeys{issuer: s.issuer, manager: serverKeys}, issuer, s.issuer, signatureAlg, 30*time.Minute, 8)
	if err != nil {
		return err
	}
	s.rs, err = resource.NewVerifier(
		resource.Config{Limits: resource.Limits{MaxDPoPProofAge: 2 * time.Minute, MaxClockSkew: 30 * time.Second}},
		resource.Dependencies{AccessTokens: resourceTokens, Replay: replay, Revocation: revocation, Clock: systemClock{}},
	)
	if err != nil {
		return fmt.Errorf("singpasstest: resource verifier: %w", err)
	}
	return nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Issuer is the issuer URL to configure clients with: "http://127.0.0.1:port/fapi"
// for Singpass, without "/fapi" for Corppass.
func (s *Server) Issuer() string { return s.issuer }

// Close stops the server.
func (s *Server) Close() error { return s.httpSrv.Close() }

// Personas returns the server's test users.
func (s *Server) Personas() []Persona { return append([]Persona(nil), s.personas...) }

// SetPersona selects, by Subject, the persona that non-interactive
// authorizations are approved as.
func (s *Server) SetPersona(subject string) error {
	for i, p := range s.personas {
		if p.Subject == subject {
			s.mu.Lock()
			s.current = i
			s.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("singpasstest: no persona with subject %q", subject)
}

// RegisterClient registers a relying party, as onboarding would.
func (s *Server) RegisterClient(c Client) error {
	if c.ID == "" || len(c.RedirectURIs) == 0 {
		return errors.New("singpasstest: client ID and at least one redirect URI are required")
	}
	if c.SigningKey == nil || c.EncryptionKey == nil {
		return errors.New("singpasstest: client signing and encryption keys are required")
	}
	redirects := make([]fapi.RegisteredRedirectURI, 0, len(c.RedirectURIs))
	for _, u := range c.RedirectURIs {
		redirects = append(redirects, fapi.RegisteredRedirectURI(u))
	}
	scopes := append([]string{"openid"}, c.Scopes...)
	rc := storage.RegisteredClientConfig{
		ID:                                 fapi.ClientID(c.ID),
		RedirectURIs:                       redirects,
		ClientAuthMethod:                   storage.ClientAuthMethodPrivateKeyJWT,
		ClientAssertionAlgorithm:           signatureAlg,
		RequestObjectAlgorithm:             signatureAlg,
		SenderConstrain:                    storage.SenderConstrainDPoP,
		IDTokenEncryptionKeyManagement:     keyManagementAlg,
		IDTokenEncryptionContentEncryption: idTokenContentEnc,
		AllowedScopes:                      scopes,
	}
	if c.App == Myinfo {
		rc.UserInfoEncryptionKeyManagement = keyManagementAlg
		rc.UserInfoEncryptionContentEncryption = userInfoContent
	}
	stored, err := storage.NewRegisteredClient(rc)
	if err != nil {
		return fmt.Errorf("singpasstest: register client: %w", err)
	}
	// JWE key agreement takes the ECDH form of the encryption key.
	encKey, err := c.EncryptionKey.ECDH()
	if err != nil {
		return fmt.Errorf("singpasstest: encryption key: %w", err)
	}
	s.clients.add(registeredClient{cfg: c, stored: stored, encKey: encKey})
	return nil
}

func (s *Server) routes() http.Handler {
	prefix := strings.TrimPrefix(s.issuer, s.base)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+prefix+"/.well-known/openid-configuration", s.handleMetadata)
	mux.HandleFunc("GET "+prefix+"/jwks", s.handleJWKS)
	mux.HandleFunc("POST "+prefix+"/par", s.handlePAR)
	mux.HandleFunc("GET "+prefix+"/auth", s.handleAuthorize)
	mux.HandleFunc("POST "+prefix+"/auth/decision", s.handleDecision)
	mux.HandleFunc("POST "+prefix+"/token", s.handleToken)
	mux.HandleFunc("GET "+prefix+"/userinfo", s.handleUserInfo)
	return mux
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	md := s.srv.Metadata(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                           s.issuer,
		"authorization_endpoint":                           s.endpoint("/auth"),
		"pushed_authorization_request_endpoint":            s.endpoint("/par"),
		"token_endpoint":                                   s.endpoint("/token"),
		"jwks_uri":                                         s.endpoint("/jwks"),
		"userinfo_endpoint":                                s.endpoint("/userinfo"),
		"response_types_supported":                         md.ResponseTypesSupported,
		"response_modes_supported":                         md.ResponseModesSupported,
		"grant_types_supported":                            []string{"authorization_code"},
		"subject_types_supported":                          []string{"public"},
		"code_challenge_methods_supported":                 md.CodeChallengeMethodsSupported,
		"token_endpoint_auth_methods_supported":            []string{"private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"},
		"dpop_signing_alg_values_supported":                []string{"ES256"},
		"id_token_signing_alg_values_supported":            []string{"ES256"},
		"id_token_encryption_alg_values_supported":         []string{"ECDH-ES+A256KW"},
		"id_token_encryption_enc_values_supported":         []string{"A256CBC-HS512"},
		"userinfo_signing_alg_values_supported":            []string{"ES256"},
		"userinfo_encryption_alg_values_supported":         []string{"ECDH-ES+A256KW"},
		"userinfo_encryption_enc_values_supported":         []string{"A256GCM"},
		"require_pushed_authorization_requests":            true,
		"authorization_response_iss_parameter_supported":   true,
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.srv.PublicJWKS(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handlePAR(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// Singpass/Corppass: authentication_context_type is required for Login
	// clients and rejected for Myinfo ones.
	if c, ok := s.clients.get(fapi.ClientID(formValue(form, "client_id"))); ok {
		act := formValue(form, "authentication_context_type")
		switch {
		case c.cfg.App == Myinfo && act != "":
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"authentication_context_type and authentication_context_message can only be provided for Login apps. Please remove these fields from your request body.")
			return
		case c.cfg.App == Login && act == "":
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authentication_context_type is required for Login apps")
			return
		}
	}
	result, err := s.srv.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{HTTP: form})
	if err != nil {
		writeServerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": result.RequestURI.String(),
		"expires_in":  result.ExpiresIn,
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	action, err := s.srv.BeginAuthorization(r.Context(), server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"),
		ClientID:   fapi.ClientID(q.Get("client_id")),
	})
	if err != nil {
		writeServerError(w, err)
		return
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		writeAuthorizationAction(w, action)
		return
	}
	if s.cfg.Interactive {
		renderSignIn(w, s, interaction)
		return
	}
	s.mu.Lock()
	p := s.personas[s.current]
	s.mu.Unlock()
	s.complete(w, r, interaction.Handle, interaction.Interaction.Scope, &p)
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	handle, err := server.ParseInteractionHandle(r.PostFormValue("handle"))
	if err != nil {
		http.Error(w, "bad interaction handle", http.StatusBadRequest)
		return
	}
	scope := strings.Fields(r.PostFormValue("scope"))
	if r.PostFormValue("decision") == "cancel" {
		s.complete(w, r, handle, scope, nil)
		return
	}
	for _, p := range s.personas {
		if p.Subject == r.PostFormValue("subject") {
			s.complete(w, r, handle, scope, &p)
			return
		}
	}
	http.Error(w, "unknown persona", http.StatusBadRequest)
}

// complete approves the interaction as p, or denies it (access_denied) when p
// is nil, and redirects back to the client.
func (s *Server) complete(w http.ResponseWriter, r *http.Request, handle server.InteractionHandle, scope []string, p *Persona) {
	var result server.InteractionResult
	if p == nil {
		result = server.Deny("the user cancelled the login")
	} else {
		subjectID, err := server.NewSubjectID(p.Subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		auth, err := server.NewAuthenticationContext(time.Now(), p.acr(), p.amr())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		claims, err := p.idTokenClaims(s.cfg.Issuer, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result = server.Authorize(subject, auth, server.GrantedAuthorization{Scope: scope, IDTokenClaims: claims})
	}
	res, err := s.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		writeServerError(w, err)
		return
	}
	switch v := res.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, v.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		writeServerError(w, v.Error)
	default:
		http.Error(w, fmt.Sprintf("unexpected authorization result %T", res), http.StatusInternalServerError)
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if gt := formValue(form, "grant_type"); gt != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	result, err := s.srv.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{HTTP: form, DPoPProofs: r.Header.Values("DPoP")})
	if err != nil {
		writeServerError(w, err)
		return
	}
	resp := map[string]any{
		"access_token": result.AccessToken.Reveal(),
		"token_type":   result.TokenType,
		"expires_in":   int64(result.ExpiresIn / time.Second),
	}
	// Corppass echoes the granted scope; Singpass omits it (RFC 6749 §5.1
	// allows that when it equals the requested scope).
	if s.cfg.Issuer == Corppass {
		resp["scope"] = result.Scope
	}
	if result.HasIDToken {
		resp["id_token"] = result.IDToken.Reveal()
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(s.base)
	u.Path, u.RawQuery = r.URL.Path, r.URL.RawQuery
	authz, err := s.rs.Verify(r.Context(), resource.VerifyRequest{
		Method:        r.Method,
		URL:           u,
		Authorization: r.Header.Get("Authorization"),
		DPoPProofs:    r.Header.Values("DPoP"),
	})
	if err != nil {
		var rerr *resource.Error
		if errors.As(err, &rerr) {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`DPoP error=%q`, rerr.Code()))
			writeOAuthError(w, rerr.HTTPStatus(), string(rerr.Code()), rerr.PublicDescription())
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c, ok := s.clients.get(fapi.ClientID(authz.ClientID))
	if !ok || c.cfg.App != Myinfo {
		writeOAuthError(w, http.StatusForbidden, "insufficient_scope", "client is not a Myinfo client")
		return
	}
	var persona *Persona
	for i := range s.personas {
		if s.personas[i].Subject == authz.Subject {
			persona = &s.personas[i]
		}
	}
	if persona == nil {
		writeOAuthError(w, http.StatusNotFound, "invalid_token", "unknown subject")
		return
	}

	claims, err := s.userInfoClaims(*persona, authz)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jwe, serr := s.srv.SignUserInfoResponse(r.Context(), c.stored, claims)
	if serr != nil {
		writeServerError(w, serr)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = io.WriteString(w, jwe)
}

// userInfoClaims builds the /userinfo payload in the issuer's shape.
func (s *Server) userInfoClaims(p Persona, authz resource.AuthorizationContext) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage)
	sub := authz.Subject
	if s.cfg.Issuer == Corppass && s.cfg.CorppassUserInfoSubClientID {
		sub = authz.ClientID // Corppass's former deviation
	}
	var err error
	if out["sub"], err = json.Marshal(sub); err != nil {
		return nil, err
	}
	for block, data := range p.UserInfo {
		var v any = data
		if s.cfg.Issuer == Singpass && block == "person_info" {
			if m, ok := data.(map[string]any); ok {
				v = filterByScope(m, authz.Scopes)
			}
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		if s.cfg.Issuer == Corppass {
			// Corppass sends each block as a JSON string holding the object.
			if raw, err = json.Marshal(string(raw)); err != nil {
				return nil, err
			}
		}
		out[block] = raw
	}
	return out, nil
}

// filterByScope keeps the person_info items the granted scopes cover: a scope
// "name" grants "name", and "vehicles.make" grants (part of) "vehicles".
func filterByScope(m map[string]any, scopes []string) map[string]any {
	granted := make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		granted[strings.SplitN(sc, ".", 2)[0]] = true
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if granted[k] {
			out[k] = v
		}
	}
	return out
}

// Authorize performs the browser's part of a login for tests: it follows
// redirectURL (from singpass.Client.BeginLogin) to the fake's authorization
// endpoint and returns the raw query of the resulting callback, ready for
// singpass.Client.Complete. The Server must not be Interactive.
func (s *Server) Authorize(ctx context.Context, redirectURL string) (string, error) {
	if s.cfg.Interactive {
		return "", errors.New("singpasstest: Authorize needs a non-interactive server")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirectURL, nil)
	if err != nil {
		return "", err
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", fmt.Errorf("singpasstest: authorize: %s: %s", res.Status, body)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		return "", err
	}
	return loc.RawQuery, nil
}

func writeAuthorizationAction(w http.ResponseWriter, action server.AuthorizationAction) {
	switch v := action.(type) {
	case server.RedirectResponse:
		w.Header().Set("Location", v.Destination.String())
		w.WriteHeader(http.StatusFound)
	case server.LocalErrorResponse:
		writeServerError(w, v.Error)
	default:
		http.Error(w, fmt.Sprintf("unexpected authorization action %T", action), http.StatusInternalServerError)
	}
}

func writeServerError(w http.ResponseWriter, err error) {
	var serr *server.Error
	if errors.As(err, &serr) {
		writeOAuthError(w, serr.HTTPStatus(), string(serr.Code()), serr.PublicDescription())
		return
	}
	writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func formValue(form server.FormRequest, name string) string {
	for _, p := range form.Parameters {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
