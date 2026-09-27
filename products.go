package singpass

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/keys"
)

// Issuer identifiers. The product options pick one from Environment; set
// Issuer only for a non-standard deployment.
const (
	// StagingSingpassIssuer is the Singpass FAPI 2.0 staging issuer (Login + Myinfo).
	StagingSingpassIssuer = "https://stg-id.singpass.gov.sg/fapi"
	// StagingCorppassIssuer is the Corppass FAPI 2.0 staging issuer (Myinfo
	// Business). Note it has no "/fapi" path suffix, unlike Singpass, and it is
	// a separate authorization server with its own discovery document.
	StagingCorppassIssuer = "https://stg-id.corppass.gov.sg"
	// ProductionSingpassIssuer is the Singpass FAPI 2.0 production issuer.
	ProductionSingpassIssuer = "https://id.singpass.gov.sg/fapi"
	// ProductionCorppassIssuer is the Corppass FAPI 2.0 production issuer.
	ProductionCorppassIssuer = "https://id.corppass.gov.sg"
)

// Environment selects Singpass/Corppass staging or production for the product
// constructors (NewLogin, NewMyinfo, NewMyinfoBusiness).
type Environment int

const (
	// Staging is the default: the staging issuers, and development assurance
	// unless Dependencies.Assurance says otherwise.
	Staging Environment = iota
	// Production selects the production issuers and, when
	// Dependencies.Assurance is unset, AssuranceProduction — so the in-memory
	// session store is refused and a durable one must be supplied.
	Production
)

// String returns "staging" or "production".
func (e Environment) String() string {
	if e == Production {
		return "production"
	}
	return "staging"
}

// issuers returns the Singpass and Corppass issuers for e.
func (e Environment) issuers() (singpass, corppass string) {
	if e == Production {
		return ProductionSingpassIssuer, ProductionCorppassIssuer
	}
	return StagingSingpassIssuer, StagingCorppassIssuer
}

// forEnvironment applies e's assurance default to deps.
func (e Environment) forEnvironment(deps Dependencies) Dependencies {
	if e == Production && deps.Assurance == 0 {
		deps.Assurance = AssuranceProduction
	}
	return deps
}

// DefaultAuthContextType is the standard Singpass/Corppass Login
// authentication_context_type — the flow a plain login authenticates for.
const DefaultAuthContextType = "APP_AUTHENTICATION_DEFAULT"

// LoginOptions configures a Singpass (or Corppass) Login relying party:
// authentication only, no /userinfo call. authentication_context_type is
// mandatory for Login and defaults to DefaultAuthContextType.
type LoginOptions struct {
	Name        string      // app slug for logging/Identity; defaults to "login"
	Environment Environment // Staging (default) or Production: picks the issuer and assurance
	Issuer      string      // FAPI issuer; empty means Environment's Singpass issuer
	ClientID    string      // client_id issued by the authorization server
	RedirectURI string      // must match what is registered with the server
	Scopes      []string    // must include "openid"

	// AuthContextType is the Login authentication_context_type; defaults to
	// DefaultAuthContextType.
	AuthContextType string
	// AcrValues is the optional requested level of assurance; "" to omit
	// (Singpass rejects it unless the client is whitelisted for it).
	AcrValues string

	// Key material. Used to build Dependencies.Keys / Dependencies.Decryption
	// when the caller leaves those nil; ignored when they are set (an HSM/KMS
	// caller injects its own).
	SigningKey    crypto.Signer     // ES256 / P-256 client-assertion + DPoP signer
	SigningKID    string            // kid of the registered signing key
	EncryptionKey *ecdsa.PrivateKey // id_token decryption key (in-memory)
	EncryptionKID string            // kid of EncryptionKey; ignored when EncryptionAgreer is set
	// EncryptionAgreer is an optional HSM/KMS-backed ECDH agreer for id_token
	// decryption, used in place of the in-memory EncryptionKey. When set it wins
	// over EncryptionKey (the encryption private key then never enters this
	// process), and the kid comes from the agreer itself — EncryptionKID is not
	// used. Ignored when Dependencies.Decryption is supplied. See
	// NewAgreerDecrypter.
	EncryptionAgreer ECDHAgreer

	// AdditionalSigningKeys and AdditionalEncryptionKeys are the extra keys of
	// a key rotation (see docs/production.md): signing keys published in the
	// JWKS but not used to sign, and encryption keys decrypted with and —
	// unless DecryptOnly — published. They need the keys above: with
	// Dependencies.Keys or Dependencies.Decryption supplied, use
	// NewRotatingKeyManager / NewRotatingDecrypter there instead.
	AdditionalSigningKeys    []PublishedKey
	AdditionalEncryptionKeys []DecryptionKey
}

// MyinfoOptions configures a Singpass Myinfo relying party: authentication plus
// person data retrieved from the DPoP-protected /userinfo endpoint.
// authentication_context_type is not sent (Singpass rejects it on Myinfo).
type MyinfoOptions struct {
	Name        string      // app slug for logging/Identity; defaults to "myinfo"
	Environment Environment // Staging (default) or Production: picks the issuer and assurance
	Issuer      string      // FAPI issuer; empty means Environment's Singpass issuer
	ClientID    string      // client_id issued by the authorization server
	RedirectURI string      // must match what is registered with the server
	Scopes      []string    // person-data scopes; must include "openid"
	AcrValues   string      // optional requested level of assurance; "" to omit

	SigningKey    crypto.Signer     // ES256 / P-256 client-assertion + DPoP signer
	SigningKID    string            // kid of the registered signing key
	EncryptionKey *ecdsa.PrivateKey // id_token / userinfo decryption key (in-memory)
	EncryptionKID string            // kid of EncryptionKey; ignored when EncryptionAgreer is set
	// EncryptionAgreer is an optional HSM/KMS-backed ECDH agreer for id_token /
	// userinfo decryption, used in place of the in-memory EncryptionKey. When set
	// it wins over EncryptionKey (the encryption private key then never enters
	// this process), and the kid comes from the agreer itself — EncryptionKID is
	// not used. Ignored when Dependencies.Decryption is supplied. See
	// NewAgreerDecrypter.
	EncryptionAgreer ECDHAgreer

	// AdditionalSigningKeys and AdditionalEncryptionKeys are the extra keys of
	// a key rotation (see docs/production.md): signing keys published in the
	// JWKS but not used to sign, and encryption keys decrypted with and —
	// unless DecryptOnly — published. They need the keys above: with
	// Dependencies.Keys or Dependencies.Decryption supplied, use
	// NewRotatingKeyManager / NewRotatingDecrypter there instead.
	AdditionalSigningKeys    []PublishedKey
	AdditionalEncryptionKeys []DecryptionKey
}

// MyinfoBusinessOptions configures a Corppass Myinfo Business relying party: the
// corporate counterpart of Myinfo, on the separate Corppass FAPI 2.0
// authorization server. Same protocol as Myinfo, with the Corppass issuer
// default.
type MyinfoBusinessOptions struct {
	Name        string      // app slug for logging/Identity; defaults to "myinfobiz"
	Environment Environment // Staging (default) or Production: picks the issuer and assurance
	Issuer      string      // FAPI issuer; empty means Environment's Corppass issuer
	ClientID    string      // client_id issued by Corppass
	RedirectURI string      // must match what is registered with the server
	Scopes      []string    // entity.* / user.* / corppass.* scopes; must include "openid"
	AcrValues   string      // optional requested level of assurance; "" to omit

	SigningKey    crypto.Signer     // ES256 / P-256 client-assertion + DPoP signer
	SigningKID    string            // kid of the registered signing key
	EncryptionKey *ecdsa.PrivateKey // id_token / userinfo decryption key (in-memory)
	EncryptionKID string            // kid of EncryptionKey; ignored when EncryptionAgreer is set
	// EncryptionAgreer is an optional HSM/KMS-backed ECDH agreer for id_token /
	// userinfo decryption, used in place of the in-memory EncryptionKey. When set
	// it wins over EncryptionKey (the encryption private key then never enters
	// this process), and the kid comes from the agreer itself — EncryptionKID is
	// not used. Ignored when Dependencies.Decryption is supplied. See
	// NewAgreerDecrypter.
	EncryptionAgreer ECDHAgreer

	// AdditionalSigningKeys and AdditionalEncryptionKeys are the extra keys of
	// a key rotation (see docs/production.md): signing keys published in the
	// JWKS but not used to sign, and encryption keys decrypted with and —
	// unless DecryptOnly — published. They need the keys above: with
	// Dependencies.Keys or Dependencies.Decryption supplied, use
	// NewRotatingKeyManager / NewRotatingDecrypter there instead.
	AdditionalSigningKeys    []PublishedKey
	AdditionalEncryptionKeys []DecryptionKey

	// TolerateUserInfoSubjectClientID also accepts a /userinfo "sub" equal to
	// the client_id. Corppass used to send that instead of the id_token's sub
	// (contrary to OIDC Core §5.3.2); it now sends the correct sub — confirmed
	// on staging — so this is off by default. Set it only if a Corppass
	// environment still fails with a /userinfo subject mismatch.
	TolerateUserInfoSubjectClientID bool
}

// NewLogin constructs a Login relying party. It fills in the Login-specific
// choices (authentication_context_type required, no /userinfo call) and, when
// deps.Keys / deps.Decryption are nil, builds them from the option's key
// material. Everything else follows Dependencies' staging defaults.
func NewLogin(ctx context.Context, o LoginOptions, deps Dependencies) (*Client, error) {
	if o.Name == "" {
		o.Name = "login"
	}
	if o.Issuer == "" {
		o.Issuer, _ = o.Environment.issuers()
	}
	deps = o.Environment.forEnvironment(deps)
	if o.AuthContextType == "" {
		o.AuthContextType = DefaultAuthContextType
	}
	deps, err := ensureKeyDeps(ctx, deps, keyMaterial{o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID, o.EncryptionAgreer, o.AdditionalSigningKeys, o.AdditionalEncryptionKeys})
	if err != nil {
		return nil, err
	}
	return New(ctx, Options{
		Name:            o.Name,
		Issuer:          o.Issuer,
		ClientID:        o.ClientID,
		RedirectURI:     o.RedirectURI,
		Scopes:          o.Scopes,
		AuthContextType: o.AuthContextType,
		AcrValues:       o.AcrValues,
	}, deps)
}

// NewMyinfo constructs a Myinfo relying party (authentication + /userinfo person
// data). It presets FetchUserInfo and omits authentication_context_type.
func NewMyinfo(ctx context.Context, o MyinfoOptions, deps Dependencies) (*Client, error) {
	if o.Name == "" {
		o.Name = "myinfo"
	}
	if o.Issuer == "" {
		o.Issuer, _ = o.Environment.issuers()
	}
	deps = o.Environment.forEnvironment(deps)
	deps, err := ensureKeyDeps(ctx, deps, keyMaterial{o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID, o.EncryptionAgreer, o.AdditionalSigningKeys, o.AdditionalEncryptionKeys})
	if err != nil {
		return nil, err
	}
	return New(ctx, Options{
		Name:          o.Name,
		Issuer:        o.Issuer,
		ClientID:      o.ClientID,
		RedirectURI:   o.RedirectURI,
		Scopes:        o.Scopes,
		AcrValues:     o.AcrValues,
		FetchUserInfo: true,
	}, deps)
}

// NewMyinfoBusiness constructs a Myinfo Business (Corppass) relying party. It
// presets FetchUserInfo and defaults to the Corppass issuer.
func NewMyinfoBusiness(ctx context.Context, o MyinfoBusinessOptions, deps Dependencies) (*Client, error) {
	if o.Name == "" {
		o.Name = "myinfobiz"
	}
	if o.Issuer == "" {
		_, o.Issuer = o.Environment.issuers()
	}
	deps = o.Environment.forEnvironment(deps)
	deps, err := ensureKeyDeps(ctx, deps, keyMaterial{o.SigningKey, o.SigningKID, o.EncryptionKey, o.EncryptionKID, o.EncryptionAgreer, o.AdditionalSigningKeys, o.AdditionalEncryptionKeys})
	if err != nil {
		return nil, err
	}
	return New(ctx, Options{
		Name:                            o.Name,
		Issuer:                          o.Issuer,
		ClientID:                        o.ClientID,
		RedirectURI:                     o.RedirectURI,
		Scopes:                          o.Scopes,
		AcrValues:                       o.AcrValues,
		FetchUserInfo:                   true,
		TolerateUserInfoSubjectClientID: o.TolerateUserInfoSubjectClientID,
	}, deps)
}

// keyMaterial is the key fields common to the product options.
type keyMaterial struct {
	sig        crypto.Signer
	sigKID     string
	enc        *ecdsa.PrivateKey
	encKID     string
	agreer     keys.ECDHAgreer
	addSigning []PublishedKey
	addEnc     []DecryptionKey
}

// ensureKeyDeps builds deps.Keys and deps.Decryption from the supplied key
// material only when the caller left them nil, so an HSM/KMS caller that injects
// its own keys.KeyManager / keys.Decrypter is respected. For decryption a
// caller-supplied agreer (HSM/KMS) is preferred over the in-memory enc key.
// Rotation keys need the built ones: they can't be added to an injected
// KeyManager or Decrypter.
func ensureKeyDeps(ctx context.Context, deps Dependencies, k keyMaterial) (Dependencies, error) {
	if deps.Keys == nil {
		km, err := NewRotatingKeyManager(k.sig, k.sigKID, k.addSigning...)
		if err != nil {
			return deps, err
		}
		deps.Keys = km
	} else if len(k.addSigning) > 0 {
		return deps, errors.New("singpass: AdditionalSigningKeys can't be combined with Dependencies.Keys: build it with NewRotatingKeyManager")
	}
	if deps.Decryption == nil {
		agreer := k.agreer
		if agreer == nil {
			if k.enc == nil {
				return deps, errors.New("singpass: encryption key is required")
			}
			if k.encKID == "" {
				return deps, errors.New("singpass: the encryption key's kid is required: it's how Singpass finds the key in your JWKS")
			}
			encECDH, err := k.enc.ECDH()
			if err != nil {
				return deps, fmt.Errorf("singpass: convert encryption key to ECDH form: %w", err)
			}
			if agreer, err = keys.NewInMemoryECDH(encECDH, k.encKID); err != nil {
				return deps, fmt.Errorf("singpass: build encryption key backend: %w", err)
			}
		}
		dec, err := NewRotatingDecrypter(ctx, agreer, k.addEnc...)
		if err != nil {
			return deps, err
		}
		deps.Decryption = dec
	} else if len(k.addEnc) > 0 {
		return deps, errors.New("singpass: AdditionalEncryptionKeys can't be combined with Dependencies.Decryption: build it with NewRotatingDecrypter")
	}
	return deps, nil
}
