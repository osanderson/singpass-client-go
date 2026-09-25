package singpass

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// OfflineClientJWKS builds the public JWKS a relying party publishes during
// onboarding (the client-authentication signing key + the id_token/userinfo
// encryption key), without contacting the authorization server. Key-generation
// tooling runs before any client_id or discovery document exists, so there is no
// Client to call Client.PublicJWKS on yet.
//
// It takes public keys only — a JWKS publishes nothing else — so an HSM/KMS
// deployment can produce it from the keys' exported public halves; with an
// in-memory key pass &priv.PublicKey.
//
// FAPIgo's keys.PublicJWKS assembles the set from key material and the declared
// algorithms — no client engine, issuer or endpoints required — and it is the
// same library code the live client's PublicJWKS resolves through, so the
// offline and online sets are produced identically: the signing key under the
// ClientAuthentication purpose and the encryption key under IDTokenDecryption
// (the DPoP key is deliberately not published).
func OfflineClientJWKS(ctx context.Context, sigKey *ecdsa.PublicKey, sigKID string, encKey *ecdsa.PublicKey, encKID string) ([]byte, error) {
	if sigKey == nil || encKey == nil {
		return nil, errors.New("singpass: OfflineClientJWKS needs both public keys")
	}
	km, err := NewKeyManager(publicOnlySigner{sigKey}, sigKID)
	if err != nil {
		return nil, err
	}
	encPub, err := encKey.ECDH()
	if err != nil {
		return nil, err
	}
	decrypter, err := NewAgreerDecrypter(publicOnlyAgreer{kid: encKID, pub: encPub})
	if err != nil {
		return nil, err
	}

	set, err := keys.PublicJWKS(ctx,
		[]keys.SigningKeyUse{{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256}},
		[]keys.EncryptionKeyUse{{Decrypter: decrypter, Purpose: keys.IDTokenDecryption, Algorithm: fapi.ECDHESA256KW}},
	)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(set, "", "  ")
}

// errPublicKeyOnly is returned if a public-key-only stand-in is ever asked to
// sign or decrypt; building a JWKS never does either.
var errPublicKeyOnly = errors.New("singpass: public key only")

// publicOnlySigner lets a bare public key stand in for the signing key when
// only its public half is needed.
type publicOnlySigner struct{ pub *ecdsa.PublicKey }

func (s publicOnlySigner) Public() crypto.PublicKey { return s.pub }
func (publicOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errPublicKeyOnly
}

// publicOnlyAgreer does the same for the encryption key.
type publicOnlyAgreer struct {
	kid string
	pub *ecdh.PublicKey
}

func (a publicOnlyAgreer) PublicKey(context.Context) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: a.kid, PublicKey: a.pub}, nil
}
func (publicOnlyAgreer) AgreeSharedSecret(context.Context, string, *ecdh.PublicKey) ([]byte, error) {
	return nil, errPublicKeyOnly
}
