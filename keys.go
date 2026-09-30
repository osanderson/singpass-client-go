package singpass

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// NewKeyManager builds the keys.KeyManager FAPIgo uses for the two signing
// operations a relying party performs:
//
//   - keys.ClientAuthentication — signs the private_key_jwt client assertion
//     with the persistent EC key whose public half is registered with the
//     authorization server under "use":"sig".
//   - keys.DPoPProofSigning — signs DPoP proofs (RFC 9449) with an EC key
//     generated here at startup. It is never registered, but Singpass binds
//     each authorization code to the DPoP key the login started with, so a
//     callback that reaches another instance, or this one after a restart,
//     fails with invalid_dpop_proof. That suits one long-lived instance in
//     development; AssuranceProduction refuses it. Use NewKeyManagerWithDPoP
//     to give every instance the same DPoP key.
//
// sig is any crypto.Signer over an ES256 / P-256 key: a plain *ecdsa.PrivateKey
// held in memory, or an HSM/KMS-backed signer. FAPIgo's
// keys.NewKeyManagerFromSigners adapts it directly — it routes the pre-hashed
// digest, selects crypto.SignerOpts, and validates the ES256 / P-256 curve
// requirement at construction — so there is no signing glue here.
//
// The id_token encryption key is NOT handled here — FAPIgo never signs with it.
// It is used only for JWE decryption, driven through the separate keys.Decrypter
// (see NewECDHDecrypter), which is why it lives outside the KeyManager contract.
func NewKeyManager(sig crypto.Signer, sigKID string) (KeyManager, error) {
	return newKeyManager(sig, sigKID, nil)
}

// NewKeyManagerWithDPoP is NewRotatingKeyManager with dpop, an ES256 / P-256
// key, as the DPoP key in place of one generated at startup. Give every
// instance of the app the same dpop, loaded like the signing key (from a file
// or secret store, or an HSM/KMS signer), so a login can finish on whichever
// instance the callback reaches, and survive a restart: Singpass binds each
// authorization code to the DPoP key the login started with. The DPoP key is
// never published or registered.
func NewKeyManagerWithDPoP(sig crypto.Signer, sigKID string, dpop crypto.Signer, published ...PublishedKey) (KeyManager, error) {
	if dpop == nil {
		return nil, errors.New("singpass: the DPoP key is nil")
	}
	return newRotatingKeyManager(sig, sigKID, dpop, published)
}

// newKeyManager builds the key manager over sig and dpop, generating a DPoP
// key when dpop is nil.
func newKeyManager(sig crypto.Signer, sigKID string, dpop crypto.Signer) (*rotatingKeyManager, error) {
	if sig == nil {
		return nil, fmt.Errorf("singpass: client authentication key is required")
	}
	if sigKID == "" {
		return nil, fmt.Errorf("singpass: the signing key's kid is required: it's how Singpass finds the key in your JWKS")
	}
	// NewKeyManagerFromSigners validates the DPoP key's curve (and the
	// client-auth key's) against ES256, so no explicit check here.
	ephemeral := dpop == nil
	if ephemeral {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("singpass: generate ephemeral DPoP key: %w", err)
		}
		dpop = generated
	}

	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{
			keys.ClientAuthentication: sig,
			keys.DPoPProofSigning:     dpop,
		},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{
			keys.ClientAuthentication: fapi.ES256,
			keys.DPoPProofSigning:     fapi.ES256,
		},
		map[keys.SigningPurpose]string{
			keys.ClientAuthentication: sigKID,
			keys.DPoPProofSigning:     "dpop-1",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("singpass: build key manager: %w", err)
	}
	return &rotatingKeyManager{KeyManager: km, ephemeralDPoP: ephemeral}, nil
}

// NewECDHDecrypter builds the keys.Decrypter FAPIgo uses to unwrap the JWE
// content-encryption key of the id_token and /userinfo response. The encryption
// key stays in process as an in-memory ECDH backend; FAPIgo owns the ECDH-ES
// Concat-KDF + RFC-3394 key-unwrap. One decrypter serves both the id_token and
// the /userinfo response (keys.IDTokenDecryption + keys.UserInfoDecryption).
//
// The private key never leaves this process. A KMS/HSM deployment would instead
// implement keys.ECDHAgreer / keys.KeyDecrypter over its own backend and inject
// the result via Dependencies.Decryption.
func NewECDHDecrypter(encKey *ecdsa.PrivateKey, encKID string) (Decrypter, error) {
	if encKey == nil {
		return nil, fmt.Errorf("singpass: encryption key is required")
	}
	if encKID == "" {
		return nil, fmt.Errorf("singpass: the encryption key's kid is required: it's how Singpass finds the key in your JWKS")
	}
	encECDH, err := encKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("singpass: convert encryption key to ECDH form: %w", err)
	}
	agreer, err := keys.NewInMemoryECDH(encECDH, encKID)
	if err != nil {
		return nil, fmt.Errorf("singpass: build encryption key backend: %w", err)
	}
	return NewRotatingDecrypter(context.Background(), agreer)
}

// NewAgreerDecrypter builds the keys.Decrypter from a caller-supplied
// keys.ECDHAgreer instead of an in-memory private key. This is the ergonomic
// seam for an HSM/KMS deployment: the agreer performs the ECDH key-agreement
// step (an HSM's CKM_ECDH1_DERIVE or a managed KMS's DeriveSharedSecret) without
// the encryption private key ever entering this process, while FAPIgo still owns
// the Concat-KDF + RFC-3394 unwrap. It parallels NewKeyManager accepting a
// crypto.Signer, so hardware-backed decryption sits on the same footing as
// hardware-backed signing. One decrypter serves both the id_token and the
// /userinfo response. There is no kid parameter: the agreer reports its own key
// id (keys.RecipientKey), which is what the published JWKS and JWE "kid"
// matching use.
func NewAgreerDecrypter(agreer ECDHAgreer) (Decrypter, error) {
	if agreer == nil {
		return nil, fmt.Errorf("singpass: encryption agreer is required")
	}
	return NewRotatingDecrypter(context.Background(), agreer)
}

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
	return OfflineJWKS(ctx, []PublishedKey{{Key: sigKey, KID: sigKID}}, []PublishedKey{{Key: encKey, KID: encKID}})
}

// OfflineJWKS is OfflineClientJWKS for any number of keys, e.g. to publish a
// static JWKS during a key rotation (see docs/production.md): every signing
// and encryption key is published under its kid, and the result equals
// Client.PublicJWKS for a client holding those keys, with the first of each
// list as the current key.
func OfflineJWKS(ctx context.Context, signing, encryption []PublishedKey) ([]byte, error) {
	if len(signing) == 0 || len(encryption) == 0 {
		return nil, errors.New("singpass: OfflineJWKS needs at least one signing and one encryption key")
	}
	if signing[0].Key == nil {
		return nil, fmt.Errorf("singpass: signing key %q has no public key", signing[0].KID)
	}
	km, err := NewRotatingKeyManager(publicOnlySigner{signing[0].Key}, signing[0].KID, signing[1:]...)
	if err != nil {
		return nil, err
	}
	agreers := make([]keys.ECDHAgreer, len(encryption))
	for i, e := range encryption {
		if e.Key == nil {
			return nil, fmt.Errorf("singpass: encryption key %q has no public key", e.KID)
		}
		pub, err := e.Key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("singpass: encryption key %q: %w", e.KID, err)
		}
		agreers[i] = publicOnlyAgreer{kid: e.KID, pub: pub}
	}
	others := make([]DecryptionKey, 0, len(agreers)-1)
	for _, a := range agreers[1:] {
		others = append(others, DecryptionKey{Agreer: a})
	}
	decrypter, err := NewRotatingDecrypter(ctx, agreers[0], others...)
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
	extra, err := publishedEncryptionKeys(ctx, decrypter, fapi.ECDHESA256KW)
	if err != nil {
		return nil, err
	}
	set.Keys = appendNewKIDs(set.Keys, extra)
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
