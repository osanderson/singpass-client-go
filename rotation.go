package singpass

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// PublishedKey is a public key and its kid, as published in the client's
// JWKS. In AdditionalSigningKeys it is a signing key published alongside the
// current one but never used to sign: during a rotation, the incoming key
// before the switch. See docs/production.md.
type PublishedKey struct {
	Key *ecdsa.PublicKey // P-256
	KID string
}

// DecryptionKey is an encryption key the client holds alongside its current
// one during a rotation: published in the JWKS and used to decrypt the tokens
// encrypted to it, selected by the JWE "kid". Set Key and KID for an in-memory
// key, or Agreer for an HSM/KMS key (its kid comes from the agreer). See
// docs/production.md.
type DecryptionKey struct {
	Key    *ecdsa.PrivateKey
	KID    string
	Agreer ECDHAgreer

	// DecryptOnly keeps the key for decryption but leaves it out of the
	// JWKS: the outgoing key, once it's no longer published, until Singpass
	// has re-fetched the JWKS and stopped encrypting to it.
	DecryptOnly bool
}

// NewRotatingKeyManager is NewKeyManager plus signing keys that are published
// in the JWKS but never used to sign, for a signing-key rotation.
func NewRotatingKeyManager(sig crypto.Signer, sigKID string, published ...PublishedKey) (KeyManager, error) {
	km, err := NewKeyManager(sig, sigKID)
	if err != nil || len(published) == 0 {
		return km, err
	}
	seen := map[string]bool{sigKID: true}
	infos := make([]keys.PublicKeyInfo, 0, len(published))
	for _, p := range published {
		switch {
		case p.Key == nil:
			return nil, fmt.Errorf("singpass: published signing key %q has no public key", p.KID)
		case p.Key.Curve != elliptic.P256():
			return nil, fmt.Errorf("singpass: published signing key %q must be P-256", p.KID)
		case p.KID == "":
			return nil, errors.New("singpass: a published signing key has no kid")
		case seen[p.KID]:
			return nil, fmt.Errorf("singpass: signing key kid %q is used more than once", p.KID)
		}
		seen[p.KID] = true
		infos = append(infos, keys.PublicKeyInfo{KeyID: p.KID, PublicKey: p.Key})
	}
	return rotatingKeyManager{KeyManager: km, published: infos}, nil
}

// rotatingKeyManager signs with its KeyManager's key and, through FAPIgo's
// keys.RotatingKeyManager, publishes the extra client-authentication keys too.
type rotatingKeyManager struct {
	keys.KeyManager
	published []keys.PublicKeyInfo
}

func (m rotatingKeyManager) PublicKeys(ctx context.Context, purpose keys.SigningPurpose, alg fapi.SignatureAlgorithm) (keys.SigningKeySet, error) {
	current, err := m.PublicKey(ctx, purpose, alg)
	if err != nil {
		return keys.SigningKeySet{}, err
	}
	set := keys.SigningKeySet{Keys: []keys.PublicKeyInfo{current}}
	if purpose == keys.ClientAuthentication {
		set.Keys = append(set.Keys, m.published...)
	}
	return set, nil
}

// NewRotatingDecrypter is NewAgreerDecrypter over several encryption keys, for
// an encryption-key rotation: it decrypts with whichever key a token's JWE
// "kid" names (current when the token names none), and Client.PublicJWKS
// publishes current and every key in others not marked DecryptOnly.
func NewRotatingDecrypter(ctx context.Context, current ECDHAgreer, others ...DecryptionKey) (Decrypter, error) {
	if current == nil {
		return nil, errors.New("singpass: encryption agreer is required")
	}
	cur, err := current.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("singpass: encryption key: %w", err)
	}
	if cur.KeyID == "" {
		return nil, errors.New("singpass: the encryption key's kid is required: it's how Singpass finds the key in your JWKS")
	}
	d := &rotatingDecrypter{byKID: map[string]keys.ECDHAgreer{cur.KeyID: current}, current: current}
	for _, o := range others {
		a := o.Agreer
		if a == nil {
			if o.Key == nil {
				return nil, fmt.Errorf("singpass: additional encryption key %q has neither Key nor Agreer", o.KID)
			}
			if o.KID == "" {
				return nil, errors.New("singpass: an additional encryption key has no kid")
			}
			ecdhKey, err := o.Key.ECDH()
			if err != nil {
				return nil, fmt.Errorf("singpass: additional encryption key %q: %w", o.KID, err)
			}
			if a, err = keys.NewInMemoryECDH(ecdhKey, o.KID); err != nil {
				return nil, fmt.Errorf("singpass: additional encryption key %q: %w", o.KID, err)
			}
		}
		info, err := a.PublicKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("singpass: additional encryption key: %w", err)
		}
		switch {
		case info.KeyID == "":
			return nil, errors.New("singpass: an additional encryption key has no kid")
		case d.byKID[info.KeyID] != nil:
			return nil, fmt.Errorf("singpass: encryption key kid %q is used more than once", info.KeyID)
		}
		d.byKID[info.KeyID] = a
		if !o.DecryptOnly {
			d.published = append(d.published, a)
		}
	}
	d.Decrypter, err = keys.NewSingleKeyDecrypter(kidAgreer{d})
	if err != nil {
		return nil, fmt.Errorf("singpass: build decrypter: %w", err)
	}
	return d, nil
}

// rotatingDecrypter is a keys.Decrypter over several encryption keys. It
// reports current as its public key; published are the additional keys
// Client.PublicJWKS adds to the JWKS.
type rotatingDecrypter struct {
	keys.Decrypter
	current   keys.ECDHAgreer
	byKID     map[string]keys.ECDHAgreer
	published []keys.ECDHAgreer
}

// kidAgreer routes the ECDH step to the key the JWE "kid" names.
type kidAgreer struct{ d *rotatingDecrypter }

func (k kidAgreer) PublicKey(ctx context.Context) (keys.PublicKeyInfo, error) {
	return k.d.current.PublicKey(ctx)
}

func (k kidAgreer) AgreeSharedSecret(ctx context.Context, keyID string, epk *ecdh.PublicKey) ([]byte, error) {
	a := k.d.current
	if keyID != "" {
		if a = k.d.byKID[keyID]; a == nil {
			kids := make([]string, 0, len(k.d.byKID))
			for kid := range k.d.byKID {
				kids = append(kids, kid)
			}
			slices.Sort(kids)
			return nil, fmt.Errorf("singpass: token is encrypted to kid %q, but this client holds %q", keyID, kids)
		}
	}
	return a.AgreeSharedSecret(ctx, keyID, epk)
}

// publishedEncryptionKeys returns the JWKS entries for the additional
// encryption keys d publishes, for algorithm alg.
func publishedEncryptionKeys(ctx context.Context, d keys.Decrypter, alg fapi.KeyManagementAlgorithm) ([]keys.PublicJWK, error) {
	rd, ok := d.(*rotatingDecrypter)
	if !ok || len(rd.published) == 0 {
		return nil, nil
	}
	uses := make([]keys.EncryptionKeyUse, 0, len(rd.published))
	for _, a := range rd.published {
		dec, err := keys.NewSingleKeyDecrypter(a)
		if err != nil {
			return nil, err
		}
		uses = append(uses, keys.EncryptionKeyUse{Decrypter: dec, Purpose: keys.IDTokenDecryption, Algorithm: alg})
	}
	set, err := keys.PublicJWKS(ctx, nil, uses)
	if err != nil {
		return nil, err
	}
	return set.Keys, nil
}

// appendNewKIDs appends the keys of extra whose kid set doesn't have yet.
func appendNewKIDs(set, extra []keys.PublicJWK) []keys.PublicJWK {
	for _, k := range extra {
		if !slices.ContainsFunc(set, func(s keys.PublicJWK) bool { return s.KeyID() == k.KeyID() }) {
			set = append(set, k)
		}
	}
	return set
}
