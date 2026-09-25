package singpass

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// OfflineClientJWKS builds the public JWKS a relying party publishes during
// onboarding (the client-authentication signing key + the id_token/userinfo
// encryption key), without contacting the authorization server. Key-generation
// tooling runs before any client_id or discovery document exists, so there is no
// Client to call Client.PublicJWKS on yet.
//
// FAPIgo's keys.PublicJWKS assembles the set straight from key material and the
// declared algorithms — no client engine, issuer or endpoints required — so the
// caller carries no JWK marshaling of its own. It is the same library code the
// live client's PublicJWKS resolves through, so the offline and online sets are
// produced identically: the signing key under the ClientAuthentication purpose
// and the encryption key under IDTokenDecryption (the DPoP key is deliberately
// not published).
func OfflineClientJWKS(ctx context.Context, sigKey *ecdsa.PrivateKey, sigKID string, encKey *ecdsa.PrivateKey, encKID string) ([]byte, error) {
	km, err := NewKeyManager(sigKey, sigKID)
	if err != nil {
		return nil, err
	}
	decrypter, err := NewECDHDecrypter(encKey, encKID)
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
