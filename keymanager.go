package singpass

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// NewKeyManager builds the keys.KeyManager FAPIgo uses for the two signing
// operations a relying party performs:
//
//   - keys.ClientAuthentication — signs the private_key_jwt client assertion
//     with the persistent EC key whose public half is registered with the
//     authorization server under "use":"sig".
//   - keys.DPoPProofSigning — signs DPoP proofs (RFC 9449) with an ephemeral
//     EC key generated here at startup. A DPoP key is sender-constraining and
//     per-instance; it is never pre-registered, so it deliberately does not
//     survive a restart.
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
func NewKeyManager(sig crypto.Signer, sigKID string) (keys.KeyManager, error) {
	if sig == nil {
		return nil, fmt.Errorf("singpass: client authentication key is required")
	}
	// The ephemeral DPoP key. NewKeyManagerFromSigners validates its curve
	// (and the client-auth key's) against ES256, so no explicit check here.
	dpop, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("singpass: generate ephemeral DPoP key: %w", err)
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
	return km, nil
}
