package singpass

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/idfoundry/fapigo/keys"
)

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
	encECDH, err := encKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("singpass: convert encryption key to ECDH form: %w", err)
	}
	agreer, err := keys.NewInMemoryECDH(encECDH, encKID)
	if err != nil {
		return nil, fmt.Errorf("singpass: build encryption key backend: %w", err)
	}
	decrypter, err := keys.NewSingleKeyDecrypter(agreer)
	if err != nil {
		return nil, fmt.Errorf("singpass: build decrypter: %w", err)
	}
	return decrypter, nil
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
	decrypter, err := keys.NewSingleKeyDecrypter(agreer)
	if err != nil {
		return nil, fmt.Errorf("singpass: build decrypter: %w", err)
	}
	return decrypter, nil
}
