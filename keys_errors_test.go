package singpass

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// Each key constructor names what's wrong with the key material it's given.
func TestKeyConstructorErrors(t *testing.T) {
	ctx := context.Background()
	key := newECKey(t)
	pub := &key.PublicKey
	agreer, err := keys.NewInMemoryECDH(mustECDH(t, key), "enc-1")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		err  func() error
		want string
	}{
		"NewKeyManager without a key":      {func() error { _, err := NewKeyManager(nil, "s"); return err }, "authentication key is required"},
		"NewKeyManager without a kid":      {func() error { _, err := NewKeyManager(key, ""); return err }, "kid is required"},
		"NewECDHDecrypter without a key":   {func() error { _, err := NewECDHDecrypter(nil, "e"); return err }, "encryption key is required"},
		"NewAgreerDecrypter without one":   {func() error { _, err := NewAgreerDecrypter(nil); return err }, "agreer is required"},
		"NewRotatingDecrypter without one": {func() error { _, err := NewRotatingDecrypter(ctx, nil); return err }, "agreer is required"},
		"OfflineJWKS without keys":         {func() error { _, err := OfflineJWKS(ctx, nil, nil); return err }, "at least one signing and one encryption key"},
		"OfflineJWKS with a nil signing key": {func() error {
			_, err := OfflineJWKS(ctx, []PublishedKey{{KID: "s"}}, []PublishedKey{{Key: pub, KID: "e"}})
			return err
		}, `signing key "s" has no public key`},
		"OfflineJWKS with a nil encryption key": {func() error {
			_, err := OfflineJWKS(ctx, []PublishedKey{{Key: pub, KID: "s"}}, []PublishedKey{{KID: "e"}})
			return err
		}, `encryption key "e" has no public key`},
		"OfflineClientJWKS without keys": {func() error { _, err := OfflineClientJWKS(ctx, nil, "s", nil, "e"); return err }, "needs both public keys"},
		"additional key with neither": {func() error {
			_, err := NewRotatingDecrypter(ctx, agreer, DecryptionKey{KID: "old"})
			return err
		}, "neither Key nor Agreer"},
		"additional key without a kid": {func() error {
			_, err := NewRotatingDecrypter(ctx, agreer, DecryptionKey{Key: newECKey(t)})
			return err
		}, "has no kid"},
		"additional key reusing a kid": {func() error {
			_, err := NewRotatingDecrypter(ctx, agreer, DecryptionKey{Key: newECKey(t), KID: "enc-1"})
			return err
		}, "used more than once"},
	} {
		if err := tc.err(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// NewAgreerDecrypter takes an HSM/KMS-style agreer and reports its kid.
func TestNewAgreerDecrypter(t *testing.T) {
	agreer, err := keys.NewInMemoryECDH(mustECDH(t, newECKey(t)), "hsm-enc")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewAgreerDecrypter(agreer)
	if err != nil {
		t.Fatal(err)
	}
	info, err := dec.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.ECDHESA256KW)
	if err != nil || info.KeyID != "hsm-enc" {
		t.Errorf("EncryptionPublicKey = %+v, %v; want kid hsm-enc", info, err)
	}
}

// The public-key-only stand-ins used to build a JWKS refuse to sign or
// decrypt.
func TestPublicKeyOnlyStandIns(t *testing.T) {
	key := newECKey(t)
	if _, err := (publicOnlySigner{&key.PublicKey}).Sign(nil, []byte("digest"), nil); !errors.Is(err, errPublicKeyOnly) {
		t.Errorf("Sign = %v", err)
	}
	if _, err := (publicOnlyAgreer{kid: "e"}).AgreeSharedSecret(context.Background(), "e", nil); !errors.Is(err, errPublicKeyOnly) {
		t.Errorf("AgreeSharedSecret = %v", err)
	}
}

func mustECDH(t *testing.T, k *ecdsa.PrivateKey) *ecdh.PrivateKey {
	t.Helper()
	e, err := k.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return e
}
