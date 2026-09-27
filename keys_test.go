package singpass

import (
	"context"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// TestOfflineClientJWKSMatchesPrivateKeyPathAndLiveClient checks that building
// the JWKS from public keys alone yields exactly what the private-key managers
// produce, and exactly what a live Client publishes — so a JWKS registered at
// onboarding matches the running client.
func TestOfflineClientJWKSMatchesPrivateKeyPathAndLiveClient(t *testing.T) {
	ctx := context.Background()
	sig, enc := newECKey(t), newECKey(t)

	offline, err := OfflineClientJWKS(ctx, &sig.PublicKey, "sig-1", &enc.PublicKey, "enc-1")
	if err != nil {
		t.Fatalf("OfflineClientJWKS: %v", err)
	}

	km, err := NewKeyManager(sig, "sig-1")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewECDHDecrypter(enc, "enc-1")
	if err != nil {
		t.Fatal(err)
	}
	set, err := keys.PublicJWKS(ctx,
		[]keys.SigningKeyUse{{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256}},
		[]keys.EncryptionKeyUse{{Decrypter: dec, Purpose: keys.IDTokenDecryption, Algorithm: fapi.ECDHESA256KW}},
	)
	if err != nil {
		t.Fatal(err)
	}
	fromPrivate, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(offline) != string(fromPrivate) {
		t.Errorf("public-key JWKS differs from private-key JWKS:\n%s\nvs\n%s", offline, fromPrivate)
	}

	deps := Dependencies{Keys: km, Decryption: dec, HTTPClient: fakeIssuer(t, discoveryDoc())}
	c, err := New(ctx, baseOptions(), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	live, err := c.PublicJWKS(ctx)
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if !sameJSON(t, offline, live) {
		t.Errorf("offline JWKS differs from live client JWKS:\n%s\nvs\n%s", offline, live)
	}
}

func TestOfflineClientJWKSRequiresKeys(t *testing.T) {
	k := newECKey(t)
	if _, err := OfflineClientJWKS(context.Background(), nil, "s", &k.PublicKey, "e"); err == nil {
		t.Error("nil signing key accepted")
	}
	if _, err := OfflineClientJWKS(context.Background(), &k.PublicKey, "s", nil, "e"); err == nil {
		t.Error("nil encryption key accepted")
	}
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}
