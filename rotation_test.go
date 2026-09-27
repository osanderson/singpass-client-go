package singpass_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

type kidKey struct {
	key *ecdsa.PrivateKey
	kid string
}

func genKey(t *testing.T, kid string) kidKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kidKey{k, kid}
}

// rotationLogin registers a Myinfo client with the fake server under the keys
// Singpass would have fetched (registeredSig, registeredEnc), builds the client
// from opts, and runs a login. It returns the client and the login's error.
func rotationLogin(t *testing.T, registeredSig, registeredEnc kidKey, opts singpass.MyinfoOptions) (*singpass.Client, error) {
	t.Helper()
	ctx := context.Background()
	srv, err := singpasstest.NewServer(singpasstest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := srv.RegisterClient(singpasstest.Client{
		ID: "rp", App: singpasstest.Myinfo,
		RedirectURIs: []string{"https://app.example/callback"},
		Scopes:       []string{"name"},
		SigningKey:   &registeredSig.key.PublicKey, SigningKID: registeredSig.kid,
		EncryptionKey: &registeredEnc.key.PublicKey, EncryptionKID: registeredEnc.kid,
	}); err != nil {
		t.Fatal(err)
	}
	opts.Issuer, opts.ClientID, opts.RedirectURI = srv.Issuer(), "rp", "https://app.example/callback"
	opts.Scopes = []string{"openid", "name"}
	client, err := singpass.NewMyinfo(ctx, opts, singpass.Dependencies{AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	redirect, state, err := client.BeginLogin(ctx)
	if err != nil {
		return client, err
	}
	callback, err := srv.Authorize(ctx, redirect)
	if err != nil {
		return client, err
	}
	id, err := client.Complete(ctx, callback, state)
	if err == nil && id.Myinfo.PersonProfile().Name.String() == "" {
		t.Error("no person data after login")
	}
	return client, err
}

func jwksKIDs(t *testing.T, c *singpass.Client) []string {
	t.Helper()
	raw, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []struct{ Kid, Use string } `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.Use+":"+k.Kid)
	}
	slices.Sort(out)
	return out
}

func TestSigningKeyRotation(t *testing.T) {
	s1, s2, e1 := genKey(t, "sig-1"), genKey(t, "sig-2"), genKey(t, "enc-1")

	// Step 1: the next key is published but the client still signs with s1.
	c, err := rotationLogin(t, s1, e1, singpass.MyinfoOptions{
		SigningKey: s1.key, SigningKID: s1.kid, EncryptionKey: e1.key, EncryptionKID: e1.kid,
		AdditionalSigningKeys: []singpass.PublishedKey{{Key: &s2.key.PublicKey, KID: s2.kid}},
	})
	if err != nil {
		t.Fatalf("login while publishing the next key: %v", err)
	}
	if got, want := jwksKIDs(t, c), []string{"enc:enc-1", "sig:sig-1", "sig:sig-2"}; !slices.Equal(got, want) {
		t.Errorf("JWKS = %v, want %v", got, want)
	}
	// The offline JWKS for the same keys matches the client's.
	offline, err := singpass.OfflineJWKS(context.Background(),
		[]singpass.PublishedKey{{Key: &s1.key.PublicKey, KID: s1.kid}, {Key: &s2.key.PublicKey, KID: s2.kid}},
		[]singpass.PublishedKey{{Key: &e1.key.PublicKey, KID: e1.kid}})
	if err != nil {
		t.Fatal(err)
	}
	live, _ := c.PublicJWKS(context.Background())
	if string(offline) != string(live) {
		t.Errorf("OfflineJWKS differs from PublicJWKS:\n%s\n%s", offline, live)
	}

	// Step 2: the client signs with s2 once Singpass knows it.
	if _, err := rotationLogin(t, s2, e1, singpass.MyinfoOptions{
		SigningKey: s2.key, SigningKID: s2.kid, EncryptionKey: e1.key, EncryptionKID: e1.kid,
	}); err != nil {
		t.Fatalf("login after the switch: %v", err)
	}
}

func TestEncryptionKeyRotation(t *testing.T) {
	s1, e1, e2 := genKey(t, "sig-1"), genKey(t, "enc-1"), genKey(t, "enc-2")
	step1 := singpass.MyinfoOptions{
		SigningKey: s1.key, SigningKID: s1.kid, EncryptionKey: e1.key, EncryptionKID: e1.kid,
		AdditionalEncryptionKeys: []singpass.DecryptionKey{{Key: e2.key, KID: e2.kid}},
	}
	// Step 1: both keys are published, and tokens encrypted to either decrypt.
	for _, registered := range []kidKey{e1, e2} {
		c, err := rotationLogin(t, s1, registered, step1)
		if err != nil {
			t.Fatalf("login with tokens encrypted to %s: %v", registered.kid, err)
		}
		if got, want := jwksKIDs(t, c), []string{"enc:enc-1", "enc:enc-2", "sig:sig-1"}; !slices.Equal(got, want) {
			t.Errorf("JWKS = %v, want %v", got, want)
		}
	}

	// Step 2: e2 is current; e1 is no longer published but still decrypts
	// tokens Singpass encrypts to it until it re-fetches the JWKS.
	step2 := singpass.MyinfoOptions{
		SigningKey: s1.key, SigningKID: s1.kid, EncryptionKey: e2.key, EncryptionKID: e2.kid,
		AdditionalEncryptionKeys: []singpass.DecryptionKey{{Key: e1.key, KID: e1.kid, DecryptOnly: true}},
	}
	c, err := rotationLogin(t, s1, e1, step2)
	if err != nil {
		t.Fatalf("login with tokens encrypted to the decrypt-only key: %v", err)
	}
	if got, want := jwksKIDs(t, c), []string{"enc:enc-2", "sig:sig-1"}; !slices.Equal(got, want) {
		t.Errorf("JWKS = %v, want %v", got, want)
	}

	// A token encrypted to a key the client doesn't hold names the kid.
	_, err = rotationLogin(t, s1, genKey(t, "enc-9"), singpass.MyinfoOptions{
		SigningKey: s1.key, SigningKID: s1.kid, EncryptionKey: e1.key, EncryptionKID: e1.kid,
	})
	if err == nil || !strings.Contains(err.Error(), `kid "enc-9"`) {
		t.Errorf("unknown key: %v", err)
	}
}

func TestRotationKeyValidation(t *testing.T) {
	ctx := context.Background()
	s1, e1 := genKey(t, "sig-1"), genKey(t, "enc-1")
	if _, err := singpass.NewRotatingKeyManager(s1.key, "sig-1", singpass.PublishedKey{Key: &s1.key.PublicKey, KID: "sig-1"}); err == nil {
		t.Error("duplicate signing kid accepted")
	}
	if _, err := singpass.NewRotatingKeyManager(s1.key, "sig-1", singpass.PublishedKey{Key: &s1.key.PublicKey}); err == nil {
		t.Error("published key without kid accepted")
	}
	agreer, err := singpass.NewECDHDecrypter(e1.key, "enc-1")
	if err != nil || agreer == nil {
		t.Fatal(err)
	}
	if _, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
		ClientID: "rp", RedirectURI: "https://app.example/cb", Scopes: []string{"openid"},
		SigningKey: s1.key, SigningKID: "sig-1", EncryptionKey: e1.key, EncryptionKID: "enc-1",
		AdditionalEncryptionKeys: []singpass.DecryptionKey{{Key: e1.key, KID: "enc-1"}},
	}, singpass.Dependencies{}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("duplicate encryption kid: %v", err)
	}
	if _, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
		ClientID: "rp", RedirectURI: "https://app.example/cb", Scopes: []string{"openid"},
		SigningKey: s1.key, SigningKID: "sig-1",
		AdditionalEncryptionKeys: []singpass.DecryptionKey{{Key: e1.key, KID: "enc-2"}},
	}, singpass.Dependencies{Decryption: agreer}); err == nil || !strings.Contains(err.Error(), "NewRotatingDecrypter") {
		t.Errorf("rotation keys with injected Decryption: %v", err)
	}
}
