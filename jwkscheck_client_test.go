package singpass_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
	"github.com/osanderson/singpass-client-go/web"
)

func TestClientCheckPublishedJWKS(t *testing.T) {
	ctx := context.Background()
	srv, err := singpasstest.NewServer(singpasstest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	sig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := srv.RegisterClient(singpasstest.Client{
		ID: "my-app", App: singpasstest.Login,
		RedirectURIs: []string{"https://app.example/callback"},
		SigningKey:   &sig.PublicKey, SigningKID: "sig-1",
		EncryptionKey: &enc.PublicKey, EncryptionKID: "enc-1",
	}); err != nil {
		t.Fatal(err)
	}
	client, err := singpass.NewLogin(ctx, singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "my-app", RedirectURI: "https://app.example/callback",
		Scopes:     []string{"openid"},
		SigningKey: sig, SigningKID: "sig-1", EncryptionKey: enc, EncryptionKID: "enc-1",
	}, singpass.Dependencies{AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}

	// The web helper's JWKS route publishes exactly the client's set.
	jwks, err := client.PublicJWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := web.New(web.Config{Apps: []*web.App{{Name: "login", Auth: client, JWKS: jwks}}})
	app := httptest.NewServer(h.Mux())
	defer app.Close()
	if err := client.CheckPublishedJWKS(ctx, app.URL+"/login/jwks.json"); err != nil {
		t.Errorf("published JWKS: %v", err)
	}

	// A JWKS URL serving someone else's keys fails.
	stale := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer stale.Close()
	if err := client.CheckPublishedJWKS(ctx, stale.URL); err == nil || !strings.Contains(err.Error(), "missing the signing key") {
		t.Errorf("stale JWKS: %v", err)
	}
}
