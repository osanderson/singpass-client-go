package singpasstest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// A complete Myinfo login against the fake server: register the client as
// onboarding would, then run BeginLogin, the browser step and Complete.
func Example() {
	ctx := context.Background()

	srv, err := singpasstest.NewServer(singpasstest.Config{}) // Singpass, auto-approving
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	sig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = srv.RegisterClient(singpasstest.Client{
		ID: "my-app", App: singpasstest.Myinfo,
		RedirectURIs: []string{"https://app.example/callback"},
		Scopes:       []string{"name", "regadd"},
		SigningKey:   &sig.PublicKey, SigningKID: "sig-1",
		EncryptionKey: &enc.PublicKey, EncryptionKID: "enc-1",
	})
	if err != nil {
		log.Fatal(err)
	}

	client, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
		Issuer:      srv.Issuer(),
		ClientID:    "my-app",
		RedirectURI: "https://app.example/callback",
		Scopes:      []string{"openid", "name", "regadd"},
		SigningKey:  sig, SigningKID: "sig-1",
		EncryptionKey: enc, EncryptionKID: "enc-1",
	}, singpass.Dependencies{AllowLoopbackHTTP: true})
	if err != nil {
		log.Fatal(err)
	}

	redirectURL, _, err := client.BeginLogin(ctx)
	if err != nil {
		log.Fatal(err)
	}
	callback, err := srv.Authorize(ctx, redirectURL) // what the browser would do
	if err != nil {
		log.Fatal(err)
	}
	id, err := client.Complete(ctx, callback)
	if err != nil {
		log.Fatal(err)
	}

	p := id.Myinfo.Person
	fmt.Println(p.Field("name").String())
	fmt.Println(p.Object("regadd").Field("postal").String())
	// Output:
	// TAN XIAO HUI
	// 460102
}
