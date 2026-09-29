package singpass_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// newLoginClient registers a Login client with a fresh fake server and
// returns the server and a client for it.
func newLoginClient(t *testing.T, deps singpass.Dependencies, register func(*singpasstest.Client)) (*singpasstest.Server, *singpass.Client) {
	t.Helper()
	srv, err := singpasstest.NewServer(singpasstest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	s1, e1 := genKey(t, "sig-1"), genKey(t, "enc-1")
	reg := singpasstest.Client{
		ID: "rp", App: singpasstest.Login, RedirectURIs: []string{"https://app.example/callback"},
		SigningKey: &s1.key.PublicKey, SigningKID: s1.kid, EncryptionKey: &e1.key.PublicKey, EncryptionKID: e1.kid,
	}
	if register != nil {
		register(&reg)
	}
	if err := srv.RegisterClient(reg); err != nil {
		t.Fatal(err)
	}
	deps.AllowLoopbackHTTP = true
	c, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		Issuer: srv.Issuer(), ClientID: "rp", RedirectURI: "https://app.example/callback", Scopes: []string{"openid"},
		SigningKey: s1.key, SigningKID: s1.kid, EncryptionKey: e1.key, EncryptionKID: e1.kid,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestServerErrorFromPAR(t *testing.T) {
	// Singpass verifies the client assertion against the registered key; a
	// different registered key makes PAR fail with invalid_client.
	_, c := newLoginClient(t, singpass.Dependencies{}, func(r *singpasstest.Client) {
		r.SigningKey = &genKey(t, "sig-1").key.PublicKey
	})
	_, _, err := c.BeginLogin(context.Background())
	resp, ok := singpass.ServerError(err)
	if !ok || resp.Code != "invalid_client" || resp.HTTPStatus < 400 {
		t.Fatalf("ServerError = %+v, %v (err %v)", resp, ok, err)
	}
	if singpass.ErrorCode(err) != "invalid_client" || singpass.IsTemporary(err) {
		t.Errorf("ErrorCode = %q, IsTemporary = %v", singpass.ErrorCode(err), singpass.IsTemporary(err))
	}
}

func TestErrorHelpersWithoutServerResponse(t *testing.T) {
	for _, err := range []error{nil, errors.New("boom"), fmt.Errorf("x: %w", singpass.ErrLoginExpired)} {
		if _, ok := singpass.ServerError(err); ok || singpass.ErrorCode(err) != "" || singpass.IsTemporary(err) {
			t.Errorf("%v: reported as a server error", err)
		}
	}
}

// A Login with an authentication context message completes against the fake
// server, which checks the message as Singpass does.
func TestLoginWithContextMessageEndToEnd(t *testing.T) {
	srv, c := newLoginClient(t, singpass.Dependencies{}, nil)
	redirect, state, err := c.BeginLoginWith(context.Background(), singpass.LoginContext{Message: "Log in to Example Bank"})
	if err != nil {
		t.Fatal(err)
	}
	callback, err := srv.Authorize(context.Background(), redirect)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), callback, state); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}
