package singpass_test

import (
	"context"
	"strings"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

// crossInstanceLogin starts a login on one client and finishes it on another,
// as when a callback reaches a different instance: both share the keys and
// the session store, and dpop is their DPoP key (nil: each generates its own).
func crossInstanceLogin(t *testing.T, dpop *kidKey) error {
	t.Helper()
	ctx := context.Background()
	sig, enc := genKey(t, "sig-1"), genKey(t, "enc-1")
	srv, err := singpasstest.NewServer(singpasstest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := srv.RegisterClient(singpasstest.Client{
		ID: "rp", App: singpasstest.Myinfo, RedirectURIs: []string{"https://app.example/callback"}, Scopes: []string{"name"},
		SigningKey: &sig.key.PublicKey, SigningKID: sig.kid, EncryptionKey: &enc.key.PublicKey, EncryptionKID: enc.kid,
	}); err != nil {
		t.Fatal(err)
	}
	shared := singpass.NewMemorySessionStore(0)
	instance := func() *singpass.Client {
		opts := singpass.MyinfoOptions{
			Issuer: srv.Issuer(), ClientID: "rp", RedirectURI: "https://app.example/callback", Scopes: []string{"openid", "name"},
			SigningKey: sig.key, SigningKID: sig.kid, EncryptionKey: enc.key, EncryptionKID: enc.kid,
		}
		if dpop != nil {
			opts.DPoPKey = dpop.key
		}
		c, err := singpass.NewMyinfo(ctx, opts, singpass.Dependencies{AllowLoopbackHTTP: true, Sessions: shared})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first, second := instance(), instance()
	redirect, state, err := first.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	callback, err := srv.Authorize(ctx, redirect)
	if err != nil {
		t.Fatal(err)
	}
	_, err = second.Complete(ctx, callback, state)
	return err
}

// With a shared DPoP key, a login started on one instance finishes on another.
func TestSharedDPoPKeySpansInstances(t *testing.T) {
	dpop := genKey(t, "")
	if err := crossInstanceLogin(t, &dpop); err != nil {
		t.Fatalf("login finished on another instance: %v", err)
	}
}

// Without one, the code is bound to the first instance's DPoP key and the
// second instance's token request is refused, as Singpass refuses it
// (invalid_dpop_proof there, invalid_grant from the fake server).
func TestPerProcessDPoPKeysDontSpanInstances(t *testing.T) {
	err := crossInstanceLogin(t, nil)
	if err == nil || !strings.Contains(err.Error(), "dpop_jkt") {
		t.Fatalf("err = %v, want the code's DPoP key binding to refuse it", err)
	}
}
