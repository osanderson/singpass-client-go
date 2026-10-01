package singpasstest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/singpasstest"
)

func testClientServer(t *testing.T, issuer singpasstest.Issuer) *singpasstest.Server {
	t.Helper()
	srv := startServer(t, singpasstest.Config{Issuer: issuer})
	if err := srv.RegisterTestClients(); err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestTestClientsLogIn(t *testing.T) {
	sig, enc := singpasstest.TestClientKeys()
	ctx := context.Background()
	sp, cp := testClientServer(t, singpasstest.Singpass), testClientServer(t, singpasstest.Corppass)

	// Any loopback redirect URI works, on any port and path.
	lc, err := singpass.NewLogin(ctx, singpass.LoginOptions{
		Issuer: sp.Issuer(), ClientID: singpasstest.TestClientLogin, RedirectURI: "http://localhost:4321/auth/callback",
		Scopes:     []string{"openid", "user.identity", "name"},
		SigningKey: sig, SigningKID: singpasstest.TestClientSigningKID, EncryptionKey: enc, EncryptionKID: singpasstest.TestClientEncryptionKID,
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	if id := login(t, sp, lc); id.SubjectAttributes().IdentityNumber == "" {
		t.Errorf("Login: no identity number in %+v", id.SubjectAttributes())
	}

	mi, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
		Issuer: sp.Issuer(), ClientID: singpasstest.TestClientMyinfo, RedirectURI: "http://localhost:8080/cb",
		Scopes:     []string{"openid", "uinfin", "name", "cpfbalances.oa", "vehicles.make"},
		SigningKey: sig, SigningKID: singpasstest.TestClientSigningKID, EncryptionKey: enc, EncryptionKID: singpasstest.TestClientEncryptionKID,
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	if id := login(t, sp, mi); id.Myinfo.PersonProfile().Name.String() == "" {
		t.Error("Myinfo: no name")
	}

	mib, err := singpass.NewMyinfoBusiness(ctx, singpass.MyinfoBusinessOptions{
		Issuer: cp.Issuer(), ClientID: singpasstest.TestClientMyinfoBusiness, RedirectURI: "http://localhost:3000/callback",
		Scopes:     []string{"openid", "entity.basic_profile.name", "entity.address"},
		SigningKey: sig, SigningKID: singpasstest.TestClientSigningKID, EncryptionKey: enc, EncryptionKID: singpasstest.TestClientEncryptionKID,
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	if id := login(t, cp, mib); id.Myinfo.EntityProfile().Name.String() == "" {
		t.Error("Myinfo Business: no entity name")
	}

	if got := fmt.Sprint(sp.TestClients(), cp.TestClients()); got != "[login-test myinfo-test] [myinfo-business-test]" {
		t.Errorf("TestClients = %s", got)
	}
}

func TestTestClientsRefuseOtherRedirectURIs(t *testing.T) {
	sp := testClientServer(t, singpasstest.Singpass)
	sig, enc := singpasstest.TestClientKeys()
	c, err := singpass.NewMyinfo(context.Background(), singpass.MyinfoOptions{
		Issuer: sp.Issuer(), ClientID: singpasstest.TestClientMyinfo, RedirectURI: "https://rp.example/callback",
		Scopes:     []string{"openid", "name"},
		SigningKey: sig, SigningKID: singpasstest.TestClientSigningKID, EncryptionKey: enc, EncryptionKID: singpasstest.TestClientEncryptionKID,
	}, devDeps)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.BeginLogin(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect_uri") {
		t.Errorf("BeginLogin with a non-loopback redirect URI: err = %v", err)
	}
}

func TestTestClientsConcurrentRedirectURIs(t *testing.T) {
	sp := testClientServer(t, singpasstest.Singpass)
	sig, enc := singpasstest.TestClientKeys()
	var wg sync.WaitGroup
	for port := 5000; port < 5008; port++ {
		wg.Go(func() {
			ctx := context.Background()
			c, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
				Issuer: sp.Issuer(), ClientID: singpasstest.TestClientMyinfo, RedirectURI: fmt.Sprintf("http://localhost:%d/cb", port),
				Scopes:     []string{"openid", "name"},
				SigningKey: sig, SigningKID: singpasstest.TestClientSigningKID, EncryptionKey: enc, EncryptionKID: singpasstest.TestClientEncryptionKID,
			}, devDeps)
			if err != nil {
				t.Error(err)
				return
			}
			redirectURL, state, err := c.BeginLogin(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			query, err := sp.Authorize(ctx, redirectURL)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := c.Complete(ctx, query, state); err != nil {
				t.Errorf("port %d: %v", port, err)
			}
		})
	}
	wg.Wait()
}

func TestTestClientKeysServed(t *testing.T) {
	get := func(url string) (int, []byte) {
		t.Helper()
		res, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, body
	}
	off := startServer(t, singpasstest.Config{})
	if code, _ := get(off.TestClientKeysURL()); code != http.StatusNotFound {
		t.Errorf("keys served without test clients: %d", code)
	}

	sp := testClientServer(t, singpasstest.Singpass)
	sig, enc := singpasstest.TestClientKeys()
	code, body := get(sp.TestClientKeysURL())
	var jwks struct{ Keys []map[string]string }
	if err := json.Unmarshal(body, &jwks); code != http.StatusOK || err != nil || len(jwks.Keys) != 2 {
		t.Fatalf("jwks.json: %d %s", code, body)
	}
	if jwks.Keys[0]["kid"] != singpasstest.TestClientSigningKID || jwks.Keys[0]["d"] == "" || jwks.Keys[1]["use"] != "enc" {
		t.Errorf("jwks.json = %s", body)
	}
	for file, want := range map[string]*ecdsa.PrivateKey{"sig.pem": sig, "enc.pem": enc} {
		code, body := get(strings.TrimSuffix(sp.TestClientKeysURL(), "jwks.json") + file)
		block, _ := pem.Decode(body)
		if code != http.StatusOK || block == nil {
			t.Fatalf("%s: %d %s", file, code, body)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil || !want.Equal(k) {
			t.Errorf("%s: %v, or not the test client's key", file, err)
		}
	}
	if code, _ := get(strings.TrimSuffix(sp.TestClientKeysURL(), "jwks.json") + "other"); code != http.StatusNotFound {
		t.Errorf("unknown file: %d", code)
	}
}
