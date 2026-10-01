package singpasstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/osanderson/singpass-client-go/myinfo"
)

// The built-in test clients' IDs. RegisterTestClients registers them, so an
// app can log in without registering a client or making keys.
const (
	// TestClientLogin is a Singpass Login client allowed every Login scope.
	TestClientLogin = "login-test"
	// TestClientMyinfo is a Myinfo client allowed every Myinfo scope.
	TestClientMyinfo = "myinfo-test"
	// TestClientMyinfoBusiness is a Corppass Myinfo Business client allowed
	// every Myinfo Business scope.
	TestClientMyinfoBusiness = "myinfo-business-test"
)

// The key IDs of the test clients' keys.
const (
	TestClientSigningKID    = "test-client-sig"
	TestClientEncryptionKID = "test-client-enc"
)

// testClientKeysPath is where a server with test clients serves their
// private keys, under its base URL.
const testClientKeysPath = "/_fake/test-client/"

// The test clients' private keys: fixed, so an app configured once keeps
// working, and published, so they protect nothing. Every test client shares
// them.
var (
	testClientSigningKey    = mustRawKey("1461bebfe50e926790c237a4562644e9ae9f8d2dbb57aa8001d5600cc93de164")
	testClientEncryptionKey = mustRawKey("e433d1a25014e03f04d362fb2e41aa395cb20c62a3771bda038dac2de7ab137b")
)

func mustRawKey(d string) *ecdsa.PrivateKey {
	raw, err := hex.DecodeString(d)
	if err != nil {
		panic(err)
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		panic(err)
	}
	return k
}

// TestClientKeys returns the test clients' signing and encryption keys.
// They are published — anyone can sign as a test client — so use them only
// with this fake.
func TestClientKeys() (signing, encryption *ecdsa.PrivateKey) {
	return testClientSigningKey, testClientEncryptionKey
}

// TestClientJWKS returns the test clients' keys as a JWKS including the
// private keys, for an app that reads its keys from a JWK. A server with
// test clients also serves it at /_fake/test-client/jwks.json, and the keys
// as PKCS#8 PEM at sig.pem and enc.pem beside it.
func TestClientJWKS() []byte {
	jwks, err := json.MarshalIndent(map[string]any{"keys": []map[string]string{
		privateJWK(testClientSigningKey, TestClientSigningKID, "sig", "ES256"),
		privateJWK(testClientEncryptionKey, TestClientEncryptionKID, "enc", "ECDH-ES+A256KW"),
	}}, "", "  ")
	if err != nil {
		panic(err)
	}
	return jwks
}

func privateJWK(k *ecdsa.PrivateKey, kid, use, alg string) map[string]string {
	pub, err := k.PublicKey.Bytes() // 0x04 || x || y
	if err != nil {
		panic(err)
	}
	d, err := k.Bytes()
	if err != nil {
		panic(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return map[string]string{
		"kty": "EC", "crv": "P-256", "kid": kid, "use": use, "alg": alg,
		"x": b64(pub[1:33]), "y": b64(pub[33:]), "d": b64(d),
	}
}

func pkcs8PEM(k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// RegisterTestClients registers the built-in test clients for the server's
// issuer — TestClientLogin and TestClientMyinfo on Singpass,
// TestClientMyinfoBusiness on Corppass — each allowed every scope and any
// loopback redirect URI, with the keys TestClientKeys returns. The server
// then serves those keys under /_fake/test-client/.
func (s *Server) RegisterTestClients() error {
	sig, enc := TestClientKeys()
	clients := []Client{
		{ID: TestClientLogin, App: Login, Scopes: []string{"user.identity", "name", "email", "mobileno"}},
		{ID: TestClientMyinfo, App: Myinfo, Scopes: myinfo.AllScopes()},
	}
	if s.cfg.Issuer == Corppass {
		clients = []Client{{ID: TestClientMyinfoBusiness, App: Myinfo, Scopes: myinfo.AllBusinessScopes()}}
	}
	for _, c := range clients {
		c.AnyLoopbackRedirectURI = true
		c.SigningKey, c.SigningKID = &sig.PublicKey, TestClientSigningKID
		c.EncryptionKey, c.EncryptionKID = &enc.PublicKey, TestClientEncryptionKID
		if err := s.RegisterClient(c); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.testClients = true
	s.mu.Unlock()
	return nil
}

// TestClients returns the IDs of the test clients registered on the server:
// none until RegisterTestClients.
func (s *Server) TestClients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.testClients:
		return nil
	case s.cfg.Issuer == Corppass:
		return []string{TestClientMyinfoBusiness}
	default:
		return []string{TestClientLogin, TestClientMyinfo}
	}
}

// TestClientKeysURL is where the server serves the test clients' private
// JWKS once RegisterTestClients has run.
func (s *Server) TestClientKeysURL() string {
	return s.base + testClientKeysPath + "jwks.json"
}

func (s *Server) handleTestClientKeys(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	on := s.testClients
	s.mu.Unlock()
	if !on {
		http.NotFound(w, r)
		return
	}
	switch r.PathValue("file") {
	case "jwks.json":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(TestClientJWKS())
	case "sig.pem":
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pkcs8PEM(testClientSigningKey))
	case "enc.pem":
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pkcs8PEM(testClientEncryptionKey))
	default:
		http.NotFound(w, r)
	}
}
