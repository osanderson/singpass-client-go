package main

import "testing"

// FuzzParseJWKS: arbitrary JWKS never panic, and an accepted one yields
// both keys.
func FuzzParseJWKS(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","use":"sig","kid":"s","x":"AA","y":"AA"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","use":"enc","kid":"e","d":"x"}]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := parseJWKS(data)
		if err == nil && (c.SigningKey == nil || c.EncryptionKey == nil) {
			t.Fatal("accepted a JWKS without both keys")
		}
	})
}
