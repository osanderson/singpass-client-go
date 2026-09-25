package singpass_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/keyfile"
)

// A Singpass Login client needs only its registered keys, client_id and
// redirect URI; everything else defaults to Singpass staging.
func ExampleNewLogin() {
	sigKey, err := keyfile.LoadECPrivateKey("keys/login/sig.pem")
	if err != nil {
		log.Fatal(err)
	}
	encKey, err := keyfile.LoadECPrivateKey("keys/login/enc.pem")
	if err != nil {
		log.Fatal(err)
	}

	client, err := singpass.NewLogin(context.Background(), singpass.LoginOptions{
		ClientID:      "your-client-id",
		RedirectURI:   "https://app.example.com/login/callback",
		Scopes:        []string{"openid", "name", "email"},
		SigningKey:    sigKey, // any crypto.Signer, e.g. an HSM/KMS key
		SigningKID:    "login-sig-1",
		EncryptionKey: encKey,
		EncryptionKID: "login-enc-1",
	}, singpass.Dependencies{})
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

// The whole flow with plain net/http: BeginLogin on the way out, Complete on
// the callback. The state handle ties the callback to the browser that
// started the login. (The web package does all of this for you.)
func ExampleClient_Complete() {
	var client *singpass.Client // from NewLogin / NewMyinfo / NewMyinfoBusiness

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		redirectURL, state, err := client.BeginLogin(r.Context())
		if err != nil {
			http.Error(w, "login unavailable", http.StatusBadGateway)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "sp_state", Value: state, Path: "/login",
			MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	http.HandleFunc("/login/callback", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sp_state")
		if err != nil || c.Value != r.URL.Query().Get("state") {
			http.Error(w, "login expired, please try again", http.StatusBadRequest)
			return
		}
		id, err := client.Complete(r.Context(), r.URL.RawQuery)
		var denied *singpass.DeniedError
		switch {
		case errors.As(err, &denied):
			fmt.Fprintf(w, "login cancelled (%s)", denied.Code)
			return
		case err != nil:
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "hello %s", id.Subject)
	})
}

// Generate the two keys a client registers during onboarding and print the
// public JWKS to submit — no client_id or network access needed yet.
func ExampleOfflineClientJWKS() {
	sig, _ := keyfile.GenerateECKey()
	enc, _ := keyfile.GenerateECKey()
	// Persist both with keyfile.MarshalECPrivateKeyPEM (file mode 0600).

	jwks, err := singpass.OfflineClientJWKS(context.Background(), sig, "login-sig-1", enc, "login-enc-1")
	if err != nil {
		log.Fatal(err)
	}

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Use string `json:"use"`
			Crv string `json:"crv"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		log.Fatal(err)
	}
	for _, k := range set.Keys {
		fmt.Println(k.Kid, k.Use, k.Crv)
	}
	// Unordered output:
	// login-sig-1 sig P-256
	// login-enc-1 enc P-256
}

// Identity's accessors read the validated id_token claims without any
// map-casting.
func ExampleIdentity() {
	id := &singpass.Identity{
		Subject: "a9865837-7bd7-46ac-bef4-42a76a946424",
		Claims: map[string]any{
			"iss": "https://stg-id.singpass.gov.sg/fapi",
			"aud": "your-client-id",
			"amr": []any{"pwd", "otp-sms"},
			"acr": "urn:singpass:authentication:loa:2",
		},
		IDTokenIssuedAt: time.Unix(1_700_000_000, 0),
		IDTokenExpiry:   time.Unix(1_700_000_600, 0),
	}

	fmt.Println(id.Issuer())
	fmt.Println(id.Audience())
	fmt.Println(id.AuthMethods())
	fmt.Println("LOA", id.AssuranceLevel())
	fmt.Println(id.IDTokenExpiry.Sub(id.IDTokenIssuedAt))
	// Output:
	// https://stg-id.singpass.gov.sg/fapi
	// [your-client-id]
	// [pwd otp-sms]
	// LOA 2
	// 10m0s
}
