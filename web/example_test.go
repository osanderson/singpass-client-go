package web_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/web"
)

// Serve login, callback, logout and JWKS routes for a client and render your
// own pages from the callbacks; the helper emits no HTML.
func ExampleNew() {
	var client *singpass.Client // from singpass.NewLogin / NewMyinfo / NewMyinfoBusiness

	jwks, err := client.PublicJWKS(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	h := web.New(web.Config{
		Apps:    []*web.App{{Name: "login", Title: "Singpass", Auth: client, JWKS: jwks}},
		Cookies: web.DefaultCookieConfig(true), // Secure cookies: serve over HTTPS
		OnAuthenticated: func(w http.ResponseWriter, r *http.Request, _ *web.App, _ *singpass.Identity) {
			http.Redirect(w, r, "/", http.StatusFound) // session cookie already set
		},
		OnDenied: func(w http.ResponseWriter, _ *http.Request, _ *web.App, d *singpass.DeniedError) {
			fmt.Fprintf(w, "login cancelled: %s", d.Code)
		},
	})

	// Routes: /login/login, /login/callback (register this redirect URI),
	// /login/logout (POST), /login/jwks.json.
	mux := h.Mux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if id, ok := h.CurrentIdentity(r); ok {
			fmt.Fprintf(w, "signed in as %s", id.Subject)
			return
		}
		fmt.Fprint(w, `<a href="/login/login">Log in with Singpass</a>`)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
