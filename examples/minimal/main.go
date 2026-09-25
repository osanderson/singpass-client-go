// Command minimal is the smallest useful Singpass Login integration: one
// client, the web helper for the login/callback/logout routes, and a page that
// greets the signed-in user. See examples/demo for all three products.
//
//	export CLIENT_ID=... SIG_KEY=keys/sig.pem ENC_KEY=keys/enc.pem
//	export BASE_URL=http://localhost:8080   # register $BASE_URL/login/callback
//	go run ./examples/minimal               # PORT overrides the default 8080
package main

import (
	"context"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/keyfile"
	"github.com/osanderson/singpass-client-go/web"
)

func main() {
	ctx := context.Background()

	sigKey, err := keyfile.LoadECPrivateKey(os.Getenv("SIG_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	encKey, err := keyfile.LoadECPrivateKey(os.Getenv("ENC_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	client, err := singpass.NewLogin(ctx, singpass.LoginOptions{
		ClientID:      os.Getenv("CLIENT_ID"),
		RedirectURI:   os.Getenv("BASE_URL") + "/login/callback",
		Scopes:        []string{"openid", "name"},
		SigningKey:    sigKey,
		SigningKID:    "login-sig-1",
		EncryptionKey: encKey,
		EncryptionKID: "login-enc-1",
	}, singpass.Dependencies{})
	if err != nil {
		log.Fatal(err)
	}
	jwks, err := client.PublicJWKS(ctx)
	if err != nil {
		log.Fatal(err)
	}

	h := web.New(web.Config{
		Apps: []*web.App{{Name: "login", Title: "Singpass", Auth: client, JWKS: jwks}},
	})
	mux := h.Mux() // /login/login, /login/callback, /login/logout, /login/jwks.json
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		id, ok := h.CurrentIdentity(r)
		if !ok {
			fmt.Fprint(w, `<a href="/login/login">Log in with Singpass</a>`)
			return
		}
		fmt.Fprintf(w, `<p>Signed in as %s</p>
<form method="post" action="/login/logout"><button>Log out</button></form>`,
			html.EscapeString(id.Subject))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
