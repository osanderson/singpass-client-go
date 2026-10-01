// Command singpass-fake-server runs fake Singpass and Corppass FAPI 2.0
// authorization servers — the singpasstest package — as a standalone
// process, so an app in any language can log in against them locally,
// without onboarding or real accounts:
//
//	go install github.com/osanderson/singpass-client-go/cmd/singpass-fake-server@latest
//	singpass-fake-server -config clients.json
//
// It is a community test tool, not Singpass or Corppass, and is not
// affiliated with or endorsed by GovTech, Singpass or Corppass.
//
// It serves the Singpass issuer at http://127.0.0.1:5156/fapi and the Corppass
// issuer at http://127.0.0.1:5157, each with a sign-in page listing test
// users (with Myinfo data) and a form to log in as any NRIC, FIN or UEN.
//
// Clients are registered from the JSON file, as they would be in the
// developer portal:
//
//	{
//	  "clients": [
//	    {
//	      "id": "my-myinfo-app",
//	      "product": "myinfo",
//	      "redirect_uris": ["http://localhost:3000/callback"],
//	      "scopes": ["uinfin", "name", "regadd"],
//	      "jwks_url": "http://localhost:3000/jwks.json"
//	    }
//	  ]
//	}
//
// "product" is login or myinfo (on the Singpass server) or myinfo-business
// (on the Corppass server). Each client's public keys — a signing and an
// encryption key — come from "jwks" (inline), "jwks_file" or "jwks_url"; a
// URL is fetched until the app serving it is up, so the two can start in any
// order.
//
// A headless test chooses who each login signs in as with MockPass's
// X-Custom-* headers on the authorization request — X-Custom-NRIC, plus
// X-Custom-UEN on Corppass, and optionally X-Custom-UUID and X-Custom-Name —
// or makes it fail with X-Custom-Error: access_denied. Such a request is
// approved straight away, with or without -auto; see singpasstest.HeaderNRIC.
//
// Extra test users — for example with Myinfo data copied from a real staging
// /userinfo response — come from a JSON file with -personas; see
// singpasstest.LoadPersonas for the format. -only-personas drops the built-in
// users.
//
// The servers use plain HTTP on loopback, which a client must be configured
// to accept; for this library, singpass.Dependencies.AllowLoopbackHTTP.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/osanderson/singpass-client-go/singpasstest"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "singpass-fake-server:", err)
		}
		os.Exit(2)
	}
}

// config is the JSON configuration file.
type config struct {
	Clients []clientConfig `json:"clients"`
}

type clientConfig struct {
	ID           string          `json:"id"`
	Product      string          `json:"product"`
	RedirectURIs []string        `json:"redirect_uris"`
	Scopes       []string        `json:"scopes"`
	JWKS         json.RawMessage `json:"jwks"`
	JWKSFile     string          `json:"jwks_file"`
	JWKSURL      string          `json:"jwks_url"`
}

// jwksPollInterval is how often a client's jwks_url is retried until it
// answers.
var jwksPollInterval = 2 * time.Second

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("singpass-fake-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON file registering the clients (required)")
	spAddr := fs.String("singpass-addr", "127.0.0.1:5156", `listen address of the Singpass server; "" to disable it`)
	cpAddr := fs.String("corppass-addr", "127.0.0.1:5157", `listen address of the Corppass server; "" to disable it`)
	spURL := fs.String("singpass-url", "", "URL clients reach the Singpass server at, if not http://<singpass-addr> (e.g. in a container)")
	cpURL := fs.String("corppass-url", "", "URL clients reach the Corppass server at, if not http://<corppass-addr>")
	auto := fs.Bool("auto", false, "approve every login straight away as the first test user, without the sign-in page (the X-Custom-* headers choose another user without it)")
	personasPath := fs.String("personas", "", "JSON file of extra test users (see singpasstest.LoadPersonas), added to the built-in ones")
	onlyPersonas := fs.Bool("only-personas", false, "use only the -personas test users, not the built-in ones")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: singpass-fake-server -config clients.json [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		fs.Usage()
		return errors.New("-config is required")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *onlyPersonas && *personasPath == "" {
		return errors.New("-only-personas needs -personas")
	}
	users := testUsers{path: *personasPath, only: *onlyPersonas}

	servers := map[string]*singpasstest.Server{}
	defer func() {
		for _, srv := range servers {
			_ = srv.Close()
		}
	}()
	for _, sc := range []struct {
		name          string
		issuer        singpasstest.Issuer
		addr, baseURL string
	}{
		{"Singpass", singpasstest.Singpass, *spAddr, *spURL},
		{"Corppass", singpasstest.Corppass, *cpAddr, *cpURL},
	} {
		if sc.addr == "" {
			continue
		}
		srv, err := startServer(sc.name, sc.issuer, sc.addr, sc.baseURL, !*auto, users, stdout)
		if err != nil {
			return err
		}
		servers[sc.name] = srv
	}

	for _, c := range cfg.Clients {
		name, app := c.server()
		srv := servers[name]
		if srv == nil {
			return fmt.Errorf("client %q is for the %s server, which is disabled", c.ID, name)
		}
		go register(ctx, srv, c, app, stderr)
	}

	<-ctx.Done()
	fmt.Fprintln(stderr, "shutting down")
	return nil
}

// testUsers is where a server's test users come from: the built-in ones,
// unless only, plus those in the JSON file at path, if any.
type testUsers struct {
	path string
	only bool
}

func (u testUsers) load(issuer singpasstest.Issuer) ([]singpasstest.Persona, error) {
	var ps []singpasstest.Persona
	if !u.only {
		ps = singpasstest.DefaultPersonas(issuer)
	}
	if u.path == "" {
		return ps, nil
	}
	extra, err := singpasstest.LoadPersonas(u.path, issuer)
	return append(ps, extra...), err
}

// startServer starts the named fake server on addr and lists its issuer and
// test users on stdout.
func startServer(name string, issuer singpasstest.Issuer, addr, baseURL string, interactive bool, users testUsers, stdout io.Writer) (*singpasstest.Server, error) {
	ps, err := users.load(issuer)
	if err != nil {
		return nil, err
	}
	if len(ps) == 0 {
		return nil, fmt.Errorf("the %s server has no test users: add some to %s", name, users.path)
	}
	srv, err := singpasstest.NewServer(singpasstest.Config{Issuer: issuer, Addr: addr, BaseURL: baseURL, Interactive: interactive, Personas: ps})
	if err != nil {
		return nil, fmt.Errorf("start %s server: %w", name, err)
	}
	fmt.Fprintf(stdout, "%s issuer: %s\n", name, srv.Issuer())
	for _, p := range srv.Personas() {
		fmt.Fprintf(stdout, "  test user: %s (sub %s)\n", p.Name, p.Subject)
	}
	return srv, nil
}

// server returns which fake server c is registered with, and as which app.
func (c clientConfig) server() (string, singpasstest.App) {
	switch c.Product {
	case "myinfo":
		return "Singpass", singpasstest.Myinfo
	case "myinfo-business":
		return "Corppass", singpasstest.Myinfo
	default:
		return "Singpass", singpasstest.Login
	}
}

// loadConfig reads and checks the configuration file.
func loadConfig(path string) (config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return config{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Clients) == 0 {
		return config{}, fmt.Errorf("%s registers no clients", path)
	}
	for _, c := range cfg.Clients {
		sources := 0
		for _, set := range []bool{len(c.JWKS) > 0, c.JWKSFile != "", c.JWKSURL != ""} {
			if set {
				sources++
			}
		}
		switch {
		case c.ID == "":
			return config{}, fmt.Errorf("%s: a client has no id", path)
		case !slices.Contains([]string{"login", "myinfo", "myinfo-business"}, c.Product):
			return config{}, fmt.Errorf("%s: client %q: product must be login, myinfo or myinfo-business, not %q", path, c.ID, c.Product)
		case len(c.RedirectURIs) == 0:
			return config{}, fmt.Errorf("%s: client %q has no redirect_uris", path, c.ID)
		case sources != 1:
			return config{}, fmt.Errorf("%s: client %q needs exactly one of jwks, jwks_file and jwks_url", path, c.ID)
		}
	}
	return cfg, nil
}

// register registers c with srv once its keys are available, retrying a
// jwks_url until it answers or ctx ends.
func register(ctx context.Context, srv *singpasstest.Server, c clientConfig, app singpasstest.App, stderr io.Writer) {
	for waited := false; ; waited = true {
		raw, err := clientJWKS(ctx, c)
		if err == nil {
			var client singpasstest.Client
			client, err = parseJWKS(raw)
			if err == nil {
				client.ID, client.App, client.RedirectURIs, client.Scopes = c.ID, app, c.RedirectURIs, c.Scopes
				err = srv.RegisterClient(client)
			}
			if err != nil {
				fmt.Fprintf(stderr, "client %q: %v\n", c.ID, err)
				return
			}
			fmt.Fprintf(stderr, "registered client %q (%s)\n", c.ID, c.Product)
			return
		}
		if c.JWKSURL == "" {
			fmt.Fprintf(stderr, "client %q: %v\n", c.ID, err)
			return
		}
		if !waited {
			fmt.Fprintf(stderr, "client %q: waiting for its JWKS at %s (%v)\n", c.ID, c.JWKSURL, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jwksPollInterval):
		}
	}
}

// clientJWKS returns the client's JWKS from wherever it is configured.
func clientJWKS(ctx context.Context, c clientConfig) ([]byte, error) {
	switch {
	case len(c.JWKS) > 0:
		return c.JWKS, nil
	case c.JWKSFile != "":
		return os.ReadFile(c.JWKSFile)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// parseJWKS picks the client's signing ("use": "sig") and encryption
// ("use": "enc") EC P-256 keys out of a JWKS.
func parseJWKS(raw []byte) (singpasstest.Client, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return singpasstest.Client{}, fmt.Errorf("not a JWKS: %w", err)
	}
	var c singpasstest.Client
	for _, k := range set.Keys {
		if k.D != "" {
			return singpasstest.Client{}, fmt.Errorf("key %q includes private key material: publish public keys only", k.Kid)
		}
		if !k.clientKey() {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			return singpasstest.Client{}, err
		}
		addKey(&c, k.Use, pub, k.Kid)
	}
	if c.SigningKey == nil || c.EncryptionKey == nil {
		return singpasstest.Client{}, errors.New(`the JWKS needs an EC P-256 key with "use": "sig" and one with "use": "enc"`)
	}
	return c, nil
}

// jwk is the part of a JWK parseJWKS reads.
type jwk struct {
	Kty, Crv, X, Y, Kid, Use string
	D                        string `json:"d"`
}

// clientKey reports whether k is an EC P-256 signing or encryption key: the
// kinds a client registers.
func (k jwk) clientKey() bool {
	return k.Kty == "EC" && k.Crv == "P-256" && (k.Use == "sig" || k.Use == "enc")
}

// addKey sets c's signing or encryption key, by use, unless it has one: the
// first key of each use is the client's current key.
func addKey(c *singpasstest.Client, use string, pub *ecdsa.PublicKey, kid string) {
	switch {
	case use == "sig" && c.SigningKey == nil:
		c.SigningKey, c.SigningKID = pub, kid
	case use == "enc" && c.EncryptionKey == nil:
		c.EncryptionKey, c.EncryptionKID = pub, kid
	}
}

// publicKey decodes k's EC P-256 public key.
func (k jwk) publicKey() (*ecdsa.PublicKey, error) {
	x, errX := base64.RawURLEncoding.DecodeString(k.X)
	y, errY := base64.RawURLEncoding.DecodeString(k.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("key %q has a malformed x or y", k.Kid)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", k.Kid, err)
	}
	return pub, nil
}
