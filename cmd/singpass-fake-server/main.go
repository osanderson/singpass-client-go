// Command singpass-fake-server runs fake Singpass and Corppass FAPI 2.0
// authorization servers — the singpasstest package — as a standalone
// process, so an app in any language can log in against them locally,
// without onboarding or real accounts:
//
//	go install github.com/osanderson/singpass-client-go/cmd/singpass-fake-server@latest
//	singpass-fake-server -config clients.json
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
	auto := fs.Bool("auto", false, "approve every login straight away as the first test user, without the sign-in page")
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

	servers := map[string]*singpasstest.Server{}
	start := func(name string, issuer singpasstest.Issuer, addr, baseURL string) error {
		if addr == "" {
			return nil
		}
		srv, err := singpasstest.NewServer(singpasstest.Config{Issuer: issuer, Addr: addr, BaseURL: baseURL, Interactive: !*auto})
		if err != nil {
			return fmt.Errorf("start %s server: %w", name, err)
		}
		servers[name] = srv
		fmt.Fprintf(stdout, "%s issuer: %s\n", name, srv.Issuer())
		for _, p := range srv.Personas() {
			fmt.Fprintf(stdout, "  test user: %s (sub %s)\n", p.Name, p.Subject)
		}
		return nil
	}
	defer func() {
		for _, srv := range servers {
			_ = srv.Close()
		}
	}()
	if err := start("Singpass", singpasstest.Singpass, *spAddr, *spURL); err != nil {
		return err
	}
	if err := start("Corppass", singpasstest.Corppass, *cpAddr, *cpURL); err != nil {
		return err
	}

	for _, c := range cfg.Clients {
		name, app := "Singpass", singpasstest.Login
		switch c.Product {
		case "myinfo":
			app = singpasstest.Myinfo
		case "myinfo-business":
			name, app = "Corppass", singpasstest.Myinfo
		}
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
		Keys []struct {
			Kty, Crv, X, Y, Kid, Use string
			D                        string `json:"d"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return singpasstest.Client{}, fmt.Errorf("not a JWKS: %w", err)
	}
	var c singpasstest.Client
	for _, k := range set.Keys {
		if k.D != "" {
			return singpasstest.Client{}, fmt.Errorf("key %q includes private key material: publish public keys only", k.Kid)
		}
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Use != "sig" && k.Use != "enc") {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return singpasstest.Client{}, fmt.Errorf("key %q has a malformed x or y", k.Kid)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return singpasstest.Client{}, fmt.Errorf("key %q: %w", k.Kid, err)
		}
		if k.Use == "sig" && c.SigningKey == nil {
			c.SigningKey, c.SigningKID = pub, k.Kid
		} else if k.Use == "enc" && c.EncryptionKey == nil {
			c.EncryptionKey, c.EncryptionKID = pub, k.Kid
		}
	}
	if c.SigningKey == nil || c.EncryptionKey == nil {
		return singpasstest.Client{}, errors.New(`the JWKS needs an EC P-256 key with "use": "sig" and one with "use": "enc"`)
	}
	return c, nil
}
