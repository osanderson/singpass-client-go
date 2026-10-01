// Command singpass-fake-server runs fake Singpass and Corppass FAPI 2.0
// authorization servers — the singpasstest package — as a standalone
// process, so an app in any language can log in against them locally,
// without onboarding or real accounts:
//
//	go run github.com/osanderson/singpass-client-go/cmd/singpass-fake-server@latest
//
// or as a container image (see docs/docker.md):
//
//	docker run --rm -p 5156:5156 -p 5157:5157 ghcr.io/osanderson/singpass-fake-server
//
// It is a community test tool, not Singpass or Corppass, and is not
// affiliated with or endorsed by GovTech, Singpass or Corppass.
//
// It serves the Singpass issuer at http://127.0.0.1:5156/fapi and the Corppass
// issuer at http://127.0.0.1:5157, each with a sign-in page listing test
// users (with Myinfo data) and a form to log in as any NRIC, FIN or UEN.
//
// With no configuration it registers built-in test clients, so an app can
// log in straight away: login-test and myinfo-test on Singpass, and
// myinfo-business-test on Corppass, each allowed every scope and any
// http://localhost redirect URI. They share one signing and one encryption
// key, which are published — the server serves them, private parts
// included, at /_fake/test-client/jwks.json, and as PKCS#8 PEM at sig.pem
// and enc.pem beside it — so they protect nothing; use them only here.
//
// To use your app's own keys, register one client with flags:
//
//	singpass-fake-server -client-id my-app -client-product myinfo \
//	    -client-redirect-uris http://localhost:3000/callback -client-scopes uinfin,name \
//	    -client-jwks-url http://localhost:3000/jwks.json
//
// or any number from a JSON file with -config, as they would be in the
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
// Clients registered with -config or -client-id replace the test clients;
// -test-clients keeps them too.
//
// Every flag can also be set with an environment variable, FAKE_ and the
// flag's name in capitals with underscores for hyphens: -singpass-url is
// FAKE_SINGPASS_URL. A flag on the command line wins.
//
// -healthcheck checks that the servers at -singpass-addr and -corppass-addr
// answer, and exits non-zero if not, for a container health check.
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
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
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

// envPrefix prefixes the environment variable that sets each flag:
// -singpass-url is FAKE_SINGPASS_URL, and so on.
const envPrefix = "FAKE_"

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("singpass-fake-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON file registering the clients; without it or -client-id, the built-in test clients are registered")
	spAddr := fs.String("singpass-addr", "127.0.0.1:5156", `listen address of the Singpass server; "" to disable it`)
	cpAddr := fs.String("corppass-addr", "127.0.0.1:5157", `listen address of the Corppass server; "" to disable it`)
	spURL := fs.String("singpass-url", "", "URL clients reach the Singpass server at, if not http://<singpass-addr> (e.g. in a container)")
	cpURL := fs.String("corppass-url", "", "URL clients reach the Corppass server at, if not http://<corppass-addr>")
	auto := fs.Bool("auto", false, "approve every login straight away as the first test user, without the sign-in page (the X-Custom-* headers choose another user without it)")
	personasPath := fs.String("personas", "", "JSON file of extra test users (see singpasstest.LoadPersonas), added to the built-in ones")
	onlyPersonas := fs.Bool("only-personas", false, "use only the -personas test users, not the built-in ones")
	testClients := fs.Bool("test-clients", false, "register the built-in test clients even with -config or -client-id")
	var one clientConfig
	fs.StringVar(&one.ID, "client-id", "", "register one client with this ID, instead of a -config file")
	fs.StringVar(&one.Product, "client-product", "", "the -client-id client's product: login, myinfo or myinfo-business")
	redirects := fs.String("client-redirect-uris", "", "the -client-id client's redirect URIs, comma-separated")
	scopes := fs.String("client-scopes", "", "the -client-id client's scopes, comma- or space-separated")
	fs.StringVar(&one.JWKSURL, "client-jwks-url", "", "URL of the -client-id client's public JWKS")
	healthcheck := fs.Bool("healthcheck", false, "check that the servers at -singpass-addr and -corppass-addr are up, and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: singpass-fake-server [flags]")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nEach flag can also be set with an environment variable: -singpass-url as %sSINGPASS_URL, and so on.\n", envPrefix)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := flagsFromEnv(fs); err != nil {
		return err
	}
	if *healthcheck {
		return checkHealth(ctx, *spAddr, *cpAddr)
	}
	var cfg config
	if *cfgPath != "" {
		var err error
		if cfg, err = loadConfig(*cfgPath); err != nil {
			return err
		}
	}
	if one.ID != "" {
		one.RedirectURIs, one.Scopes = splitList(*redirects), splitList(*scopes)
		if err := one.check(); err != nil {
			return fmt.Errorf("-client-id: %w", err)
		}
		cfg.Clients = append(cfg.Clients, one)
	}
	if *onlyPersonas && *personasPath == "" {
		return errors.New("-only-personas needs -personas")
	}
	users := testUsers{path: *personasPath, only: *onlyPersonas}
	withTestClients := *testClients || len(cfg.Clients) == 0

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
		srv, err := startServer(sc.name, sc.issuer, sc.addr, sc.baseURL, !*auto, withTestClients, users, stdout)
		if err != nil {
			return err
		}
		servers[sc.name] = srv
	}
	fmt.Fprintln(stdout, "Choose the user for a login with the X-Custom-NRIC header (and X-Custom-UEN on Corppass) on the authorization request.")

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

// flagsFromEnv sets each flag not given on the command line from its
// environment variable, if set.
func flagsFromEnv(fs *flag.FlagSet) error {
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var err error
	fs.VisitAll(func(f *flag.Flag) {
		name := envPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		v, ok := os.LookupEnv(name)
		if !ok || given[f.Name] || err != nil {
			return
		}
		if e := fs.Set(f.Name, v); e != nil {
			err = fmt.Errorf("%s: %w", name, e)
		}
	})
	return err
}

// splitList splits a comma- or space-separated list.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

// checkHealth fetches the discovery document of each server listening at a
// non-empty address, for a container health check.
func checkHealth(ctx context.Context, spAddr, cpAddr string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, s := range []struct{ addr, path string }{{spAddr, "/fapi"}, {cpAddr, ""}} {
		if s.addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(s.addr)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
			host = "127.0.0.1"
		}
		u := "http://" + net.JoinHostPort(host, port) + s.path + "/.well-known/openid-configuration"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
		}
	}
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

// startServer starts the named fake server on addr, registers the test
// clients if testClients, and lists how to use it on stdout.
func startServer(name string, issuer singpasstest.Issuer, addr, baseURL string, interactive, testClients bool, users testUsers, stdout io.Writer) (*singpasstest.Server, error) {
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
	if testClients {
		if err := srv.RegisterTestClients(); err != nil {
			_ = srv.Close()
			return nil, err
		}
	}
	fmt.Fprintf(stdout, "%s issuer: %s\n", name, srv.Issuer())
	fmt.Fprintf(stdout, "  discovery:    %s/.well-known/openid-configuration\n", srv.Issuer())
	if ids := srv.TestClients(); len(ids) > 0 {
		fmt.Fprintf(stdout, "  test clients: %s, for any http://localhost redirect URI\n", strings.Join(ids, ", "))
		fmt.Fprintf(stdout, "                keys (published, for testing only): %s\n", srv.TestClientKeysURL())
	}
	for _, p := range srv.Personas() {
		fmt.Fprintf(stdout, "  test user: %-22s %s (sub %s)\n", personaID(p), p.Name, p.Subject)
	}
	return srv, nil
}

// personaID is how the X-Custom-* headers name p: its NRIC or FIN, or on
// Corppass its UEN and the acting person's NRIC or FIN.
func personaID(p singpasstest.Persona) string {
	nric, _ := p.SubAttributes["identity_number"].(string)
	if p.Act != nil {
		nric, _ = p.Act.SubAttributes["identity_number"].(string)
		return p.Subject + " / " + nric
	}
	return nric
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
		if err := c.check(); err != nil {
			return config{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	return cfg, nil
}

// check reports what is missing or wrong in c.
func (c clientConfig) check() error {
	sources := 0
	for _, set := range []bool{len(c.JWKS) > 0, c.JWKSFile != "", c.JWKSURL != ""} {
		if set {
			sources++
		}
	}
	switch {
	case c.ID == "":
		return errors.New("a client has no id")
	case !slices.Contains([]string{"login", "myinfo", "myinfo-business"}, c.Product):
		return fmt.Errorf("client %q: product must be login, myinfo or myinfo-business, not %q", c.ID, c.Product)
	case len(c.RedirectURIs) == 0:
		return fmt.Errorf("client %q has no redirect_uris", c.ID)
	case sources != 1:
		return fmt.Errorf("client %q needs exactly one of jwks, jwks_file and jwks_url", c.ID)
	}
	return nil
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
