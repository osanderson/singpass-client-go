// Command singpass-keygen creates the two EC P-256 keys a Singpass or Corppass
// client registers — a signing key (private_key_jwt client assertions and DPoP)
// and an encryption key (id_token and /userinfo decryption) — and prints the
// public JWKS to register during onboarding.
//
//	go install github.com/osanderson/singpass-client-go/cmd/singpass-keygen@latest
//	singpass-keygen -dir keys/login -sig-kid login-sig-1 -enc-kid login-enc-1 > login.jwks.json
//
// Existing key files are reused, so re-running prints the same JWKS; keys are
// never overwritten. The private keys are written as PKCS#8 PEM, readable only
// by their owner. The JWKS goes to standard output and progress to standard
// error.
//
// To publish several keys — each step of a key rotation, for a JWKS pasted
// into the developer portal or served as a static file — list every key with
// -sig and -enc (PATH=KID, repeatable) instead of -dir. Missing files are
// created, so adding a new key is one command. For example, the first step of
// a signing-key rotation publishes the current and the next signing key:
//
//	singpass-keygen -sig keys/login/sig.pem=login-sig-1 -sig keys/login/sig-2.pem=login-sig-2 \
//	    -enc keys/login/enc.pem=login-enc-1
//
// See docs/production.md, "Rotating keys", for each step.
//
// Once the JWKS is published at the URL registered in the developer portal,
// -check confirms that URL serves these keys — the usual cause of an
// "invalid_client" error at login is a JWKS URL serving stale or other keys:
//
//	singpass-keygen -dir keys/login -sig-kid login-sig-1 -enc-kid login-enc-1 -check https://app.example.com/login/jwks.json
//
// With -check, no keys are created: every key file must already exist.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/keyfile"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "singpass-keygen:", err)
		}
		os.Exit(2)
	}
}

// keySpec is a key file and the kid it is published under.
type keySpec struct{ path, kid string }

// keyList is a repeatable PATH=KID flag.
type keyList []keySpec

func (l *keyList) String() string { return "" }

func (l *keyList) Set(v string) error {
	path, kid, ok := strings.Cut(v, "=")
	if !ok || path == "" || kid == "" {
		return fmt.Errorf("want PATH=KID, got %q", v)
	}
	*l = append(*l, keySpec{path, kid})
	return nil
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("singpass-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "keys", "directory for sig.pem and enc.pem")
	sigKID := fs.String("sig-kid", "sig-1", `"kid" of the signing key in the JWKS`)
	encKID := fs.String("enc-kid", "enc-1", `"kid" of the encryption key in the JWKS`)
	var sigs, encs keyList
	fs.Var(&sigs, "sig", "a signing key to publish, as PATH=KID; repeat for several (instead of -dir)")
	fs.Var(&encs, "enc", "an encryption key to publish, as PATH=KID; repeat for several (instead of -dir)")
	check := fs.String("check", "", "instead of printing the JWKS, check that this published JWKS URL serves the keys")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: singpass-keygen [-dir keys] [-sig-kid sig-1] [-enc-kid enc-1] [-check URL] > jwks.json")
		fmt.Fprintln(stderr, "       singpass-keygen -sig PATH=KID [-sig PATH=KID …] -enc PATH=KID [-enc PATH=KID …] [-check URL] > jwks.json")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	if len(sigs) == 0 && len(encs) == 0 {
		sigs = keyList{{filepath.Join(*dir, "sig.pem"), *sigKID}}
		encs = keyList{{filepath.Join(*dir, "enc.pem"), *encKID}}
	} else if err := checkKeyLists(fs, sigs, encs); err != nil {
		return err
	}
	if err := checkDistinct(sigs, encs); err != nil {
		return err
	}

	// With -check the keys must exist already; otherwise missing ones are
	// created.
	loadOnly := *check != ""
	signing, err := loadKeys(sigs, "signing key", loadOnly, stderr)
	if err != nil {
		return err
	}
	encryption, err := loadKeys(encs, "encryption key", loadOnly, stderr)
	if err != nil {
		return err
	}
	ctx := context.Background()
	jwks, err := singpass.OfflineJWKS(ctx, signing, encryption)
	if err != nil {
		return err
	}

	if *check != "" {
		if err := singpass.CheckPublishedJWKS(ctx, nil, *check, jwks); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stderr, "ok: %s publishes signing %s and encryption %s\n", *check, kidList(sigs), kidList(encs))
		return err
	}
	_, err = fmt.Fprintln(stdout, string(jwks))
	return err
}

// checkKeyLists checks -sig/-enc lists: both given, and not mixed with the
// -dir form's flags.
func checkKeyLists(fs *flag.FlagSet, sigs, encs keyList) error {
	var mixed []string
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dir" || f.Name == "sig-kid" || f.Name == "enc-kid" {
			mixed = append(mixed, "-"+f.Name)
		}
	})
	switch {
	case len(mixed) > 0:
		return fmt.Errorf("%s can't be combined with -sig/-enc: give each key as PATH=KID", strings.Join(mixed, ", "))
	case len(sigs) == 0 || len(encs) == 0:
		return errors.New("list at least one -sig and one -enc key: a JWKS needs both")
	}
	return nil
}

// checkDistinct refuses a key file listed twice.
func checkDistinct(sigs, encs keyList) error {
	seen := map[string]string{}
	for _, k := range append(append(keyList{}, sigs...), encs...) {
		if other, ok := seen[filepath.Clean(k.path)]; ok {
			return fmt.Errorf("%s is listed twice (as %q and %q): use separate keys", k.path, other, k.kid)
		}
		seen[filepath.Clean(k.path)] = k.kid
	}
	return nil
}

// loadKeys loads each key's public half, creating missing key files unless
// loadOnly, and reports each one it creates or uses on stderr.
func loadKeys(list keyList, what string, loadOnly bool, stderr io.Writer) ([]singpass.PublishedKey, error) {
	var out []singpass.PublishedKey
	for _, k := range list {
		key, err := loadKey(k.path, what, loadOnly, stderr)
		if err != nil {
			return nil, err
		}
		out = append(out, singpass.PublishedKey{Key: &key.PublicKey, KID: k.kid})
	}
	return out, nil
}

func loadKey(path, what string, loadOnly bool, stderr io.Writer) (*ecdsa.PrivateKey, error) {
	if loadOnly {
		return keyfile.LoadECPrivateKey(path)
	}
	key, created, err := keyfile.LoadOrGenerate(path)
	if err == nil {
		report(stderr, what, path, created)
	}
	return key, err
}

// kidList formats the keys' kids for a message: "key \"a\"" or "keys \"a\", \"b\"".
func kidList(l keyList) string {
	quoted := make([]string, len(l))
	for i, k := range l {
		quoted[i] = fmt.Sprintf("%q", k.kid)
	}
	if len(l) == 1 {
		return "key " + quoted[0]
	}
	return "keys " + strings.Join(quoted, ", ")
}

func report(w io.Writer, what, path string, created bool) {
	verb := "using existing"
	if created {
		verb = "created"
	}
	fmt.Fprintf(w, "%s %s %s\n", verb, what, path)
}
