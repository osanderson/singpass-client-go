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
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("singpass-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "keys", "directory for sig.pem and enc.pem")
	sigKID := fs.String("sig-kid", "sig-1", `"kid" of the signing key in the JWKS`)
	encKID := fs.String("enc-kid", "enc-1", `"kid" of the encryption key in the JWKS`)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: singpass-keygen [-dir keys] [-sig-kid sig-1] [-enc-kid enc-1] > jwks.json")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	sigPath, encPath := filepath.Join(*dir, "sig.pem"), filepath.Join(*dir, "enc.pem")
	sig, created, err := keyfile.LoadOrGenerate(sigPath)
	if err != nil {
		return err
	}
	report(stderr, "signing key", sigPath, created)
	enc, created, err := keyfile.LoadOrGenerate(encPath)
	if err != nil {
		return err
	}
	report(stderr, "encryption key", encPath, created)

	jwks, err := singpass.OfflineClientJWKS(context.Background(), &sig.PublicKey, *sigKID, &enc.PublicKey, *encKID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(jwks))
	return err
}

func report(w io.Writer, what, path string, created bool) {
	verb := "using existing"
	if created {
		verb = "created"
	}
	fmt.Fprintf(w, "%s %s %s\n", verb, what, path)
}
