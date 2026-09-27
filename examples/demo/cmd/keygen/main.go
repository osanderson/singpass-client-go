// Command keygen generates the EC P-256 key pairs the demo relying parties
// register with Singpass / Corppass. For each app it writes a signing key
// (private_key_jwt client assertion + DPoP) and an encryption key (id_token /
// userinfo decryption) as PKCS#8 PEM under keys/<app>/, then prints the public
// JWKS to register during onboarding. Existing keys are left in place unless
// -force is given, so re-running is safe.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/keyfile"
)

// keyapp describes one relying party's key material to generate. Paths and kids
// mirror the config package's defaults; override with the same environment
// variables the server reads.
type keyapp struct {
	name    string
	sigPath string
	sigKID  string
	encPath string
	encKID  string
}

func apps() []keyapp {
	return []keyapp{
		{
			name:    "login",
			sigPath: env("SINGPASS_LOGIN_SIG_KEY_PATH", "keys/login/sig.pem"),
			sigKID:  env("SINGPASS_LOGIN_SIG_KID", "login-sig-1"),
			encPath: env("SINGPASS_LOGIN_ENC_KEY_PATH", "keys/login/enc.pem"),
			encKID:  env("SINGPASS_LOGIN_ENC_KID", "login-enc-1"),
		},
		{
			name:    "myinfo",
			sigPath: env("MYINFO_SIG_KEY_PATH", "keys/myinfo/sig.pem"),
			sigKID:  env("MYINFO_SIG_KID", "myinfo-sig-1"),
			encPath: env("MYINFO_ENC_KEY_PATH", "keys/myinfo/enc.pem"),
			encKID:  env("MYINFO_ENC_KID", "myinfo-enc-1"),
		},
		{
			name:    "myinfobiz",
			sigPath: env("MYINFO_BIZ_SIG_KEY_PATH", "keys/myinfobiz/sig.pem"),
			sigKID:  env("MYINFO_BIZ_SIG_KID", "myinfobiz-sig-1"),
			encPath: env("MYINFO_BIZ_ENC_KEY_PATH", "keys/myinfobiz/enc.pem"),
			encKID:  env("MYINFO_BIZ_ENC_KID", "myinfobiz-enc-1"),
		},
	}
}

func main() {
	force := flag.Bool("force", false, "overwrite existing key files")
	flag.Parse()

	ctx := context.Background()
	for _, a := range apps() {
		if err := generate(ctx, a, *force); err != nil {
			fmt.Fprintf(os.Stderr, "keygen %s: %v\n", a.name, err)
			os.Exit(1)
		}
	}
}

func generate(ctx context.Context, a keyapp, force bool) error {
	sigKey, err := loadOrCreate(a.sigPath, force)
	if err != nil {
		return err
	}
	encKey, err := loadOrCreate(a.encPath, force)
	if err != nil {
		return err
	}

	jwks, err := singpass.OfflineClientJWKS(ctx, &sigKey.PublicKey, a.sigKID, &encKey.PublicKey, a.encKID)
	if err != nil {
		return err
	}

	fmt.Printf("# %s public JWKS (sig kid=%s, enc kid=%s)\n", a.name, a.sigKID, a.encKID)
	fmt.Printf("#   sig: %s\n#   enc: %s\n", a.sigPath, a.encPath)
	fmt.Println(string(jwks))
	fmt.Println()
	return nil
}

// loadOrCreate returns the key at path, generating and saving a fresh one
// (owner-only, via keyfile) when it is absent. With force, an existing key is
// deleted first so a new one replaces it — keyfile itself never overwrites.
func loadOrCreate(path string, force bool) (*ecdsa.PrivateKey, error) {
	if force {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	k, _, err := keyfile.LoadOrGenerate(path)
	return k, err
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
