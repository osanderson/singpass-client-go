package keyfile_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/osanderson/singpass-client-go/keyfile"
)

// Generate a key, save it as PKCS#8 PEM with owner-only permissions, and
// load it back.
func Example() {
	key, err := keyfile.GenerateECKey()
	if err != nil {
		log.Fatal(err)
	}
	pemBytes, err := keyfile.MarshalECPrivateKeyPEM(key)
	if err != nil {
		log.Fatal(err)
	}

	dir, _ := os.MkdirTemp("", "keys")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sig.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		log.Fatal(err)
	}

	loaded, err := keyfile.LoadECPrivateKey(path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(loaded.Curve.Params().Name, loaded.Equal(key))
	// Output: P-256 true
}

// LoadOrGenerate is the one call a key-setup step needs: it reuses the key at
// path, or creates and saves one (owner-only) the first time.
func ExampleLoadOrGenerate() {
	dir, _ := os.MkdirTemp("", "keys")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "login", "sig.pem")

	first, created, err := keyfile.LoadOrGenerate(path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created:", created)

	again, created, err := keyfile.LoadOrGenerate(path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created:", created, "same key:", again.Equal(first))
	// Output:
	// created: true
	// created: false same key: true
}
