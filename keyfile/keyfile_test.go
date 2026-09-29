package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteECPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "dir", "sig.pem")
	k, _ := GenerateECKey()
	if err := WriteECPrivateKey(path, k); err != nil {
		t.Fatalf("WriteECPrivateKey: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 600", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 700", info.Mode().Perm())
	}
	loaded, err := LoadECPrivateKey(path)
	if err != nil || !loaded.Equal(k) {
		t.Fatalf("round trip: %v", err)
	}

	// Never overwrites: the registered key must survive.
	other, _ := GenerateECKey()
	if err := WriteECPrivateKey(path, other); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("overwrite err = %v, want fs.ErrExist", err)
	}
	if still, _ := LoadECPrivateKey(path); !still.Equal(k) {
		t.Error("existing key was replaced")
	}
}

func TestLoadOrGenerateRefusesCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sig.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerate(path); err == nil {
		t.Fatal("corrupt key file was accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != "not a key" {
		t.Error("corrupt file was replaced instead of reported")
	}
}

// writePEM writes a PEM block of the given type and bytes to a temp file.
func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadECPrivateKeyRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKCS8PrivateKey(p384)
	noPEM := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(noPEM, []byte("not a PEM file"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"missing file": {filepath.Join(t.TempDir(), "absent.pem"), "read key"},
		"no PEM block": {noPEM, "no PEM block"},
		"not PKCS#8":   {writePEM(t, "PRIVATE KEY", []byte("junk")), "parse PKCS#8"},
		"RSA key":      {writePEM(t, "PRIVATE KEY", rsaDER), "not an EC private key"},
		"P-384 key":    {writePEM(t, "PRIVATE KEY", p384DER), "must be EC P-256"},
	} {
		if _, err := LoadECPrivateKey(tc.path); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestMarshalECPrivateKeyPEMRejectsInvalidKey(t *testing.T) {
	if _, err := MarshalECPrivateKeyPEM(&ecdsa.PrivateKey{}); err == nil {
		t.Error("marshalled a key with no curve")
	}
	if err := WriteECPrivateKey(filepath.Join(t.TempDir(), "k.pem"), &ecdsa.PrivateKey{}); err == nil {
		t.Error("wrote a key with no curve")
	}
}

func TestWriteECPrivateKeyErrors(t *testing.T) {
	key, _ := GenerateECKey()
	// A parent "directory" that is a file can't be created.
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteECPrivateKey(filepath.Join(parent, "key.pem"), key); err == nil || !strings.Contains(err.Error(), "create key directory") {
		t.Errorf("parent is a file: %v", err)
	}
	// An existing key is never replaced.
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := WriteECPrivateKey(p, key); err != nil {
		t.Fatal(err)
	}
	if err := WriteECPrivateKey(p, key); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second write: err = %v, want fs.ErrExist", err)
	}
	// Missing parent directories are created owner-only.
	nested := filepath.Join(t.TempDir(), "a", "b", "key.pem")
	if err := WriteECPrivateKey(nested, key); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Dir(nested)); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("parent directory mode = %v, %v; want 0700", info.Mode().Perm(), err)
	}
}

func TestLoadOrGenerate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keys", "sig.pem")
	first, created, err := LoadOrGenerate(p)
	if err != nil || !created {
		t.Fatalf("first call: created %v, err %v", created, err)
	}
	again, created, err := LoadOrGenerate(p)
	if err != nil || created || !again.Equal(first) {
		t.Fatalf("second call: created %v, err %v, same key %v", created, err, again.Equal(first))
	}
	// A path that can't be examined (under a file) is an error, not a new key.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := LoadOrGenerate(filepath.Join(file, "sig.pem")); err == nil || created {
		t.Errorf("path under a file: created %v, err %v", created, err)
	}
	// A key that can't be written is reported, not returned.
	if _, created, err := LoadOrGenerate(filepath.Join(file, "sub", "sig.pem")); err == nil || created {
		t.Errorf("unwritable path: created %v, err %v", created, err)
	}
}

// failingFile is a real file whose Write or Close fails.
type failingFile struct {
	*os.File
	failWrite, failClose bool
}

func (f failingFile) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("disk full")
	}
	return f.File.Write(p)
}

func (f failingFile) Close() error {
	err := f.File.Close()
	if f.failClose {
		return errors.New("close failed")
	}
	return err
}

// A key file that fails part-way is removed, so a half-written key is never
// left to be loaded later.
func TestWriteECPrivateKeyRemovesPartialFile(t *testing.T) {
	key, _ := GenerateECKey()
	orig := createExclusive
	t.Cleanup(func() { createExclusive = orig })
	for name, fail := range map[string][2]bool{"write fails": {true, false}, "close fails": {false, true}} {
		createExclusive = func(path string) (io.WriteCloser, error) {
			f, err := orig(path)
			if err != nil {
				return nil, err
			}
			return failingFile{f.(*os.File), fail[0], fail[1]}, nil
		}
		p := filepath.Join(t.TempDir(), "key.pem")
		if err := WriteECPrivateKey(p, key); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: partial key file left behind (%v)", name, err)
		}
	}
}
