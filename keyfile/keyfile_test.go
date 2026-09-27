package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
