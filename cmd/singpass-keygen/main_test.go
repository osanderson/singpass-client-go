package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCreatesThenReuses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys", "login")
	args := []string{"-dir", dir, "-sig-kid", "login-sig-1", "-enc-kid", "login-enc-1"}

	var out1, log1 bytes.Buffer
	if err := run(args, &out1, &log1); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if !strings.Contains(log1.String(), "created signing key") || !strings.Contains(log1.String(), "created encryption key") {
		t.Errorf("first run log = %q", log1.String())
	}
	var set struct {
		Keys []struct{ Kid, Use string } `json:"keys"`
	}
	if err := json.Unmarshal(out1.Bytes(), &set); err != nil {
		t.Fatalf("stdout is not a JWKS: %v\n%s", err, out1.String())
	}
	if len(set.Keys) != 2 || set.Keys[0].Kid != "login-sig-1" || set.Keys[1].Kid != "login-enc-1" {
		t.Errorf("JWKS keys = %+v", set.Keys)
	}
	for _, f := range []string{"sig.pem", "enc.pem"} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", f, perm)
		}
	}

	// A second run reuses the keys and prints the identical JWKS.
	var out2, log2 bytes.Buffer
	if err := run(args, &out2, &log2); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !strings.Contains(log2.String(), "using existing signing key") || out2.String() != out1.String() {
		t.Errorf("second run should reuse the keys: log %q", log2.String())
	}
}

func TestRunRejectsStrayArgs(t *testing.T) {
	var out, log bytes.Buffer
	if err := run([]string{"extra"}, &out, &log); err == nil {
		t.Error("stray argument accepted")
	}
}
