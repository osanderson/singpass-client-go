package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestRunCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	args := []string{"-dir", dir, "-sig-kid", "s1", "-enc-kid", "e1"}

	// -check never creates keys.
	if err := run(append(args, "-check", "https://app.example/jwks.json"), io.Discard, io.Discard); err == nil {
		t.Fatal("check with no keys succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "sig.pem")); !os.IsNotExist(err) {
		t.Fatal("check created a key")
	}

	var jwks bytes.Buffer
	if err := run(args, &jwks, io.Discard); err != nil {
		t.Fatal(err)
	}
	published := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks.Bytes())
	}))
	defer published.Close()
	var log bytes.Buffer
	if err := run(append(args, "-check", published.URL), io.Discard, &log); err != nil {
		t.Fatalf("check of the published JWKS: %v", err)
	}
	if !strings.Contains(log.String(), "ok: ") {
		t.Errorf("log = %q", log.String())
	}

	// Different kids than the published ones fail.
	if err := run([]string{"-dir", dir, "-sig-kid", "s2", "-enc-kid", "e1", "-check", published.URL}, io.Discard, io.Discard); err == nil ||
		!strings.Contains(err.Error(), `missing the signing key "s2"`) {
		t.Errorf("check with wrong kid: %v", err)
	}
}

func jwksKIDs(t *testing.T, out []byte) []string {
	t.Helper()
	var set struct {
		Keys []struct{ Kid, Use string } `json:"keys"`
	}
	if err := json.Unmarshal(out, &set); err != nil {
		t.Fatalf("not a JWKS: %v\n%s", err, out)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Use+":"+k.Kid)
	}
	return kids
}

// A key rotation, step by step, with -sig/-enc lists.
func TestRunKeyLists(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }

	// Onboarding: one key each.
	var out bytes.Buffer
	if err := run([]string{"-sig", p("sig.pem") + "=sig-1", "-enc", p("enc.pem") + "=enc-1"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := jwksKIDs(t, out.Bytes()); strings.Join(got, " ") != "sig:sig-1 enc:enc-1" {
		t.Errorf("onboarding JWKS = %v", got)
	}

	// Signing rotation, step 1: publish the next signing key too; its file is created.
	out.Reset()
	var log bytes.Buffer
	args := []string{"-sig", p("sig.pem") + "=sig-1", "-sig", p("sig-2.pem") + "=sig-2", "-enc", p("enc.pem") + "=enc-1"}
	if err := run(args, &out, &log); err != nil {
		t.Fatal(err)
	}
	if got := jwksKIDs(t, out.Bytes()); strings.Join(got, " ") != "sig:sig-1 sig:sig-2 enc:enc-1" {
		t.Errorf("rotation JWKS = %v", got)
	}
	if !strings.Contains(log.String(), "created signing key "+p("sig-2.pem")) || !strings.Contains(log.String(), "using existing signing key "+p("sig.pem")) {
		t.Errorf("log = %q", log.String())
	}

	// -check against a URL serving that set.
	published := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(out.Bytes()) }))
	defer published.Close()
	log.Reset()
	if err := run(append(args, "-check", published.URL), io.Discard, &log); err != nil {
		t.Fatalf("check: %v", err)
	}
	if !strings.Contains(log.String(), `signing keys "sig-1", "sig-2"`) {
		t.Errorf("check log = %q", log.String())
	}
	// A list the URL doesn't serve fails the check, and -check creates nothing.
	if err := run([]string{"-sig", p("sig-3.pem") + "=sig-3", "-enc", p("enc.pem") + "=enc-1", "-check", published.URL}, io.Discard, io.Discard); err == nil {
		t.Error("check with a missing key file succeeded")
	}
	if _, err := os.Stat(p("sig-3.pem")); !os.IsNotExist(err) {
		t.Error("-check created a key")
	}
}

func TestRunKeyListErrors(t *testing.T) {
	dir := t.TempDir()
	sig, enc := filepath.Join(dir, "sig.pem"), filepath.Join(dir, "enc.pem")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no enc":         {[]string{"-sig", sig + "=s"}, "at least one -sig and one -enc"},
		"mixed with dir": {[]string{"-dir", dir, "-sig", sig + "=s", "-enc", enc + "=e"}, "-dir can't be combined"},
		"bad format":     {[]string{"-sig", sig, "-enc", enc + "=e"}, "PATH=KID"},
		"same file":      {[]string{"-sig", sig + "=s", "-enc", sig + "=e"}, "listed twice"},
		"duplicate kid":  {[]string{"-sig", sig + "=k", "-sig", filepath.Join(dir, "s2.pem") + "=k", "-enc", enc + "=e"}, "more than once"},
	} {
		if err := run(tc.args, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
}
