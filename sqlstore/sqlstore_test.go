package sqlstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/myinfo"
	"github.com/osanderson/singpass-client-go/singpasstest"

	"github.com/idfoundry/fapigo/storage"
	_ "modernc.org/sqlite"
)

// newStore opens a fresh SQLite database file (so several connections share
// it, as they would a real database) and creates the tables.
func newStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "sessions.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfg.Dialect = SQLite
	s := New(db, cfg)
	if err := s.CreateTables(context.Background()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	return s
}

// TestSessionsContract runs FAPIgo's own SessionStore contract suite:
// round trip, single-use consume, and one winner among concurrent consumes.
func TestSessionsContract(t *testing.T) {
	storage.TestSessionStoreContract(t, func() storage.SessionStore { return newStore(t, Config{}).Sessions() })
}

func TestSessionsDeclareProductionCapabilities(t *testing.T) {
	sa, ok := newStore(t, Config{}).Sessions().(singpass.StoreAssurance)
	if !ok {
		t.Fatal("Sessions() does not implement StoreAssurance")
	}
	if c := sa.Capabilities(); !c.Durable || !c.AtomicConsume {
		t.Errorf("capabilities = %+v, want durable and atomic", c)
	}
}

func TestConsumeStaleIsLoginExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	s := newStore(t, Config{Now: func() time.Time { return now }})
	sessions := s.Sessions()
	for _, st := range []string{"used", "stale"} {
		if err := sessions.Create(ctx, storage.NewSession{State: st, Nonce: "n", ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sessions.Consume(ctx, storage.SessionConsumption{State: "used"}); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	now = now.Add(6 * time.Minute)
	for _, st := range []string{"never-issued", "used", "stale"} {
		if _, err := sessions.Consume(ctx, storage.SessionConsumption{State: st}); !errors.Is(err, singpass.ErrLoginExpired) {
			t.Errorf("Consume(%q) = %v, want ErrLoginExpired", st, err)
		}
	}
}

func TestLoginSessionsRoundTripIdentity(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	s := newStore(t, Config{Now: func() time.Time { return now }})
	ls := s.LoginSessions()

	want := &singpass.Identity{
		App: "mi", Subject: "a9865837", Scope: "openid name",
		Claims: map[string]any{"acr": "urn:singpass:authentication:loa:2", "amr": []any{"pwd"}},
		Myinfo: myinfo.Parse(map[string]any{"person_info": map[string]any{
			"name": map[string]any{"value": "TAN XIAO HUI", "source": "1"},
		}}),
		IDTokenIssuedAt: now, IDTokenExpiry: now.Add(10 * time.Minute),
	}
	sid, err := ls.Create(ctx, want, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok, err := ls.Get(ctx, sid)
	if err != nil || !ok {
		t.Fatalf("Get = %v, %v", ok, err)
	}
	if got.Subject != want.Subject || got.AssuranceLevel() != "2" || !got.IDTokenExpiry.Equal(want.IDTokenExpiry) {
		t.Errorf("identity = %+v", got)
	}
	if name := got.Myinfo.Person.Field("name").String(); name != "TAN XIAO HUI" {
		t.Errorf("Myinfo name after storage = %q", name)
	}

	now = now.Add(2 * time.Hour)
	if _, ok, err := ls.Get(ctx, sid); ok || err != nil {
		t.Errorf("expired session: ok=%v err=%v, want not found", ok, err)
	}
	if n, err := s.DeleteExpired(ctx); err != nil || n != 1 {
		t.Errorf("DeleteExpired = %d, %v; want 1", n, err)
	}
	if err := ls.Delete(ctx, "absent"); err != nil {
		t.Errorf("deleting an absent session: %v", err)
	}
}

func TestPostgresPlaceholders(t *testing.T) {
	s := New(nil, Config{Dialect: Postgres})
	if got := s.q("SELECT a FROM t WHERE x = ? AND y > ?"); got != "SELECT a FROM t WHERE x = $1 AND y > $2" {
		t.Errorf("q = %q", got)
	}
}

func TestInvalidPrefixPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic for a prefix containing SQL")
		}
	}()
	New(nil, Config{TablePrefix: "x; DROP TABLE users; --"})
}

// TestFullLoginThroughStore runs a real Myinfo login against singpasstest with
// this store holding the protocol session, then keeps the identity in a login
// session and reads it back.
func TestFullLoginThroughStore(t *testing.T) {
	ctx := context.Background()
	store := newStore(t, Config{})
	srv, err := singpasstest.NewServer(singpasstest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	sig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const redirect = "https://rp.example/mi/callback"
	if err := srv.RegisterClient(singpasstest.Client{
		ID: "mi", App: singpasstest.Myinfo, RedirectURIs: []string{redirect}, Scopes: []string{"name"},
		SigningKey: &sig.PublicKey, SigningKID: "s", EncryptionKey: &enc.PublicKey, EncryptionKID: "e",
	}); err != nil {
		t.Fatal(err)
	}
	c, err := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
		Issuer: srv.Issuer(), ClientID: "mi", RedirectURI: redirect, Scopes: []string{"openid", "name"},
		SigningKey: sig, SigningKID: "s", EncryptionKey: enc, EncryptionKID: "e",
	}, singpass.Dependencies{Sessions: store.Sessions(), AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("NewMyinfo: %v", err)
	}

	redirectURL, _, err := c.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	callback, err := srv.Authorize(ctx, redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Complete(ctx, callback)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// Replaying the callback finds the session already consumed.
	if _, err := c.Complete(ctx, callback); !errors.Is(err, singpass.ErrLoginExpired) {
		t.Errorf("replayed callback: %v, want ErrLoginExpired", err)
	}

	sid, err := store.LoginSessions().Create(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	back, ok, err := store.LoginSessions().Get(ctx, sid)
	if err != nil || !ok {
		t.Fatalf("Get: %v %v", ok, err)
	}
	if got := back.Myinfo.Person.Field("name").String(); got != "TAN XIAO HUI" {
		t.Errorf("stored identity name = %q", got)
	}
}
