package singpass

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// TestMemorySessionStoreContract runs FAPIgo's own SessionStore contract suite
// (round-trip, single-use consume, concurrent consume has one winner).
func TestMemorySessionStoreContract(t *testing.T) {
	storage.TestSessionStoreContract(t, func() storage.SessionStore { return NewMemorySessionStore(0) })
}

type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time { return c.t }

func pending(s *memorySessionStore) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// TestMemorySessionStoreSweepsAbandonedLogins checks that sessions whose
// callback never arrives are removed once expired, rather than kept forever.
func TestMemorySessionStoreSweepsAbandonedLogins(t *testing.T) {
	ctx := context.Background()
	clk := &stepClock{t: time.Unix(1_700_000_000, 0)}
	s := newMemorySessionStore(0, clk.now)

	for _, st := range []string{"a", "b", "c"} {
		if err := s.Create(ctx, storage.NewSession{State: st, ExpiresAt: clk.t.Add(5 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	clk.t = clk.t.Add(6 * time.Minute) // past expiry and the sweep interval
	if err := s.Create(ctx, storage.NewSession{State: "d", ExpiresAt: clk.t.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	if n := pending(s); n != 1 {
		t.Fatalf("pending sessions = %d, want 1 (only the fresh one)", n)
	}
	if _, err := s.Consume(ctx, storage.SessionConsumption{State: "a"}); err == nil {
		t.Error("consumed a swept session")
	}
	if _, err := s.Consume(ctx, storage.SessionConsumption{State: "d"}); err != nil {
		t.Errorf("fresh session: %v", err)
	}
}

// TestMemorySessionStoreCap checks the pending-login cap: refused at the cap,
// room made by expiry, and a Create for an existing State never refused.
func TestMemorySessionStoreCap(t *testing.T) {
	ctx := context.Background()
	clk := &stepClock{t: time.Unix(1_700_000_000, 0)}
	s := newMemorySessionStore(2, clk.now)
	exp := clk.t.Add(5 * time.Minute)

	for _, st := range []string{"a", "b"} {
		if err := s.Create(ctx, storage.NewSession{State: st, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Create(ctx, storage.NewSession{State: "c", ExpiresAt: exp}); !errors.Is(err, ErrTooManyPendingLogins) {
		t.Fatalf("Create over cap err = %v, want ErrTooManyPendingLogins", err)
	}
	if err := s.Create(ctx, storage.NewSession{State: "a", ExpiresAt: exp}); err != nil {
		t.Fatalf("re-Create of existing state at cap: %v", err)
	}

	// Consuming frees a slot.
	if _, err := s.Consume(ctx, storage.SessionConsumption{State: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, storage.NewSession{State: "c", ExpiresAt: exp}); err != nil {
		t.Fatalf("Create after consume: %v", err)
	}

	// Expiry frees slots at the cap even inside the sweep interval.
	clk.t = exp
	if err := s.Create(ctx, storage.NewSession{State: "d", ExpiresAt: clk.t.Add(5 * time.Minute)}); err != nil {
		t.Fatalf("Create after expiry at cap: %v", err)
	}
}

// TestBeginLoginReportsPendingCap drives BeginLogin through a real PAR against
// the fake issuer and checks a full store surfaces ErrTooManyPendingLogins.
func TestBeginLoginReportsPendingCap(t *testing.T) {
	deps := testKeyDeps(t)
	deps.HTTPClient = fakeIssuer(t, discoveryDoc())
	deps.Sessions = NewMemorySessionStore(1)
	c, err := New(context.Background(), baseOptions(), deps)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := c.BeginLogin(context.Background()); err != nil {
		t.Fatalf("first BeginLogin: %v", err)
	}
	if _, _, err := c.BeginLogin(context.Background()); !errors.Is(err, ErrTooManyPendingLogins) {
		t.Fatalf("second BeginLogin err = %v, want ErrTooManyPendingLogins", err)
	}
}

// TestMemorySessionStoreLoginExpired checks that every stale-callback case —
// unknown state, a replayed state, and a session past its lifetime that the
// sweep hasn't removed yet — surfaces as ErrLoginExpired, so callers can show
// "please try again" rather than a protocol error.
func TestMemorySessionStoreLoginExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	clk := &now
	s := newMemorySessionStore(0, func() time.Time { return *clk })
	for _, st := range []string{"used", "stale"} {
		if err := s.Create(ctx, storage.NewSession{State: st, ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
			t.Fatalf("Create %s: %v", st, err)
		}
	}
	if _, err := s.Consume(ctx, storage.SessionConsumption{State: "used"}); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	*clk = now.Add(6 * time.Minute) // "stale" is expired but not yet swept

	for _, st := range []string{"never-issued", "used", "stale"} {
		if _, err := s.Consume(ctx, storage.SessionConsumption{State: st}); !errors.Is(err, ErrLoginExpired) {
			t.Errorf("Consume(%q) err = %v, want ErrLoginExpired", st, err)
		}
	}
}
