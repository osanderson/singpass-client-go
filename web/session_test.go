package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
)

// fakeClock is a settable time source for the memory store.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestStore(clk *fakeClock) *memoryLoginSessionStore {
	st := NewMemoryLoginSessionStore().(*memoryLoginSessionStore)
	st.now = clk.now
	return st
}

// TestMemoryStoreExpiry checks that an entry is served until its TTL elapses and
// refused from that instant on, independent of any cookie.
func TestMemoryStoreExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	st := newTestStore(clk)
	want := &singpass.Identity{Subject: "S1234567D"}

	sid := st.Create(want, 30*time.Minute)

	clk.t = clk.t.Add(30*time.Minute - time.Second)
	if got, ok := st.Get(sid); !ok || got != want {
		t.Fatalf("Get before expiry = %v, %v; want identity, true", got, ok)
	}

	clk.t = clk.t.Add(time.Second)
	if got, ok := st.Get(sid); ok || got != nil {
		t.Fatalf("Get at expiry = %v, %v; want nil, false", got, ok)
	}
}

// TestMemoryStoreSweep checks that expired entries are removed from the map (not
// merely hidden by Get) once a later Create runs the sweep.
func TestMemoryStoreSweep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	st := newTestStore(clk)

	old := st.Create(&singpass.Identity{}, time.Minute)
	clk.t = clk.t.Add(2 * time.Minute) // past both the TTL and sweepInterval
	fresh := st.Create(&singpass.Identity{}, time.Hour)

	if _, present := st.m[old]; present {
		t.Errorf("expired session %q still in map after sweep", old)
	}
	if _, present := st.m[fresh]; !present {
		t.Errorf("fresh session %q missing from map", fresh)
	}
}

type stubAuth struct{ id *singpass.Identity }

func (s stubAuth) BeginLogin(context.Context) (string, string, error) { return "", "", nil }
func (s stubAuth) Complete(context.Context, string) (*singpass.Identity, error) {
	return s.id, nil
}

// recordingStore captures the TTL the handlers hand to Create.
type recordingStore struct {
	LoginSessionStore
	ttl time.Duration
}

func (r *recordingStore) Create(id *singpass.Identity, ttl time.Duration) string {
	r.ttl = ttl
	return r.LoginSessionStore.Create(id, ttl)
}

// TestCallbackPassesSessionTTL checks that the server-side session is created
// with the same lifetime as the session cookie.
func TestCallbackPassesSessionTTL(t *testing.T) {
	store := &recordingStore{LoginSessionStore: NewMemoryLoginSessionStore()}
	app := &App{Name: "login", Auth: stubAuth{id: &singpass.Identity{Subject: "S1234567D"}}}
	h := New(Config{
		Apps:          []*App{app},
		LoginSessions: store,
		Cookies:       CookieConfig{SessionTTL: 7 * time.Minute},
	})

	req := httptest.NewRequest(http.MethodGet, "/login/callback?state=abc&code=x", nil)
	req.AddCookie(&http.Cookie{Name: "sp_state_login", Value: "abc"})
	rec := httptest.NewRecorder()
	h.Callback(app)(rec, req)

	if store.ttl != 7*time.Minute {
		t.Fatalf("Create ttl = %v, want 7m", store.ttl)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sid" && c.MaxAge != int((7*time.Minute).Seconds()) {
			t.Errorf("sid cookie MaxAge = %d, want %d", c.MaxAge, int((7 * time.Minute).Seconds()))
		}
	}
}
