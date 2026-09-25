package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
)

// LoginSessionStore persists authenticated identities server-side, keyed by an
// opaque session id that is handed to the browser in an HttpOnly cookie. It is
// the *application* login-session store — deliberately named apart from the FAPI
// protocol session store (singpass.Dependencies.Sessions, a storage.SessionStore),
// which holds in-flight authorization state between BeginLogin and Complete and
// is a different concept with a different interface.
//
// Implementations must be safe for concurrent use. The context is the
// request's, for a store backed by Redis, SQL or similar; an error means the
// store itself failed, not that a session is missing.
type LoginSessionStore interface {
	// Create stores id for ttl and returns a fresh opaque session id. The
	// handlers pass the session cookie's lifetime (CookieConfig.SessionTTL), so
	// the server-side entry dies with the cookie: a copied session id stops
	// working once ttl has elapsed, whatever the browser does with the cookie.
	// The session id must be unguessable (e.g. 32 bytes from crypto/rand).
	Create(ctx context.Context, id *singpass.Identity, ttl time.Duration) (sid string, err error)
	// Get returns the identity for sid, or ok=false (and a nil error) if there
	// is none or it has expired.
	Get(ctx context.Context, sid string) (id *singpass.Identity, ok bool, err error)
	// Delete removes the session for sid; deleting an absent session is not
	// an error.
	Delete(ctx context.Context, sid string) error
}

// NewMemoryLoginSessionStore returns an in-memory LoginSessionStore. Entries
// expire after the ttl passed to Create and are swept lazily, so the store's
// size is bounded by the sessions created within one TTL. It is non-durable — a
// restart drops every session — so it suits a single instance or development; a
// production deployment supplies its own durable store.
func NewMemoryLoginSessionStore() LoginSessionStore {
	return &memoryLoginSessionStore{m: make(map[string]memorySession), now: time.Now}
}

type memorySession struct {
	id      *singpass.Identity
	expires time.Time
}

type memoryLoginSessionStore struct {
	mu        sync.RWMutex
	m         map[string]memorySession
	now       func() time.Time // injectable for tests
	nextSweep time.Time
}

// sweepInterval bounds how often Create scans the map for expired entries, so
// the O(n) sweep is amortised over many logins rather than run on each one.
const sweepInterval = time.Minute

func (st *memoryLoginSessionStore) Create(_ context.Context, id *singpass.Identity, ttl time.Duration) (string, error) {
	sid := newSessionID()
	now := st.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if !now.Before(st.nextSweep) {
		for k, s := range st.m {
			if !now.Before(s.expires) {
				delete(st.m, k)
			}
		}
		st.nextSweep = now.Add(sweepInterval)
	}
	st.m[sid] = memorySession{id: id, expires: now.Add(ttl)}
	return sid, nil
}

func (st *memoryLoginSessionStore) Get(_ context.Context, sid string) (*singpass.Identity, bool, error) {
	st.mu.RLock()
	s, ok := st.m[sid]
	st.mu.RUnlock()
	if !ok || !st.now().Before(s.expires) {
		return nil, false, nil
	}
	return s.id, true, nil
}

func (st *memoryLoginSessionStore) Delete(_ context.Context, sid string) error {
	st.mu.Lock()
	delete(st.m, sid)
	st.mu.Unlock()
	return nil
}

func newSessionID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
