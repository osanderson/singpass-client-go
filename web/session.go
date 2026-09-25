package web

import (
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
// Implementations must be safe for concurrent use.
type LoginSessionStore interface {
	// Create stores id for ttl and returns a fresh opaque session id. The
	// handlers pass the session cookie's lifetime (CookieConfig.SessionTTL), so
	// the server-side entry dies with the cookie: a copied session id stops
	// working once ttl has elapsed, whatever the browser does with the cookie.
	Create(id *singpass.Identity, ttl time.Duration) string
	// Get returns the identity for sid, or ok=false if none or expired.
	Get(sid string) (*singpass.Identity, bool)
	// Delete removes the session for sid (a no-op if absent).
	Delete(sid string)
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

func (st *memoryLoginSessionStore) Create(id *singpass.Identity, ttl time.Duration) string {
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
	return sid
}

func (st *memoryLoginSessionStore) Get(sid string) (*singpass.Identity, bool) {
	st.mu.RLock()
	s, ok := st.m[sid]
	st.mu.RUnlock()
	if !ok || !st.now().Before(s.expires) {
		return nil, false
	}
	return s.id, true
}

func (st *memoryLoginSessionStore) Delete(sid string) {
	st.mu.Lock()
	delete(st.m, sid)
	st.mu.Unlock()
}

func newSessionID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
