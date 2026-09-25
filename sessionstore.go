package singpass

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// DefaultMaxPendingLogins caps how many started-but-unfinished logins the
// in-memory session store holds at once when NewMemorySessionStore is given 0.
// At FAPIgo's 5-minute session lifetime that allows ~33 new logins a second,
// sustained, before new ones are refused.
const DefaultMaxPendingLogins = 10_000

// ErrTooManyPendingLogins is returned (wrapped) by BeginLogin when the
// in-memory session store is at its cap. It means too many logins have been
// started and not finished within the session lifetime — typically someone
// hitting the login route in a loop — and a caller may map it to 503.
var ErrTooManyPendingLogins = errors.New("singpass: too many pending logins")

// ErrLoginExpired is returned (wrapped) by Client.Complete when the callback's
// state is unknown, already used or past its lifetime — typically the user took
// too long, pressed back, or reloaded the callback page, or the process
// restarted mid-login. It is not a protocol failure: show a "please try again"
// page, e.g. with errors.Is(err, singpass.ErrLoginExpired). A custom
// SessionStore should return (or wrap) it from Consume in the same cases.
var ErrLoginExpired = errors.New("singpass: login expired or already used")

// sessionSweepInterval bounds how often Create scans for expired sessions, so
// the O(n) sweep is amortised across many logins rather than run on each one.
const sessionSweepInterval = time.Minute

// NewMemorySessionStore returns an in-memory storage.SessionStore for FAPIgo's
// in-flight authorization state (state, nonce, PKCE verifier) between
// BeginLogin and Complete. It is the default when Dependencies.Sessions is nil.
//
// Unlike FAPIgo's memstore, which keeps a session until its callback arrives, it
// drops a session once its ExpiresAt passes, so logins that are started and
// never finished do not accumulate. It also refuses new sessions beyond
// maxPending (0 means DefaultMaxPendingLogins) with ErrTooManyPendingLogins, so
// memory stays bounded however fast the login route is hit.
//
// It is still per-process and non-durable, declares no storage.StoreAssurance,
// and so — like memstore — is refused under AssuranceProduction.
func NewMemorySessionStore(maxPending int) SessionStore {
	return newMemorySessionStore(maxPending, time.Now)
}

func newMemorySessionStore(maxPending int, now func() time.Time) *memorySessionStore {
	if maxPending <= 0 {
		maxPending = DefaultMaxPendingLogins
	}
	return &memorySessionStore{
		sessions:   make(map[string]storage.NewSession),
		maxPending: maxPending,
		now:        now,
	}
}

type memorySessionStore struct {
	mu         sync.Mutex
	sessions   map[string]storage.NewSession
	maxPending int
	now        func() time.Time
	nextSweep  time.Time
}

// Create implements storage.SessionStore.
func (s *memorySessionStore) Create(_ context.Context, session storage.NewSession) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.nextSweep) {
		s.sweepLocked(now)
	}
	if _, replacing := s.sessions[session.State]; !replacing && len(s.sessions) >= s.maxPending {
		// At the cap: sweep now rather than waiting for the interval, in case
		// enough have expired since the last sweep to make room.
		s.sweepLocked(now)
		if len(s.sessions) >= s.maxPending {
			return ErrTooManyPendingLogins
		}
	}
	s.sessions[session.State] = session
	return nil
}

func (s *memorySessionStore) sweepLocked(now time.Time) {
	for state, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, state)
		}
	}
	s.nextSweep = now.Add(sessionSweepInterval)
}

// Consume implements storage.SessionStore. The entry is deleted whether or not
// it exists, so a State can be consumed at most once. An unknown, already-used
// or expired (but not yet swept) state is reported as ErrLoginExpired, so the
// caller can tell a stale login from a protocol failure.
func (s *memorySessionStore) Consume(_ context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	now := s.now()
	s.mu.Lock()
	sess, ok := s.sessions[c.State]
	delete(s.sessions, c.State)
	s.mu.Unlock()
	if !ok || !now.Before(sess.ExpiresAt) {
		return storage.ConsumedSession{}, ErrLoginExpired
	}
	return storage.ConsumedSession{
		Nonce:                sess.Nonce,
		PKCEVerifier:         sess.PKCEVerifier,
		ExpectedIssuer:       sess.ExpectedIssuer,
		ExpectedRedirectURI:  sess.ExpectedRedirectURI,
		ExpectedResponseMode: sess.ExpectedResponseMode,
		ExpiresAt:            sess.ExpiresAt,
	}, nil
}
