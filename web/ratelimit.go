package web

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ErrTooManyLogins is passed to Config.OnError when a client starts logins
// faster than Config.LoginRateLimit allows. The response already carries a
// Retry-After header; the default OnError answers 429 Too Many Requests.
var ErrTooManyLogins = errors.New("web: too many logins started; try again shortly")

// LoginRateLimit limits how often one client may start a login at
// /{name}/login. Every login started makes a pushed authorization request to
// Singpass or Corppass and holds a pending login until it expires, so without
// a limit anyone can send those requests in a loop: using up your client's
// request allowance and, with the in-memory session store, filling it so that
// no one else can log in.
//
// A client may start Burst logins at once, then one more every Every. The
// zero value allows 10 at once and then 10 a minute, across all apps.
type LoginRateLimit struct {
	Burst int           // default 10
	Every time.Duration // default 6s

	// Key identifies the client, e.g. by IP address. Nil means the address
	// the request came from (Request.RemoteAddr). Behind a proxy or load
	// balancer that is the proxy's address, so return the client address it
	// reports instead — only a part of the request the proxy sets, never one
	// the client can supply, or a client can pick a new key for every request.
	Key func(*http.Request) string
}

// rateLimiter is a token bucket per key.
type rateLimiter struct {
	burst float64
	every time.Duration
	key   func(*http.Request) string
	now   func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	nextSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(l LoginRateLimit) *rateLimiter {
	if l.Burst <= 0 {
		l.Burst = 10
	}
	if l.Every <= 0 {
		l.Every = 6 * time.Second
	}
	if l.Key == nil {
		l.Key = remoteIP
	}
	return &rateLimiter{burst: float64(l.Burst), every: l.Every, key: l.Key, now: time.Now, buckets: map[string]*bucket{}}
}

// allow takes a token from r's bucket. When it is empty, it reports how long
// until the next token.
func (rl *rateLimiter) allow(r *http.Request) (ok bool, retryAfter time.Duration) {
	key, now := rl.key(r), rl.now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !now.Before(rl.nextSweep) {
		rl.sweepLocked(now)
	}
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	b.tokens = math.Min(rl.burst, b.tokens+float64(now.Sub(b.last))/float64(rl.every))
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) * float64(rl.every))
}

// sweepLocked drops the buckets that have refilled completely, which are the
// same as no bucket, so the map only holds recently active clients.
func (rl *rateLimiter) sweepLocked(now time.Time) {
	full := time.Duration(rl.burst * float64(rl.every))
	for k, b := range rl.buckets {
		if now.Sub(b.last) >= full {
			delete(rl.buckets, k)
		}
	}
	rl.nextSweep = now.Add(time.Minute)
}

// remoteIP is the default key: the IP address the request came from.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// retryAfterSeconds formats d for a Retry-After header, rounded up.
func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(int(math.Ceil(d.Seconds())))
}
