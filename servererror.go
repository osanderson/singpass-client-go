package singpass

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// ServerErrorResponse is the error response Singpass or Corppass sent: the
// OAuth error code (e.g. "invalid_client"), its description and URI, and the
// HTTP status. See ServerError.
type ServerErrorResponse = client.ServerErrorResponse

// ServerError returns the error response from Singpass or Corppass behind err
// — from BeginLogin's pushed authorization request, or Complete's token or
// /userinfo call — or false when err didn't come from one (a transport
// failure, a validation failure, or an error from this package). The
// description is the server's own text: log it, don't show it to users.
func ServerError(err error) (ServerErrorResponse, bool) {
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.ServerResponse()
	}
	return ServerErrorResponse{}, false
}

// ErrorCode returns the OAuth error code Singpass or Corppass sent behind err,
// e.g. "invalid_client" or "server_error", or "" when there is none.
// docs/troubleshooting.md lists what each code means.
func ErrorCode(err error) string {
	r, _ := ServerError(err)
	return r.Code
}

// temporaryCodes are the error codes Singpass says may be retried.
var temporaryCodes = map[string]bool{
	"server_error":              true,
	"temporarily_unavailable":   true,
	"upstream_dependency_error": true,
}

// IsTemporary reports whether err is a temporary failure worth trying again:
// Singpass or Corppass answered server_error, temporarily_unavailable or
// upstream_dependency_error (Singpass allows up to 3 retries with
// exponential backoff), or a 5xx without an error code, or the request timed
// out.
//
// What to try again depends on the call. BeginLogin can simply be called
// again (Dependencies.BeginLoginRetries does it for you). A Complete failure
// can't be: the authorization code and login state are already used, so
// restart the login from BeginLogin instead.
func IsTemporary(err error) bool {
	if r, ok := ServerError(err); ok {
		return temporaryCodes[r.Code] || (r.Code == "" && r.HTTPStatus >= 500)
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// maxBeginLoginRetries bounds Dependencies.BeginLoginRetries at what Singpass
// allows.
const maxBeginLoginRetries = 3

// retryDelay is the backoff before retry attempt+1: 250ms, 500ms, 1s, each
// with up to 25% jitter.
func retryDelay(attempt int) time.Duration {
	d := 250 * time.Millisecond << attempt
	return d + rand.N(d/4+1)
}

// callbackSession checks the callback's state against the login state kept
// with the browser, and returns FAPIgo's session handle for it.
func callbackSession(rawQuery, state string) (client.SessionHandle, error) {
	if state == "" {
		return client.SessionHandle{}, fmt.Errorf("singpass: no login in progress in this browser: %w", ErrLoginExpired)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || q.Get("state") != state {
		return client.SessionHandle{}, fmt.Errorf("singpass: callback state doesn't match this browser's login: %w", ErrLoginExpired)
	}
	handle, err := client.ParseSessionHandle(state)
	if err != nil {
		return client.SessionHandle{}, fmt.Errorf("singpass: malformed login state: %w", ErrLoginExpired)
	}
	return handle, nil
}
