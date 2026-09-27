package singpass

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// flakyPAR answers the first failures pushed authorization requests with
// status and body, then accepts them.
func flakyPAR(failures int32, status int, body string) (http.HandlerFunc, *atomic.Int32) {
	calls := new(atomic.Int32)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) <= failures {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":60}`))
	}, calls
}

func newRetryClient(t *testing.T, par http.HandlerFunc, retries int) *Client {
	t.Helper()
	deps := testKeyDeps(t)
	deps.HTTPClient = fakeIssuerWithPAR(t, discoveryDoc(), par)
	deps.BeginLoginRetries = retries
	c, err := New(context.Background(), baseOptions(), deps)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBeginLoginRetriesTemporaryFailures(t *testing.T) {
	par, calls := flakyPAR(2, http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`)
	c := newRetryClient(t, par, 3)
	if _, _, err := c.BeginLogin(context.Background()); err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("PAR calls = %d, want 3", calls.Load())
	}
}

func TestBeginLoginReportsTemporaryFailure(t *testing.T) {
	par, calls := flakyPAR(10, http.StatusInternalServerError, `{"error":"server_error","error_description":"try later"}`)
	c := newRetryClient(t, par, 0)
	_, _, err := c.BeginLogin(context.Background())
	if !IsTemporary(err) || ErrorCode(err) != "server_error" || calls.Load() != 1 {
		t.Fatalf("err = %v (temporary %v, code %q), calls %d", err, IsTemporary(err), ErrorCode(err), calls.Load())
	}
	if r, _ := ServerError(err); r.Description != "try later" || r.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("ServerError = %+v", r)
	}

	// A 5xx without an OAuth error body is temporary too.
	html, _ := flakyPAR(10, http.StatusBadGateway, `<html>bad gateway</html>`)
	if _, _, err := newRetryClient(t, html, 0).BeginLogin(context.Background()); !IsTemporary(err) || ErrorCode(err) != "" {
		t.Errorf("502 without a code: temporary %v, code %q", IsTemporary(err), ErrorCode(err))
	}
}

func TestBeginLoginDoesNotRetryPermanentFailures(t *testing.T) {
	par, calls := flakyPAR(10, http.StatusBadRequest, `{"error":"invalid_scope"}`)
	c := newRetryClient(t, par, 3)
	_, _, err := c.BeginLogin(context.Background())
	if ErrorCode(err) != "invalid_scope" || IsTemporary(err) || calls.Load() != 1 {
		t.Fatalf("err = %v, calls %d; want invalid_scope, not retried", err, calls.Load())
	}
}

func TestBeginLoginRetriesStopWithContext(t *testing.T) {
	par, calls := flakyPAR(10, http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`)
	c := newRetryClient(t, par, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := c.BeginLogin(ctx); ErrorCode(err) != "temporarily_unavailable" {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("PAR calls = %d, want 1 (the context ended during the first backoff)", calls.Load())
	}
}

func TestBeginLoginRetriesBounds(t *testing.T) {
	for _, n := range []int{-1, 4} {
		deps := testKeyDeps(t)
		deps.BeginLoginRetries = n
		if _, err := New(context.Background(), baseOptions(), deps); err == nil {
			t.Errorf("BeginLoginRetries %d accepted", n)
		}
	}
}

func TestCompleteBindsCallbackToBrowser(t *testing.T) {
	c := newRetryClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":60}`))
	}, 0)
	_, state, err := c.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	callback := "code=x&state=" + state + "&iss=" + testIssuer
	for name, browserState := range map[string]string{"no login in this browser": "", "another login": "other"} {
		if _, err := c.Complete(context.Background(), callback, browserState); !errorsIsLoginExpired(err) {
			t.Errorf("%s: err = %v, want ErrLoginExpired", name, err)
		}
	}
}

func errorsIsLoginExpired(err error) bool { return err != nil && errors.Is(err, ErrLoginExpired) }
