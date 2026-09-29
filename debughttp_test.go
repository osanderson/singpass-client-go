package singpass

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// With debug on, the logging client logs each request's body and each
// response's size, and both bodies still arrive intact; with it off, it logs
// nothing.
func TestLoggingHTTPClient(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	for _, debug := range []bool{true, false} {
		var logs strings.Builder
		c := newLoggingHTTPClient(srv.Client(), debug, slog.New(slog.NewTextHandler(&logs, nil)))
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader("grant_type=authorization_code"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if received != "grant_type=authorization_code" || string(body) != `{"ok":true}` {
			t.Errorf("debug=%v: server got %q, client read %q", debug, received, body)
		}
		logged := logs.String()
		if debug != strings.Contains(logged, "body=\"grant_type=authorization_code\"") || debug != strings.Contains(logged, "read_bytes=11") {
			t.Errorf("debug=%v: logs = %q", debug, logged)
		}
	}
	if c := newLoggingHTTPClient(http.DefaultClient, true, nil); c.log == nil {
		t.Error("a nil logger wasn't defaulted")
	}
}
