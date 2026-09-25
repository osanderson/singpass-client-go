package singpass

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
)

// loggingHTTPClient wraps an *http.Client and, when debug is set, logs the
// method, URL and (form) body of every outbound request, plus the status and
// size of every response, to the injected slog.Logger. It satisfies FAPIgo's
// fapihttp.HTTPClient interface (it has a Do method) and, apart from reading the
// response body to measure it (then restoring it verbatim), is transparent.
// When debug is unset it just delegates.
//
// This wrapper carries no protocol behaviour: FAPIgo sends the full PAR body
// itself (client_id, authentication_context_type / acr_values, plus the DPoP
// proof header binding the code to the DPoP key) and
// decrypts the JWE id_token itself (via the keys.Decrypter wired in New). The
// wrapper exists only as a bring-up diagnostic.
//
// The response-size log is what reveals how large a userinfo JWE actually is —
// useful because FAPIgo's JOSE parser caps a compact serialization at 16 KiB,
// which a many-scope Myinfo response can exceed. The wrapper sees the raw wire
// response before FAPIgo parses it, so it reports the size even when parsing
// then fails.
//
// The request dump includes the client_assertion JWT (a bearer credential), so
// enable it only against staging (Dependencies.Debug).
type loggingHTTPClient struct {
	base  *http.Client
	debug bool
	log   *slog.Logger
}

func newLoggingHTTPClient(base *http.Client, debug bool, log *slog.Logger) *loggingHTTPClient {
	if log == nil {
		log = slog.Default()
	}
	return &loggingHTTPClient{base: base, debug: debug, log: log}
}

// Do implements fapihttp.HTTPClient.
func (c *loggingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.debug {
		c.logRequest(req)
	}
	resp, err := c.base.Do(req)
	if c.debug && err == nil && resp != nil {
		c.logResponse(req, resp)
	}
	return resp, err
}

func (c *loggingHTTPClient) logRequest(req *http.Request) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	c.log.Info("singpass http request", "method", req.Method, "url", req.URL.String(), "body", string(body))
}

// logResponse reads the response body to report its size, then restores it so
// FAPIgo reads the identical bytes. content_length is the server's declared
// size (-1 when unknown, e.g. chunked); read_bytes is what actually arrived.
func (c *loggingHTTPClient) logResponse(req *http.Request, resp *http.Response) {
	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	c.log.Info("singpass http response",
		"method", req.Method, "url", req.URL.String(),
		"status", resp.Status, "content_length", resp.ContentLength, "read_bytes", len(body))
}
