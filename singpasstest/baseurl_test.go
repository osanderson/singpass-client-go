package singpasstest_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/osanderson/singpass-client-go/singpasstest"
)

// A server behind a proxy that strips a path prefix, reached at a BaseURL
// with that prefix, completes a Myinfo login: the DPoP proofs at PAR, token
// and /userinfo all name the URL the client called.
func TestBaseURLWithPathPrefix(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	backend := &url.URL{Scheme: "http", Host: addr}
	proxy := httptest.NewServer(http.StripPrefix("/singpass", httputil.NewSingleHostReverseProxy(backend)))
	t.Cleanup(proxy.Close)

	srv := startServer(t, singpasstest.Config{Addr: addr, BaseURL: proxy.URL + "/singpass"})
	id, err := loginAs(t, srv, myinfoClient(t, srv), singpasstest.LoginAs{NRIC: "S1234567D"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject == "" || len(id.Claims) == 0 {
		t.Errorf("identity = %+v, want a subject and Myinfo claims", id)
	}
}
