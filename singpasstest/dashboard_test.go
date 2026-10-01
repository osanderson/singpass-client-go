package singpasstest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/osanderson/singpass-client-go/singpasstest"
)

func getBody(t *testing.T, u string, header http.Header) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	if header != nil {
		req.Header = header
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// The dashboard lists the server's clients and users, and its request log
// records each request with its outcome.
func TestDashboard(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Interactive: true})
	if err := srv.RegisterTestClients(); err != nil {
		t.Fatal(err)
	}
	c := myinfoClient(t, srv)

	// A login, a cancelled login, a rejected request and a health check.
	if _, err := loginAs(t, srv, c, singpasstest.LoginAs{NRIC: "S8012345F"}); err != nil {
		t.Fatal(err)
	}
	if _, err := loginAs(t, srv, c, singpasstest.LoginAs{Cancel: true}); err == nil {
		t.Fatal("cancelled login succeeded")
	}
	if _, err := http.PostForm(srv.Issuer()+"/token", url.Values{"grant_type": {"password"}, "client_id": {"mi"}}); err != nil {
		t.Fatal(err)
	}
	getBody(t, srv.Issuer()+"/.well-known/openid-configuration", http.Header{"User-Agent": {"singpass-fake-server-healthcheck"}})
	getBody(t, srv.DashboardURL(), nil)

	var log []string
	for _, r := range srv.Requests() {
		log = append(log, fmt.Sprintf("%s %s %s %d %s %s", r.Method, r.Path, r.ClientID, r.Status, r.Error, r.Detail))
	}
	got := strings.Join(log, "\n")
	for _, want := range []string{
		"POST /fapi/token mi 400 unsupported_grant_type",
		"GET /fapi/auth mi 302 access_denied the user cancelled",
		"GET /fapi/userinfo mi 200  sent the Myinfo data of S8012345F Muhammad Hafiz",
		"POST /fapi/token mi 200  issued tokens",
		"GET /fapi/auth mi 302  logged in as S8012345F Muhammad Hafiz",
		"POST /fapi/par mi 201  accepted the pushed authorization request",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("request log lacks %q:\n%s", want, got)
		}
	}
	// The client's own discovery is logged; the health check and the
	// dashboard aren't.
	if strings.Count(got, "openid-configuration") != 1 || strings.Contains(got, "/_fake/") {
		t.Errorf("request log has health checks or dashboard requests:\n%s", got)
	}
	if r := srv.Requests()[0]; r.Error != "unsupported_grant_type" || r.ErrorDescription == "" {
		t.Errorf("newest record = %+v", r)
	}

	// The same as JSON.
	status, body := getBody(t, srv.DashboardURL()+"requests", nil)
	var records []singpasstest.RequestRecord
	if err := json.Unmarshal([]byte(body), &records); status != http.StatusOK || err != nil || len(records) != len(srv.Requests()) {
		t.Errorf("/_fake/requests: %d %v, %d records", status, err, len(records))
	}

	status, page := getBody(t, srv.DashboardURL(), nil)
	for _, want := range []string{srv.Issuer(), "myinfo-test", "test client", "any http://localhost URI", "S8012345F", "Muhammad Hafiz", "unsupported_grant_type", "not affiliated"} {
		if status != http.StatusOK || !strings.Contains(page, want) {
			t.Errorf("dashboard (%d) lacks %q", status, want)
		}
	}
	if status, _ := getBody(t, srv.DashboardURL()+"nope", nil); status != http.StatusNotFound {
		t.Errorf("/_fake/nope: %d", status)
	}
}

// The interactive sign-in page's logins are recorded with their client.
func TestDashboardRecordsSignInPage(t *testing.T) {
	srv := startServer(t, singpasstest.Config{Interactive: true})
	c := myinfoClient(t, srv)
	redirect, _, err := c.BeginLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resp := customLogin(t, redirect, url.Values{"nric": {"S7654321Z"}})
	resp.Body.Close()
	rs := srv.Requests()
	if len(rs) < 2 || rs[0].Path != "/fapi/auth/decision" || rs[0].ClientID != "mi" || !strings.Contains(rs[0].Detail, "logged in as S7654321Z") ||
		rs[1].Detail != "showed the sign-in page" {
		t.Errorf("records = %+v", rs)
	}
}

// The log keeps the most recent 200 requests.
func TestDashboardKeepsRecentRequests(t *testing.T) {
	srv := startServer(t, singpasstest.Config{})
	for range 205 {
		getBody(t, srv.Issuer()+"/jwks", nil)
	}
	if n := len(srv.Requests()); n != 200 {
		t.Errorf("%d records, want 200", n)
	}
}
