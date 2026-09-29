package main

import (
	"net/http"
	"testing"
)

func TestClientKey(t *testing.T) {
	for _, tc := range []struct {
		name        string
		behindProxy bool
		xff         []string
		want        string
	}{
		{"direct", false, nil, "198.51.100.7"},
		{"direct ignores X-Forwarded-For", false, []string{"203.0.113.1"}, "198.51.100.7"},
		{"proxy appends the client", true, []string{"10.0.0.1, 203.0.113.1"}, "203.0.113.1"},
		{"last of several headers", true, []string{"10.0.0.1", "203.0.113.2"}, "203.0.113.2"},
		{"proxy without the header", true, nil, "198.51.100.7"},
	} {
		r := &http.Request{RemoteAddr: "198.51.100.7:4321", Header: http.Header{}}
		for _, v := range tc.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientKey(tc.behindProxy)(r); got != tc.want {
			t.Errorf("%s: key = %q, want %q", tc.name, got, tc.want)
		}
	}
}
