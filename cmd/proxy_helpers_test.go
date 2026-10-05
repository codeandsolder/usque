package cmd

import (
	"net/http"
	"testing"
)

func TestAuthenticateDisabledIgnoresClientProxyAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Basic client-supplied")
	if !authenticate(req, "") {
		t.Fatal("proxy with authentication disabled rejected a client Proxy-Authorization header")
	}
}

func TestAuthenticateEnabled(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "Basic expected"
	if authenticate(req, expected) {
		t.Fatal("authenticated proxy accepted missing credentials")
	}
	req.Header.Set("Proxy-Authorization", expected)
	if !authenticate(req, expected) {
		t.Fatal("authenticated proxy rejected matching credentials")
	}
}

func TestStripHopByHopHeaders(t *testing.T) {
	header := http.Header{
		"Connection":          {"keep-alive, X-Private-Hop"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authorization": {"Basic secret"},
		"Proxy-Connection":    {"keep-alive"},
		"Transfer-Encoding":   {"chunked"},
		"X-Private-Hop":       {"remove-me"},
		"X-End-To-End":        {"keep-me"},
	}

	stripHopByHopHeaders(header)

	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Transfer-Encoding",
		"X-Private-Hop",
	} {
		if got := header.Get(name); got != "" {
			t.Errorf("%s was not removed: %q", name, got)
		}
	}
	if got := header.Get("X-End-To-End"); got != "keep-me" {
		t.Fatalf("end-to-end header = %q, want keep-me", got)
	}
}
