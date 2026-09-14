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

func TestAuthorityWithPort(t *testing.T) {
	tests := map[string]string{
		"example.com":          "example.com:443",
		"example.com:8443":     "example.com:8443",
		"[2001:db8::1]":        "[2001:db8::1]:443",
		"[2001:db8::1]:8443":   "[2001:db8::1]:8443",
	}
	for in, want := range tests {
		got, err := authorityWithPort(in, "443")
		if err != nil {
			t.Fatalf("authorityWithPort(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("authorityWithPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEndpointHost(t *testing.T) {
	tests := map[string]string{
		"162.159.198.1:0":    "162.159.198.1",
		"[2606:4700::1]:0":   "2606:4700::1",
	}
	for in, want := range tests {
		got, err := endpointHost(in)
		if err != nil {
			t.Fatalf("endpointHost(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("endpointHost(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"", "162.159.198.1", "[2606:4700::1]", "not-an-ip:443"} {
		if _, err := endpointHost(in); err == nil {
			t.Errorf("endpointHost(%q) unexpectedly succeeded", in)
		}
	}
}
