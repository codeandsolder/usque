package api

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
)

func TestNewHTTP2ClientWithDialerUsesHTTP2Only(t *testing.T) {
	client, err := newHTTP2ClientWithDialer(
		&tls.Config{ServerName: "localhost"},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		"https://127.0.0.1/",
		nil,
	)
	if err != nil {
		t.Fatalf("newHTTP2ClientWithDialer() error = %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Protocols == nil {
		t.Fatal("transport.Protocols is nil")
	}
	if !transport.Protocols.HTTP2() {
		t.Fatal("HTTP/2 is disabled")
	}
	if transport.Protocols.HTTP1() {
		t.Fatal("HTTP/1 must remain disabled for direct CONNECT-IP")
	}
	if transport.DialTLSContext == nil {
		t.Fatal("custom TLS dialer is missing")
	}
	if !transport.DisableCompression {
		t.Fatal("compression should remain disabled")
	}
}
