package api

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestNewL4ProxyRejectsSourceFamilyMismatch(t *testing.T) {
	_, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
		LocalAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1")},
	})
	if err == nil {
		t.Fatal("expected address-family mismatch error")
	}
}

func TestListenUDPForEndpointUsesLocalAddr(t *testing.T) {
	endpoint := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}

	conn, err := listenUDPForEndpoint(endpoint, local)
	if err != nil {
		t.Fatalf("listenUDPForEndpoint: %v", err)
	}
	defer func() { _ = conn.Close() }()

	got, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected local address type %T", conn.LocalAddr())
	}
	if !got.IP.Equal(local.IP) {
		t.Fatalf("bound source IP = %s, want %s", got.IP, local.IP)
	}
}
