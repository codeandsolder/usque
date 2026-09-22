package internal

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/txthinking/socks5"
)

func newAssociationTestServer(t *testing.T) *SOCKS5Server {
	t.Helper()
	s, err := NewSOCKS5Server(SOCKS5Config{
		Addr: "127.0.0.1:0",
		DialTCP: func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	return s
}

func TestIsZeroUDPAssociateRequest(t *testing.T) {
	for _, r := range []*socks5.Request{
		{Atyp: socks5.ATYPIPv4, DstAddr: []byte{0, 0, 0, 0}, DstPort: []byte{0, 0}},
		{Atyp: socks5.ATYPIPv6, DstAddr: make([]byte, net.IPv6len), DstPort: []byte{0, 0}},
	} {
		if !isZeroUDPAssociateRequest(r) {
			t.Fatalf("request %#v was not recognized as zero-source", r)
		}
	}

	for _, r := range []*socks5.Request{
		{Atyp: socks5.ATYPIPv4, DstAddr: []byte{192, 0, 2, 1}, DstPort: []byte{0, 0}},
		{Atyp: socks5.ATYPIPv4, DstAddr: []byte{0, 0, 0, 0}, DstPort: []byte{0, 1}},
		{Atyp: socks5.ATYPDomain, DstAddr: []byte("example.com"), DstPort: []byte{0, 0}},
	} {
		if isZeroUDPAssociateRequest(r) {
			t.Fatalf("request %#v was incorrectly recognized as zero-source", r)
		}
	}
}

func TestFindUDPAssociationClaimsAndCaches(t *testing.T) {
	s := newAssociationTestServer(t)
	assoc := &udpAssociation{ch: make(chan byte)}
	s.addPendingUDPAssociation("192.0.2.10", assoc)

	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 43210}
	got, ok, err := s.findUDPAssociation(s.server, addr)
	if err != nil {
		t.Fatalf("findUDPAssociation: %v", err)
	}
	if !ok || got != assoc {
		t.Fatalf("association = (%p, %v), want (%p, true)", got, ok, assoc)
	}
	if source := assoc.getSource(); source != addr.String() {
		t.Fatalf("association source = %q, want %q", source, addr.String())
	}
	cached, ok := s.server.AssociatedUDP.Get(addr.String())
	if !ok || cached != assoc {
		t.Fatalf("cached association = (%v, %v), want (%p, true)", cached, ok, assoc)
	}
}

func TestFindUDPAssociationConcurrentClaim(t *testing.T) {
	s := newAssociationTestServer(t)
	assoc := &udpAssociation{ch: make(chan byte)}
	s.addPendingUDPAssociation("192.0.2.20", assoc)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 54321}

	const workers = 32
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, ok, err := s.findUDPAssociation(s.server, addr)
			if err != nil {
				errCh <- err
				return
			}
			if !ok || got != assoc {
				errCh <- &associationTestError{}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent claim failed: %v", err)
	}
}

type associationTestError struct{}

func (*associationTestError) Error() string { return "unexpected association result" }

func TestFindUDPAssociationClaimsSeparatePorts(t *testing.T) {
	s := newAssociationTestServer(t)
	first := &udpAssociation{ch: make(chan byte)}
	second := &udpAssociation{ch: make(chan byte)}
	s.addPendingUDPAssociation("192.0.2.30", first)
	s.addPendingUDPAssociation("192.0.2.30", second)

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.0.2.30"), Port: 10001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.0.2.30"), Port: 10002}

	got1, ok1, err := s.findUDPAssociation(s.server, addr1)
	if err != nil || !ok1 || got1 != first {
		t.Fatalf("first claim = (%p, %v, %v), want (%p, true, nil)", got1, ok1, err, first)
	}
	got2, ok2, err := s.findUDPAssociation(s.server, addr2)
	if err != nil || !ok2 || got2 != second {
		t.Fatalf("second claim = (%p, %v, %v), want (%p, true, nil)", got2, ok2, err, second)
	}
}
