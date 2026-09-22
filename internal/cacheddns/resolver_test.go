package cacheddns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestParseNegativePolicy(t *testing.T) {
	for _, raw := range []string{"return", "retry", "off", " RETRY "} {
		if _, err := ParseNegativePolicy(raw); err != nil {
			t.Fatalf("ParseNegativePolicy(%q): %v", raw, err)
		}
	}
	if _, err := ParseNegativePolicy("maybe"); err == nil {
		t.Fatal("expected invalid policy to fail")
	}
}

func TestNegativeCacheReturnVsRetry(t *testing.T) {
	for _, tt := range []struct {
		name      string
		policy    NegativePolicy
		wantDials int32
	}{
		{name: "return", policy: NegativeReturn, wantDials: 0},
		{name: "retry", policy: NegativeRetry, wantDials: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var dials atomic.Int32
			r, err := New(Options{
				Upstreams:      []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				NegativePolicy: tt.policy,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("synthetic dial failure")
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			msg := dns.NewMsg("missing.example", dns.TypeA)
			msg.Rcode = dns.RcodeNameError
			key := cacheKey{name: "missing.example", qtype: dns.TypeA}
			r.cache.put(key, msg, time.Now().Add(time.Minute), true, true, 0)

			if _, err := r.Resolve(context.Background(), "missing.example"); err == nil {
				t.Fatal("expected cached NXDOMAIN")
			}
			if got := dials.Load(); got != tt.wantDials {
				t.Fatalf("dial count = %d, want %d", got, tt.wantDials)
			}
		})
	}
}

func TestNegativeResponseTTLUsesSOAMinimum(t *testing.T) {
	msg := dns.NewMsg("missing.example", dns.TypeA)
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.", TTL: 120}}
	soa.Minttl = 30
	msg.Ns = []dns.RR{soa}
	if got, want := negativeResponseTTL(msg, 10*time.Second), 30*time.Second; got != want {
		t.Fatalf("negativeResponseTTL = %v, want %v", got, want)
	}
}

func TestNegativeResponseTTLHonorsExplicitZero(t *testing.T) {
	msg := dns.NewMsg("missing.example", dns.TypeA)
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.", TTL: 120}}
	soa.Minttl = 0
	msg.Ns = []dns.RR{soa}
	if got := negativeResponseTTL(msg, 30*time.Second); got != 0 {
		t.Fatalf("negativeResponseTTL = %v, want 0", got)
	}
}

func TestValidateUpstreamResponse(t *testing.T) {
	for _, rcode := range []uint16{dns.RcodeSuccess, dns.RcodeNameError} {
		msg := new(dns.Msg)
		msg.Rcode = rcode
		if err := validateUpstreamResponse(msg); err != nil {
			t.Fatalf("rcode %d unexpectedly rejected: %v", rcode, err)
		}
	}
	for _, rcode := range []uint16{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeFormatError} {
		msg := new(dns.Msg)
		msg.Rcode = rcode
		if err := validateUpstreamResponse(msg); err == nil {
			t.Fatalf("rcode %d unexpectedly accepted", rcode)
		}
	}
}

func TestCacheRoundRobinsAndExpires(t *testing.T) {
	msg := dns.NewMsg("example.com", dns.TypeA)
	a1 := &dns.A{Hdr: dns.Header{Name: "example.com.", TTL: 60}}
	a1.Addr = netip.MustParseAddr("192.0.2.1")
	a2 := &dns.A{Hdr: dns.Header{Name: "example.com.", TTL: 60}}
	a2.Addr = netip.MustParseAddr("192.0.2.2")
	msg.Answer = []dns.RR{a1, a2}

	c := newResponseCache(1)
	key := cacheKey{name: "example.com", qtype: dns.TypeA}
	now := time.Now()
	c.put(key, msg, now.Add(time.Minute), false, false, 0)

	first, ok := c.get(key, now)
	if !ok {
		t.Fatal("expected cache hit")
	}
	second, ok := c.get(key, now)
	if !ok {
		t.Fatal("expected second cache hit")
	}
	if got := selectIP(first.msg, dns.TypeA, first.next).String(); got != "192.0.2.1" {
		t.Fatalf("first IP = %s", got)
	}
	if got := selectIP(second.msg, dns.TypeA, second.next).String(); got != "192.0.2.2" {
		t.Fatalf("second IP = %s", got)
	}
	if _, ok := c.get(key, now.Add(2*time.Minute)); ok {
		t.Fatal("expired cache entry still present")
	}
}

func TestResponseTTLIgnoresOPT(t *testing.T) {
	msg := dns.NewMsg("example.com", dns.TypeA)
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", TTL: 60}}
	a.Addr = netip.MustParseAddr("192.0.2.1")
	msg.Answer = []dns.RR{a}
	msg.Extra = []dns.RR{&dns.OPT{Hdr: dns.Header{Name: ".", TTL: 0}}}
	if got, want := responseTTL(msg), 60*time.Second; got != want {
		t.Fatalf("responseTTL = %v, want %v", got, want)
	}
}
